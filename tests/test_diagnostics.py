"""Production diagnostics/Controller tests; synthetic rulesets are not kernel evidence."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from rulemoor.backend import NftBackend
from rulemoor.core import Controller, PreflightRejected
from rulemoor.diagnostics import diagnose, load_paths, validate_paths
from rulemoor.policy import expected
from tests.test_core import MemoryBackend, BASE

PATHS=[{'name':'api','port':18443}]
BLOCK={'default':'drop','rules':[]}
ALLOW={'default':'drop','rules':[{'port':18443,'verdict':'accept'},{'port':18443,'verdict':'drop'}]}


def ruleset(expr=None, policy='accept', priority=10):
    value={'nftables':[{'chain':{'family':'ip','table':'external','name':'input','hook':'input','prio':priority,'policy':policy}}]}
    if expr is not None:
        value['nftables'].append({'rule':{'family':'ip','table':'external','chain':'input','expr':expr}})
    return value


def dport(port):return {'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':port}}


class DiagnosticTests(unittest.TestCase):
    def inspect(self, raw, policy=BASE):
        backend=MemoryBackend();backend.inspect_ruleset=lambda:copy.deepcopy(raw)
        return diagnose(policy,PATHS,backend)

    def test_configuration_is_strict_bounded_and_copied(self):
        paths=copy.deepcopy(PATHS);out=validate_paths(paths);paths[0]['port']=1
        self.assertEqual(out,PATHS)
        for bad in ([],{},[{'name':'x','port':True}],[{'name':'x','port':0}],PATHS*2,[{'name':'bad name','port':22}],PATHS+[{'name':'x','port':22,'ip':'127.0.0.1'}],PATHS*9):
            with self.subTest(bad=bad),self.assertRaises(ValueError):validate_paths(bad)
        with tempfile.TemporaryDirectory() as root:
            p=Path(root,'paths.json');p.write_text(json.dumps({'paths':PATHS}))
            self.assertEqual(load_paths(p),PATHS)
            link=Path(root,'link');link.symlink_to(p)
            with self.assertRaises(ValueError):load_paths(link)
            p.write_text(json.dumps({'paths':None}))
            with self.assertRaises(ValueError):load_paths(p)
            p.write_text(' '*4097)
            with self.assertRaises(ValueError):load_paths(p)

    def test_first_match_and_default_guard_preserve_journal_and_kernel(self):
        with tempfile.TemporaryDirectory() as root:
            backend=MemoryBackend();backend.inspect_ruleset=lambda:ruleset()
            c=Controller(root,backend,management_paths=PATHS);c.initialize(BASE)
            try:
                before=c.store.path.read_bytes();state=c.status()
                self.assertEqual(c.plan(BLOCK)['diagnostics']['own_policy']['status'],'blocked')
                with self.assertRaises(PreflightRejected):c.apply('denied',0,BLOCK,10)
                self.assertEqual(c.status(),state);self.assertEqual(backend.value,expected(BASE))
                self.assertEqual(c.store.path.read_bytes(),before)
                self.assertEqual(c.plan(ALLOW)['diagnostics']['own_policy']['status'],'allowed')
                receipt=c.apply('allowed',0,ALLOW,10)
                self.assertEqual(receipt['phase'],'AWAITING_CONFIRM')
                self.assertEqual(receipt['diagnostics']['context'],'before_new_apply')
                self.assertNotIn('diagnostics',c.store.load())
                repeat=c.apply('allowed',0,ALLOW,10)
                self.assertEqual(repeat['diagnostics']['context'],'receipt_lookup_no_reapply')
                self.assertEqual(c.status()['generation'],1)
            finally:c.close()

    def test_external_earlier_and_later_chains_can_block(self):
        for prio in (-100,10):
            value=self.inspect(ruleset([dport(18443),{'drop':None}],priority=prio))
            self.assertEqual(value['external']['status'],'blocked')
            self.assertFalse(value['reachability_verified']);self.assertTrue(value['fresh_connection_confirmation_required'])
        self.assertEqual(self.inspect(ruleset(policy='drop'))['external']['status'],'blocked')
        self.assertEqual(self.inspect(ruleset([dport(22),{'drop':None}]))['external']['status'],'no_observed_input_conflict')

    def test_first_verdict_and_new_connection_semantics(self):
        raw=ruleset([dport(18443),{'accept':None}])
        raw['nftables'].append({'rule':{'family':'ip','table':'external','chain':'input','expr':[dport(18443),{'drop':None}]}})
        self.assertEqual(self.inspect(raw)['external']['status'],'no_observed_input_conflict')
        established={'match':{'op':'in','left':{'ct':{'key':'state'}},'right':['established','related']}}
        self.assertEqual(self.inspect(ruleset([established,{'accept':None}],policy='drop'))['external']['status'],'blocked')

    def test_unsupported_expression_jump_and_other_hooks_are_not_clear(self):
        ip={'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':'127.0.0.1'}}
        for expr in ([ip,{'drop':None}],[{'jump':{'target':'other'}}],[{'mangle':{'key':{},'value':1}}]):
            with self.subTest(expr=expr):self.assertEqual(self.inspect(ruleset(expr))['external']['status'],'risk')
        self.assertEqual(self.inspect({'nftables':[{'future_object':{'family':'ip','table':'other'}}]})['external']['status'],'risk')
        mixed=ruleset([dport(18443),{'drop':None}]);mixed['nftables'].append({'chain':{'family':'ip','table':'other','name':'out','hook':'output','policy':'accept'}})
        self.assertEqual(self.inspect(mixed)['external']['status'],'risk')
        raw=ruleset();raw['nftables'][0]['chain']['hook']='output'
        value=self.inspect(raw)['external'];self.assertEqual(value['status'],'risk');self.assertEqual(value['unassessed_hooks'][0]['hook'],'output')

    def test_unknown_condition_cannot_hide_possible_drop(self):
        unknown={'match':{'op':'==','left':{'meta':{'key':'iifname'}},'right':'eth0'}}
        raw=ruleset([unknown,{'accept':None}],policy='drop')
        self.assertEqual(self.inspect(raw)['external']['status'],'risk')
        raw=ruleset([unknown,{'drop':None}])
        self.assertEqual(self.inspect(raw)['external']['status'],'risk')

        altered=ruleset([{'mangle':{'key':{},'value':22}},dport(22),{'drop':None}])
        self.assertEqual(self.inspect(altered)['external']['status'],'risk')

    def test_own_table_excluded_and_inventory_limit_is_explicit(self):
        raw=ruleset([dport(18443),{'drop':None}])
        for row in raw['nftables']:next(iter(row.values()))['table']='rulemoor'
        self.assertEqual(self.inspect(raw)['external']['status'],'no_observed_input_conflict')
        raw={'nftables':[{'chain':{'family':'ip','table':'foreign','name':'c'+str(i),'hook':'input','policy':'accept'}} for i in range(65)]}
        value=self.inspect(raw)['external'];self.assertTrue(value['truncated']);self.assertEqual(value['status'],'risk')

    def test_failure_and_missing_configuration_are_never_clear(self):
        backend=MemoryBackend()
        self.assertEqual(diagnose(BASE,None,backend)['external']['status'],'not_configured')
        for raw in ({}, {'nftables':['bad']}, {'nftables':[{}]*4097}):
            self.assertEqual(self.inspect(raw)['external']['status'],'unavailable')
        self.assertEqual(diagnose(BASE,PATHS,backend)['external']['status'],'unavailable')

    def test_ruleset_reader_bounds_bytes_timeout_and_nonzero_and_reaps(self):
        original=subprocess.Popen
        for code in ('print(" "*1048577+"{}")', 'import time;time.sleep(5)', 'raise SystemExit(3)'):
            children=[]
            def launch(args,**kw):
                self.assertEqual(args,['nft','-j','-s','list','ruleset'])
                p=original([sys.executable,'-c',code],**kw);children.append(p);return p
            with self.subTest(code=code),patch('rulemoor.backend.subprocess.Popen',side_effect=launch):
                with self.assertRaises(RuntimeError):NftBackend().inspect_ruleset()
            self.assertTrue(children);self.assertIsNotNone(children[0].poll())
