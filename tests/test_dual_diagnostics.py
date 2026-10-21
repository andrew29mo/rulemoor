"""Formal dual management diagnostics; synthetic inventories are not VM evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from rulemoor.core import Controller, PreflightRejected
from rulemoor.diagnostics import diagnose, validate_paths, load_paths
from rulemoor.policy import expected
from tests.test_core import MemoryBackend
from tests.test_dual_stack import confirm
from tests.test_diagnostics import dport

PATHS=[{'name':'api4','family':'ipv4','port':18443},{'name':'api6','family':'ipv6','port':18443}]
ALLOW={'default':'drop','rules':[{'port':18443,'verdict':'accept'}]}
BASE={'ipv4':ALLOW,'ipv6':ALLOW}
BLOCK={'ipv4':ALLOW,'ipv6':{'default':'drop','rules':[]}}


def inventory(family='ip6',expr=None,policy='accept',table='external'):
    raw={'nftables':[{'chain':{'family':family,'table':table,'name':'in','hook':'input','prio':-100,'policy':policy}}]}
    if expr is not None:raw['nftables'].append({'rule':{'family':family,'table':table,'chain':'in','expr':expr}})
    return raw


def diagnostic(raw,policy=BASE):
    b=MemoryBackend();b.inspect_ruleset=lambda:copy.deepcopy(raw)
    return diagnose(policy,PATHS,b)


class DualDiagnosticTests(unittest.TestCase):
    def test_family_configuration_preserves_legacy_and_bounds(self):
        self.assertEqual(validate_paths(PATHS),PATHS)
        self.assertEqual(validate_paths([{'name':'legacy','port':18443}]),[{'name':'legacy','port':18443}])
        for bad in ([{**PATHS[0],'family':'ip6'}],[{**PATHS[0],'family':None}],PATHS+[{'name':'duplicate','port':18443}],PATHS+[{'name':'api6','port':22}],PATHS+[{'name':'address','family':'ipv6','port':22,'address':'::1'}]):
            with self.subTest(bad=bad),self.assertRaises(ValueError):validate_paths(bad)
        with tempfile.TemporaryDirectory() as root:
            p=Path(root,'paths.json');p.write_text(json.dumps({'paths':PATHS}))
            self.assertEqual(load_paths(p),PATHS)

    def test_ipv4_allowed_does_not_mask_ipv6_own_block_or_unmanaged_family(self):
        b=MemoryBackend();b.inspect_ruleset=lambda:{'nftables':[]}
        with tempfile.TemporaryDirectory() as root:
            c=Controller(root,b,management_paths=PATHS);c.initialize(BASE)
            try:
                before=c.status();raw=c.store.path.read_bytes();plan=c.plan(BLOCK)['diagnostics']
                self.assertEqual(plan['family_statuses']['ipv4']['own_policy'],'allowed')
                self.assertEqual(plan['family_statuses']['ipv6']['own_policy'],'blocked')
                self.assertEqual(plan['own_policy']['status'],'blocked')
                with self.assertRaises(PreflightRejected):c.apply('blocked6',0,BLOCK,30)
                self.assertEqual(c.status(),before);self.assertEqual(b.read(),expected(BASE));self.assertEqual(c.store.path.read_bytes(),raw)
            finally:c.close()
        legacy=diagnose(ALLOW,PATHS,b)
        self.assertEqual(legacy['family_statuses']['ipv6']['own_policy'],'risk')
        only4=diagnose(BASE,PATHS[:1],b)
        self.assertEqual(only4['ipv6_preflight'],'not_configured')
        self.assertEqual(only4['family_statuses']['ipv6']['configuration'],'not_configured')

    def test_ip6_and_inet_nfproto_are_evaluated_per_family(self):
        raw=inventory(expr=[dport(18443),{'drop':None}]);d=diagnostic(raw)
        self.assertEqual(d['family_statuses']['ipv4']['external'],'no_observed_input_conflict')
        self.assertEqual(d['family_statuses']['ipv6']['external'],'blocked')
        self.assertEqual(d['external']['status'],'blocked')
        for op,right,blocked in (('==','ipv6','ipv6'),('!=','ipv4','ipv6'),('==','ipv4','ipv4')):
            match={'match':{'op':op,'left':{'meta':{'key':'nfproto'}},'right':right}}
            d=diagnostic(inventory('inet',[match,dport(18443),{'drop':None}]))
            for family in ('ipv4','ipv6'):
                self.assertEqual(d['family_statuses'][family]['external'],'blocked' if family==blocked else 'no_observed_input_conflict')
        established={'match':{'op':'==','left':{'ct':{'key':'state'}},'right':'established'}}
        self.assertEqual(diagnostic(inventory('ip6',[established,{'drop':None}]))['external']['status'],'blocked')

    def test_unknown_ipv6_conditions_and_unavailable_are_never_clear(self):
        unknown={'match':{'op':'==','left':{'payload':{'protocol':'ip6','field':'saddr'}},'right':'2001:db8::1'}}
        for expr in ([unknown,{'drop':None}],[{'jump':{'target':'sub'}}],[{'mangle':{'key':{},'value':1}},dport(22),{'drop':None}]):
            with self.subTest(expr=expr):
                d=diagnostic(inventory(expr=expr))
                self.assertEqual(d['family_statuses']['ipv4']['external'],'no_observed_input_conflict')
                self.assertEqual(d['family_statuses']['ipv6']['external'],'risk');self.assertEqual(d['external']['status'],'risk')
                self.assertFalse(d['reachability_verified'])
        b=MemoryBackend();b.inspect_ruleset=lambda:(_ for _ in ()).throw(RuntimeError('inspection failure'))
        d=diagnose(BASE,PATHS,b)
        self.assertEqual([d['family_statuses'][f]['external'] for f in ('ipv4','ipv6')],['unavailable','unavailable'])

    def test_owned_exclusion_respects_mode_inventory_is_read_only_and_bounded(self):
        raw=inventory('ip6',[dport(18443),{'drop':None}],table='rulemoor');original=copy.deepcopy(raw)
        self.assertEqual(diagnostic(raw)['external']['status'],'no_observed_input_conflict')
        b=MemoryBackend();b.inspect_ruleset=lambda:raw
        self.assertEqual(diagnose(ALLOW,PATHS,b)['family_statuses']['ipv6']['external'],'blocked')
        self.assertEqual(raw,original)
        raw={'nftables':[{'chain':{'family':'ip6','table':'foreign','name':'c'+str(i),'hook':'input','policy':'accept'}} for i in range(65)]}
        d=diagnostic(raw);self.assertTrue(d['external']['truncated']);self.assertEqual(d['family_statuses']['ipv6']['external'],'risk')
        raw=inventory();raw['nftables'][0]['chain']['hook']='prerouting'
        d=diagnostic(raw);self.assertEqual(d['family_statuses']['ipv6']['external'],'risk')

    def test_preflight_never_blocks_cancel_deadline_restart_or_reboot_recovery(self):
        protected=PATHS+[{'name':'ssh6','family':'ipv6','port':22}]
        candidate=copy.deepcopy(BASE);candidate['ipv6']['rules'].append({'port':22,'verdict':'accept'})
        for mode in ('cancel','deadline','restart','reboot'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as root:
                b=MemoryBackend();b.inspect_ruleset=lambda:{'nftables':[]}
                c=Controller(root,b,management_paths=protected);c.initialize(BASE)
                self.assertEqual(c.plan(BASE)['diagnostics']['own_policy']['status'],'blocked')
                s=c.apply('partial',0,candidate,10);confirm(c,s,'ipv4')
                b.inspect_ruleset=lambda:(_ for _ in ()).throw(AssertionError('Recovery must bypass preflight'))
                try:
                    if mode=='cancel':c.cancel(s['op'],s['generation'])
                    elif mode=='deadline':b.t=s['deadline'];c.tick()
                    else:
                        c.close()
                        if mode=='reboot':b.boot_value='new-boot';b.value=None
                        c=Controller(root,b,management_paths=protected);c.start()
                    self.assertEqual(c.status()['phase'],'ROLLED_BACK');self.assertEqual(b.read(),expected(BASE))
                finally:c.close()
