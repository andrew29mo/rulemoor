"""Report boundary checks; full frozen VM receipts have a separate audit CLI."""
import copy
import unittest
from tools.boot_report import (verify_closed, verify_open_receipt, verify_kill,
                               verify_stages, installed_provenance, verify_native, STAGES, render)
from tools.evidence import fingerprint
from rulemoor.policy import expected, digest


class BootReportTests(unittest.TestCase):
    def test_failed_start_requires_observed_closed_interface(self):
        link={'up':False,'boot':'boot','ifindex':2,'namespace_inode':123}
        good={'exit_code':1,'link':dict(link),'unit':{'ActiveState':'failed','MainPID':'0'},
              'cleanup':{'status':'CLOSED','link':dict(link)}}
        verify_closed(good)
        for key in ('command-succeeded','interface-up','cleanup-faulted','cleanup-up','wrong-cleanup-identity'):
            bad=copy.deepcopy(good)
            if key=='command-succeeded':bad['exit_code']=0
            elif key=='interface-up':bad['link']['up']=True
            elif key=='cleanup-faulted':bad['cleanup']['status']='FAULTED'
            elif key=='cleanup-up':bad['cleanup']['link']['up']=True
            else:bad['cleanup']['link']['namespace_inode']=124
            with self.subTest(key=key),self.assertRaises(AssertionError):verify_closed(bad)

    def test_open_binds_both_policies_identity_and_clock(self):
        p={f:{'default':'drop','rules':[]} for f in ('ipv4','ipv6')}
        j={'current':p,'boot':'new-boot','generation':3,'phase':'ROLLED_BACK'}
        link={'up':True,'boot':'new-boot','namespace_inode':123,'ifindex':2}
        receipt={**link,'up':False,'generation':3,'phase':'ROLLED_BACK',
                 'policy_digest':digest(expected(p)),'verified_ns':2,'clock':'monotonic_ns'}
        good={'status':'OPEN','kernel':expected(p),'link':link,'receipt':receipt,
              'started_ns':1,'opened_ns':3,'finished_ns':4}
        verify_open_receipt(good,j)
        for key,value in (('boot','old-boot'),('generation',2),('namespace_inode',124),
                          ('ifindex',3),('policy_digest','0'*64),('verified_ns',5)):
            bad=copy.deepcopy(good);bad['receipt'][key]=value
            with self.subTest(key=key),self.assertRaises(AssertionError):verify_open_receipt(bad,j)
        bad=copy.deepcopy(good);bad['kernel'].pop()
        with self.assertRaises(AssertionError):verify_open_receipt(bad,j)

    def test_stage_protocol_rejects_missing_reordered_duplicate_and_bad_outcomes(self):
        rows=[{'name':n,'exit_code':0,'timed_out':False,'seconds':.1} for n in STAGES]
        verify_stages(rows)
        for bad in (rows[:1],list(reversed(rows)),rows+[rows[-1]],
                    [{**r,'seconds':float('nan')} for r in rows],
                    [{**r,'timed_out':True} for r in rows]):
            with self.assertRaises(AssertionError):verify_stages(bad)

    def test_kill_requires_same_process_invocation_both_locks_and_closed_identity(self):
        link={'up':True,'boot':'boot','ifindex':2,'namespace_inode':123}
        closed={**link,'up':False}
        good={'point':'after-up','held':{'point':'after-up','pid':1234},'link_before':dict(link),
              'unit_before':{'ActiveState':'activating','MainPID':'1234','InvocationID':'invocation'},
              'unit':{'ActiveState':'failed','MainPID':'0','Result':'signal','ExecMainStatus':'9','InvocationID':'invocation'},
              'process_before':{'pid':1234,'start_ticks':30,'boot':'boot'},'process_namespace_inode':123,
              'contending_controller_exit':7,'owner_lock_contender':{'exit_code':7,'blocked':True},
              'writer_lock_contender':{'exit_code':7,'blocked':True},
              'cleanup':{'status':'CLOSED','link':dict(closed)},'link_after':dict(closed),
              'signal_clock':{'clock':'monotonic_ns','sent_ns':1,'observed_closed_ns':2}}
        verify_kill(good)
        mutations=[lambda x:x['unit'].update(Result='success',ExecMainStatus='0'),
                   lambda x:x['unit'].update(InvocationID='other'),lambda x:x['held'].update(pid=1235),
                   lambda x:x['cleanup']['link'].update(up=True),lambda x:x['cleanup']['link'].update(boot='other'),
                   lambda x:x['writer_lock_contender'].update(blocked=False),
                   lambda x:x['process_before'].update(start_ticks=-1)]
        for mutate in mutations:
            bad=copy.deepcopy(good);mutate(bad)
            with self.assertRaises(AssertionError):verify_kill(bad)

    def test_provenance_rejects_source_import_even_with_matching_bytes(self):
        source={'rulemoor/core.py':'abc','tools/unit.py':'def'}
        good={'origin':'/opt/rulemoor/venv/lib/python3.12/site-packages/rulemoor','hashes':{'rulemoor/core.py':'abc'}}
        installed_provenance(good,source)
        for origin in ('/opt/rulemoor-validation/rulemoor','/opt/rulemoor/venv/lib/../rulemoor',
                       '/opt/rulemoor/venv/lib/python3.12/site-packages/other'):
            with self.assertRaises(AssertionError):installed_provenance({**good,'origin':origin},source)

    def test_native_receipt_must_match_vm_source_and_test_outcomes(self):
        source={'rulemoor/core.py':'abc'}
        good={'passed':True,'platform':'Darwin','source':source,'source_sha256':fingerprint(source),
              'tests':2,'test_ids':['one','two'],'failures':0,'errors':0,'skipped':0}
        verify_native(good,source)
        for key,value in (('tests',1),('test_ids',['one','one']),('errors',1),('skipped',1),('source_sha256','bad')):
            with self.subTest(key=key),self.assertRaises(AssertionError):verify_native({**good,key:value},source)

    def test_incomplete_report_is_not_success(self):
        for flag in (False,True):
            page=render({'passed':flag,'cases':[{'name':'boot','passed':False}]})
            self.assertIn('FAIL / INCOMPLETE',page)
            self.assertIn('No early-boot zero-gap or sudden power-loss claim',page)
            self.assertNotIn('<h1>Boot design experiments: PASS',page)

    def test_report_escapes_untrusted_labels(self):
        page=render({'cases':[{'name':'<script>oops</script>','passed':False}]})
        self.assertNotIn('<script>',page)
        self.assertIn('&lt;script&gt;',page)
