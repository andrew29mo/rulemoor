"""Production recovery contracts; real VM/process evidence is separate."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from rulemoor.backend import lock
from rulemoor.core import Controller, Conflict, Store
from rulemoor.policy import expected
from tests.test_core import MemoryBackend
from tests.test_dual_stack import confirm
from tools.dual_recovery import INITIAL, BASELINE, PENDING, SUCCESSOR, LATE, FINAL, writer_locked
from tools.deployment_report import recovery_stale_observations


class DualRecoveryTests(unittest.TestCase):
    def test_partial_reboot_restores_last_normal_commit_for_either_family(self):
        for family in ('ipv4','ipv6'):
            with self.subTest(family=family),tempfile.TemporaryDirectory() as root:
                b=MemoryBackend();c=Controller(root,b);c.initialize(INITIAL)
                base=c.apply('confirmed-baseline',0,BASELINE,30)
                confirm(c,base,'ipv4');confirm(c,base,'ipv6')
                old=c.apply('before-boot',base['generation'],PENDING,30);confirm(c,old,family)
                before=Store(root).load();c.close()
                self.assertEqual(before['phase'],'AWAITING_CONFIRM');self.assertEqual(before['confirmed_families'],[family])
                b.boot_value='new-boot';b.value=None;c=Controller(root,b)
                try:
                    restored=c.start()
                    self.assertEqual(restored['phase'],'ROLLED_BACK');self.assertEqual(restored['current'],BASELINE)
                    self.assertEqual(b.read(),expected(BASELINE));self.assertGreater(restored['generation'],old['generation'])
                    new=c.apply('after-boot',restored['generation'],SUCCESSOR,30)
                    with self.assertRaises(Conflict):confirm(c,old,'ipv6')
                    with self.assertRaises(Conflict):c.cancel(old['op'],old['generation'])
                    with self.assertRaises(Conflict):c.apply('stale-base',old['generation'],LATE,30)
                    self.assertEqual(c.status(),new);self.assertEqual(b.read(),expected(SUCCESSOR))
                    confirm(c,new,'ipv4');self.assertEqual(confirm(c,new,'ipv6')['phase'],'COMMITTED')
                finally:c.close()

    def test_inflight_dual_executor_must_retire_before_successor_admission(self):
        for retire_fails in (False,True):
            with self.subTest(retire_fails=retire_fails),tempfile.TemporaryDirectory() as root:
                b=MemoryBackend();c=Controller(root,b);c.initialize(BASELINE);execute=b.execute
                def held(*args,**kwargs):raise SystemExit('simulated abrupt Agent exit before executor writes')
                b.execute=held
                with self.assertRaises(SystemExit):c.apply('held',0,LATE,30)
                old=c.status();self.assertEqual(old['phase'],'APPLYING');c.close();b.execute=execute
                observations=[]
                def retire(state_root,state):
                    observations.append((copy.deepcopy(state),b.read()))
                    if retire_fails:raise RuntimeError('old writer cannot be retired')
                b.retire=retire;c=Controller(root,b)
                try:
                    restored=c.start()
                    self.assertEqual(len(observations),1);self.assertEqual(observations[0],(old,expected(BASELINE)))
                    self.assertEqual(b.read(),expected(BASELINE))
                    if retire_fails:
                        self.assertEqual(restored['phase'],'DEGRADED')
                        with self.assertRaises(Conflict):c.apply('new',restored['generation'],FINAL,30)
                    else:
                        self.assertEqual(restored['phase'],'ROLLED_BACK');self.assertGreater(restored['generation'],old['generation'])
                        new=c.apply('new',restored['generation'],FINAL,30)
                        with self.assertRaises(Conflict):c.cancel(old['op'],old['generation'])
                        self.assertEqual(b.read(),expected(FINAL));confirm(c,new,'ipv4');confirm(c,new,'ipv6')
                finally:c.close()

    def test_real_writer_lock_observation_does_not_treat_missing_path_as_held(self):
        with tempfile.TemporaryDirectory() as root,patch('tools.dual_recovery.g.STATE',Path(root)):
            self.assertFalse(writer_locked())
            fd=lock(Path(root)/'writer.lock')
            try:self.assertTrue(writer_locked())
            finally:os.close(fd)
            self.assertFalse(writer_locked())
        with patch('tools.dual_recovery.g.STATE',Path(root)/'missing'):
            with self.assertRaises(FileNotFoundError):writer_locked()

    def test_stale_evidence_rejects_one_family_mutation_and_journal_changes(self):
        state={'phase':'AWAITING_CONFIRM','generation':4}
        rows=[{'path':'/cancel','status':409,'before':state,'after':state,
               'kernel_before':expected(FINAL),'kernel_after':expected(FINAL)}]
        recovery_stale_observations(rows,('/cancel',),state,FINAL)
        for change in ('kernel','journal','status','missing'):
            bad=copy.deepcopy(rows)
            if change=='kernel':bad[0]['kernel_after']=expected({'ipv4':FINAL['ipv4'],'ipv6':LATE['ipv6']})
            elif change=='journal':bad[0]['after']['phase']='ROLLED_BACK'
            elif change=='status':bad[0]['status']=200
            else:bad=[]
            with self.subTest(change=change),self.assertRaises(AssertionError):recovery_stale_observations(bad,('/cancel',),state,FINAL)
