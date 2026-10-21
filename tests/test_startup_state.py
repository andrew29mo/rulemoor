"""Persist malformed snapshots in real SQLite and invoke production startup."""
import copy
import json
import tempfile
import unittest
from unittest.mock import patch
from rulemoor.core import Controller, Conflict, MAX_SNAPSHOT_BYTES
from rulemoor.policy import expected
from tests.test_core import MemoryBackend, BASE, NEXT


class StartupStateTests(unittest.TestCase):
    def check_invalid(self, value, raw=False):
        with tempfile.TemporaryDirectory() as root:
            backend=MemoryBackend(); c=Controller(root,backend); c.initialize(BASE)
            payload=value if raw else json.dumps(value)
            with c.store.connect() as db:db.execute('UPDATE snapshot SET value=? WHERE id=1',(payload,))
            c.close(); c=Controller(root,backend)
            try:
                with patch.object(backend,'retire',side_effect=AssertionError('must not signal')), patch.object(backend,'read',side_effect=AssertionError('must not access kernel')):
                    s=c.start()
                self.assertEqual(s['phase'],'DEGRADED');self.assertTrue(c.storage_failed)
                self.assertEqual(backend.value, expected(BASE))
                with c.store.connect() as db:self.assertEqual(db.execute('SELECT value FROM snapshot').fetchone()[0],payload)
                with self.assertRaises(Conflict):c.apply('blocked',0,NEXT,5)
                self.assertEqual(c.start()['phase'],'DEGRADED')
            finally:c.close()

    def test_missing_or_wrong_state_shape_is_diagnostic(self):
        for value in ([],{},None,{'phase':[]},{'phase':'unknown'}):
            with self.subTest(value=value):self.check_invalid(value)

    def test_invalid_policy_and_generation_are_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            c=Controller(root,MemoryBackend()); good=c.initialize(BASE); c.close()
        for key,value in (('current',{'default':'invalid','rules':[]}),('generation',True),('generation',-1),('generation',2**80),('boot',None),('deadline',10**1000)):
            bad=copy.deepcopy(good);bad[key]=value
            with self.subTest(key=key,value=value):self.check_invalid(bad)

    def test_incomplete_pending_state_is_diagnostic(self):
        self.check_invalid({'phase':'AWAITING_CONFIRM','generation':1,'op':'bad','boot':'test-boot','current':BASE})

    def test_parser_resource_and_nonfinite_values_are_diagnostic(self):
        for raw in ('['*1100+']'*1100,' '*MAX_SNAPSHOT_BYTES+'{}','NaN','{"phase":"COMMITTED","generation":NaN}'):
            with self.subTest(prefix=raw[:32]):self.check_invalid(raw,raw=True)

    def test_oversized_valid_snapshot_is_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            c=Controller(root,MemoryBackend());good=c.initialize(BASE);c.close()
        self.check_invalid(' '*MAX_SNAPSHOT_BYTES+json.dumps(good),raw=True)

    def test_missing_snapshot_row_is_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            c=Controller(root,MemoryBackend());c.initialize(BASE)
            with c.store.connect() as db:db.execute('DELETE FROM snapshot')
            c.close();c=Controller(root,MemoryBackend())
            try:self.assertEqual(c.start()['phase'],'DEGRADED')
            finally:c.close()

    def test_initial_operation_id_pending_restart_restores_baseline(self):
        with tempfile.TemporaryDirectory() as root:
            backend=MemoryBackend();c=Controller(root,backend);c.initialize(BASE)
            old=c.apply('initial',0,NEXT,10);c.close()
            c=Controller(root,backend)
            try:
                restored=c.start()
                self.assertEqual(restored['phase'],'ROLLED_BACK')
                self.assertGreater(restored['generation'],old['generation'])
                self.assertEqual(backend.value,expected(BASE))
                fresh=c.apply('new-after-initial',restored['generation'],NEXT,10)
                with self.assertRaises(Conflict):c.cancel(old['op'],old['generation'])
                with self.assertRaises(Conflict):c.confirm(**{k:old[k] for k in ('op','generation','candidate_digest','challenge')},connected_at=101.)
                self.assertEqual(c.status(),fresh)
                self.assertEqual(backend.value,expected(NEXT))
            finally:c.close()

    def test_initial_operation_id_confirmed_restart_remains_manageable(self):
        with tempfile.TemporaryDirectory() as root:
            backend=MemoryBackend();c=Controller(root,backend);c.initialize(BASE)
            pending=c.apply('initial',0,NEXT,10)
            c.confirm(**{k:pending[k] for k in ('op','generation','candidate_digest','challenge')},connected_at=101.)
            c.close();c=Controller(root,backend)
            try:
                self.assertEqual(c.start()['phase'],'COMMITTED')
                self.assertFalse(c.storage_failed)
                self.assertEqual(backend.value,expected(NEXT))
                self.assertEqual(c.plan(BASE)['generation'],pending['generation'])
                self.assertEqual(c.apply('next-operation',pending['generation'],BASE,10)['phase'],'AWAITING_CONFIRM')
            finally:c.close()

    def test_unfinished_baseline_must_match_current_before_recovery(self):
        with tempfile.TemporaryDirectory() as root:
            c=Controller(root,MemoryBackend());c.initialize(BASE)
            pending=c.apply('mismatch',0,NEXT,10);c.close()
        for phase in ('PREPARED','APPLYING','AWAITING_CONFIRM','ROLLING_BACK'):
            bad=copy.deepcopy(pending);bad['phase']=phase
            bad['baseline']={'default':'accept','rules':[]}
            with self.subTest(phase=phase):self.check_invalid(bad)
