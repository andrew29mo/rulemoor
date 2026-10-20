"""Portable contract tests call the production Controller; kernel behavior is tested separately."""
import copy
import json
import os
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from rulemoor.core import Controller, Conflict, MAX_HISTORY, Store
from rulemoor.policy import validate, expected, compile_policy, canonical, digest

BASE = {'default': 'accept', 'rules': [{'port': 59991, 'verdict': 'drop'}]}
NEXT = {'default': 'drop', 'rules': [{'port': 18443, 'verdict': 'accept'}]}


class MemoryBackend:
    def __init__(self):
        self.value = None
        self.t = 100.
        self.boot_value = 'test-boot'
        self.calls = 0
    def clock(self): return self.t
    def boot(self): return self.boot_value
    def read(self): return copy.deepcopy(self.value)
    def check(self, policy, replace=True): validate(policy)
    def initialize(self, policy): self.value = expected(policy)
    def execute(self, root, state, policy, fd, persist, hook):
        self.calls += 1
        self.value = expected(policy)
    def retire(self, root, state): pass


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.b = MemoryBackend()
        self.c = Controller(self.temp.name, self.b)
        self.c.initialize(BASE)
    def tearDown(self):
        self.c.close()
        self.temp.cleanup()
    def apply(self, **kw):
        return self.c.apply(kw.get('op', 'change-1'), self.c.s['generation'], NEXT, kw.get('window', 10))
    def confirm(self, state=None, at=101.):
        s = state or self.c.status()
        return self.c.confirm(s['op'], s['generation'], s['candidate_digest'], s['challenge'], at)
    def restart(self):
        self.c.close()
        self.c = Controller(self.temp.name, self.b)
        return self.c.start()
    def test_commit_and_restart(self):
        self.apply(); self.confirm()
        self.assertEqual(self.restart()['phase'], 'COMMITTED')
        self.assertEqual(self.b.read(), expected(NEXT))
    def test_pending_restart_restores(self):
        old = self.apply()
        s = self.restart()
        self.assertEqual(s['phase'], 'ROLLED_BACK')
        self.assertGreater(s['generation'], old['generation'])
        self.assertEqual(self.b.read(), expected(BASE))
        self.assertEqual(self.restart()['phase'], 'ROLLED_BACK')
    def test_timeout(self):
        self.apply(); self.b.t = 110.; self.c.tick()
        self.assertEqual(self.c.s['phase'], 'ROLLED_BACK')
        self.assertEqual(self.b.read(), expected(BASE))
    def test_expired_confirm_without_timer(self):
        self.apply(); self.b.t = 110.
        with self.assertRaises(Conflict): self.confirm()
        self.assertEqual(self.c.s['phase'], 'AWAITING_CONFIRM')
    def test_readback_time_cannot_extend_confirmation(self):
        self.apply()
        read = self.b.read
        def slow():
            self.b.t = 111.
            return read()
        with patch.object(self.b, 'read', slow):
            with self.assertRaises(Conflict): self.confirm()
    def test_old_connection(self):
        self.apply()
        with self.assertRaises(Conflict): self.confirm(at=100.)
    def test_wrong_challenge_generation_and_digest(self):
        self.apply()
        for field in ('generation', 'candidate_digest', 'challenge', 'op'):
            state = self.c.status()
            state[field] = 999 if field == 'generation' else 'wrong'
            with self.subTest(field=field), self.assertRaises(Conflict): self.confirm(state)
    def test_apply_idempotence(self):
        first = self.apply()
        again = self.c.apply('change-1', 0, NEXT, 10)
        self.assertEqual(again, first)
        self.assertEqual(self.b.calls, 1)
        with self.assertRaises(Conflict): self.c.apply('change-1', 0, BASE, 10)
    def test_stale_apply(self):
        self.apply()
        with self.assertRaises(Conflict): self.c.apply('change-2', 0, BASE, 10)
    def test_cancel_and_stale_cancel(self):
        state = self.apply()
        self.c.cancel(state['op'], state['generation'])
        self.assertEqual(self.b.read(), expected(BASE))
        with self.assertRaises(Conflict): self.c.cancel(state['op'], state['generation'])
    def test_confirmed_not_cancelled(self):
        state = self.apply(); self.confirm()
        with self.assertRaises(Conflict): self.c.cancel(state['op'], state['generation'])
    def test_drift_blocks_apply(self):
        self.b.value = [{'unknown': True}]
        with self.assertRaises(Conflict): self.apply()
        self.assertEqual(self.c.s['phase'], 'DEGRADED')
        self.assertEqual(self.b.calls, 0)
    def test_unknown_during_pending_not_overwritten(self):
        self.apply(); self.b.value = [{'foreign': True}]; self.b.t = 111.; self.c.tick()
        self.assertEqual(self.c.s['phase'], 'DEGRADED')
        self.assertEqual(self.b.read(), [{'foreign': True}])
    def test_unknown_before_readback_not_blessed(self):
        def drift(point):
            if point == 'kernel-applied': self.b.value = [{'foreign': True}]
        self.c.hook = drift
        self.apply()
        self.assertEqual(self.c.s['phase'], 'DEGRADED')
    def test_unknown_before_confirm(self):
        self.apply(); self.b.value = [{'foreign': True}]
        with self.assertRaises(Conflict): self.confirm()
        self.assertEqual(self.c.s['phase'], 'DEGRADED')
    def test_foreign_boot_rejects_confirm(self):
        self.apply(); self.b.boot_value = 'another-boot'
        with self.assertRaises(Conflict): self.confirm()
        self.c.tick()
        self.assertEqual(self.c.s['phase'], 'ROLLED_BACK')
    def test_confirmation_persistence_failure(self):
        self.apply()
        with patch.object(self.c.store, 'save', side_effect=sqlite3.OperationalError('disk full')):
            with self.assertRaises(sqlite3.Error): self.confirm()
        self.assertEqual(self.c.s['phase'], 'AWAITING_CONFIRM')
        self.assertEqual(self.restart()['phase'], 'ROLLED_BACK')
    def test_post_commit_checkpoint_failure_preserves_confirmation(self):
        self.apply()
        original = self.c.store.connect
        calls = 0
        @contextmanager
        def failed_checkpoint_connection():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise sqlite3.OperationalError('injected post-commit checkpoint failure')
            with original() as connection:
                yield connection
        error = None
        with patch.object(self.c.store, 'connect', failed_checkpoint_connection):
            try:
                result = self.confirm()
            except sqlite3.Error as exc:
                error = type(exc).__name__
        self.assertIsNone(error, 'Post-commit maintenance was misreported as a failed confirmation')
        self.assertEqual(result['phase'], 'COMMITTED')
        self.assertEqual(self.c.store.load()['phase'], 'COMMITTED')
        self.assertIn('journal_maintenance_warning', result)
        self.b.t = 111.
        self.c.tick()
        self.assertEqual(self.c.s['phase'], 'COMMITTED')
        self.assertEqual(self.b.read(), expected(NEXT))
        self.assertEqual(self.restart()['phase'], 'COMMITTED')

    def executor_exit_recovery(self, boundary):
        from rulemoor.backend import NftBackend
        self.apply(op='exit-' + boundary)
        token = 'e' * 32
        record = {'pid': 12345678, 'start_ticks': 1, 'boot': 'test-boot', 'token': token}
        Path(self.temp.name, 'executor-' + token + '.json').write_text(json.dumps(record))
        self.c.s['executor_token'] = token
        self.c._save('simulated_executor_record')
        self.b.retire = NftBackend().retire
        identity = {k: record[k] for k in ('pid', 'start_ticks', 'boot')}
        descriptor = os.open(os.devnull, os.O_RDONLY) if boundary == 'pidfd_send_signal' else None
        with patch('rulemoor.backend.clock', return_value=100.), patch('rulemoor.backend.identity', return_value=identity), \
             patch('rulemoor.backend.os.pidfd_open', create=True, side_effect=ProcessLookupError() if boundary == 'pidfd_open' else None, return_value=descriptor), \
             patch('rulemoor.backend.signal.pidfd_send_signal', create=True, side_effect=ProcessLookupError()):
            self.assertEqual(self.restart()['phase'], 'ROLLED_BACK')
        self.assertEqual(self.b.read(), expected(BASE))

    def test_executor_exit_before_pidfd_open_recovers(self):
        self.executor_exit_recovery('pidfd_open')

    def test_executor_exit_before_pidfd_signal_recovers(self):
        self.executor_exit_recovery('pidfd_send_signal')

    def test_executor_permission_failure_still_blocks_recovery(self):
        from rulemoor.backend import NftBackend
        self.apply()
        token = 'f' * 32
        record = {'pid': 12345678, 'start_ticks': 1, 'boot': 'test-boot', 'token': token}
        Path(self.temp.name, 'executor-' + token + '.json').write_text(json.dumps(record))
        self.c.s['executor_token'] = token; self.c._save('simulated_executor_record')
        self.b.retire = NftBackend().retire
        identity = {k: record[k] for k in ('pid', 'start_ticks', 'boot')}
        with patch('rulemoor.backend.clock', return_value=100.), patch('rulemoor.backend.identity', return_value=identity), \
             patch('rulemoor.backend.os.pidfd_open', create=True, side_effect=PermissionError()):
            self.assertEqual(self.restart()['phase'], 'DEGRADED')
        self.assertEqual(self.b.read(), expected(NEXT))

    def test_rollback_despite_journal_write_failure(self):
        self.apply(); self.b.t = 111.
        with patch.object(self.c.store, 'save', side_effect=sqlite3.OperationalError('disk full')):
            self.c.tick()
        self.assertEqual(self.b.read(), expected(BASE))
        self.assertEqual(self.c.s['phase'], 'DEGRADED')
        self.assertFalse(Path(self.temp.name, 'reserve').exists())
        with self.assertRaises(Conflict): self.apply(op='other')
    def test_space_guard_precedes_kernel_write(self):
        with patch('rulemoor.core.shutil.disk_usage', return_value=type('Disk', (), {'free': 0})()):
            with self.assertRaises(Conflict): self.apply()
        self.assertEqual(self.b.calls, 0)
    def test_corrupt_journal_no_write(self):
        self.c.close()
        Path(self.temp.name, 'state.sqlite').write_bytes(b'not a database')
        self.c = Controller(self.temp.name, self.b)
        self.assertEqual(self.c.start()['phase'], 'DEGRADED')
        self.assertEqual(self.b.calls, 0)
    def test_journal_open_error_closes_connection(self):
        connection = MagicMock()
        connection.execute.side_effect = sqlite3.DatabaseError('corrupt journal')
        with patch('rulemoor.core.sqlite3.connect', return_value=connection):
            with self.assertRaises(sqlite3.DatabaseError):
                with Store(self.temp.name).connect():
                    self.fail('Corrupt journal unexpectedly opened')
        connection.close.assert_called_once()
    def test_one_owner(self):
        with self.assertRaises(RuntimeError): Controller(self.temp.name, self.b)
    def test_bounded_history_and_receipts(self):
        for i in range(24):
            s = self.apply(op='op-' + str(i)); self.c.cancel(s['op'], s['generation'])
        self.assertLessEqual(len(self.c.store.history()), MAX_HISTORY)
        self.assertEqual(self.b.read(), expected(BASE))
    def test_invalid_requests_do_not_write(self):
        for window in (0, 301, float('nan'), True):
            with self.subTest(window=window), self.assertRaises(ValueError): self.apply(window=window)
        self.assertEqual(self.b.calls, 0)
    def test_shutdown_rolls_back(self):
        self.apply(); self.c.shutdown()
        self.assertEqual(self.c.s['phase'], 'ROLLED_BACK')


class PolicyTests(unittest.TestCase):
    def test_injection_unknown_keys_and_types(self):
        for value in ({'default': 'accept; flush ruleset', 'rules': []},
                      {'default': 'accept', 'rules': [], 'extra': 1},
                      {'default': 'accept', 'rules': [{'port': True, 'verdict': 'accept'}]},
                      {'default': 'accept', 'rules': [{'port': 0, 'verdict': 'drop'}]},
                      {'default': 'accept', 'rules': [{'port': 10, 'verdict': 'queue'}]},
                      {'default': 'accept', 'rules': [{'port': 10, 'verdict': 'drop'}] * 33}):
            with self.subTest(value=value), self.assertRaises(ValueError): validate(value)
    def test_order_and_default_are_policy(self):
        reverse = {'default': 'accept', 'rules': [{'port': 1, 'verdict': 'drop'}, {'port': 1, 'verdict': 'accept'}]}
        other = copy.deepcopy(reverse); other['rules'].reverse()
        self.assertNotEqual(digest(expected(reverse)), digest(expected(other)))
        other = copy.deepcopy(reverse); other['default'] = 'drop'
        self.assertNotEqual(digest(expected(reverse)), digest(expected(other)))
    def test_expected_matches_contract(self):
        rows = expected(BASE)
        self.assertEqual(rows[1]['chain']['policy'], 'accept')
        self.assertEqual(rows[-1]['rule']['expr'][0]['match']['right'], 59991)
        self.assertIn('delete table ip rulemoor', compile_policy(BASE))
    def test_canonical_retains_unknowns(self):
        raw = {'nftables': [{'metainfo': {}}, {'rule': {'handle': 5, 'expr': [{'unknown': 1}]}}]}
        self.assertEqual(canonical(raw), [{'rule': {'expr': [{'unknown': 1}]}}])


class RecoveryMetadataTests(unittest.TestCase):
    def test_corrupt_executor_metadata_is_degraded_without_signaling(self):
        from rulemoor.backend import NftBackend
        token = 'a' * 32
        valid = {'pid': 12345678, 'start_ticks': 1, 'boot': 'test-boot', 'token': token}
        payloads = ['{broken', '{}', json.dumps({**valid, 'pid': True}),
                    json.dumps({**valid, 'start_ticks': 'wrong'}),
                    json.dumps({**valid, 'boot': None}), json.dumps({**valid, 'token': 'b' * 32}),
                    ' ' * 4097 + json.dumps(valid)]
        for payload in payloads:
            with self.subTest(payload=payload[:80]), tempfile.TemporaryDirectory() as root:
                b = MemoryBackend(); c = Controller(root, b)
                c.initialize(BASE); c.apply('metadata', 0, NEXT, 10)
                c.s['executor_token'] = token; c._save('metadata_fixture'); c.close()
                Path(root, 'executor-' + token + '.json').write_text(payload)
                b.retire = NftBackend().retire
                c = Controller(root, b)
                error = None
                try:
                    with patch('rulemoor.backend.clock', return_value=100.), \
                         patch('rulemoor.backend.identity', side_effect=AssertionError('Invalid record reached a process lookup')):
                        try: result = c.start()
                        except Exception as exc: error = type(exc).__name__
                    self.assertIsNone(error, 'Malformed metadata aborted startup instead of reporting DEGRADED')
                    self.assertEqual(result['phase'], 'DEGRADED')
                    self.assertEqual(b.read(), expected(NEXT))
                    with self.assertRaises(Conflict): c.apply('blocked', 1, BASE, 10)
                finally:
                    c.close()
