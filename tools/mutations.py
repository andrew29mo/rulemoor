"""Portable negative controls: production changes must be caught by existing tests."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from .evidence import ROOT, manifest, save
from .process import run

MUTATIONS = [
    ('rulemoor/core.py', 'reserve-initial-operation-id', "is_initialization = set(s)==common and s['op']=='initial' and s['candidate'] is None", "is_initialization = s['op']=='initial'", 'tests.test_startup_state.StartupStateTests.test_initial_operation_id_pending_restart_restores_baseline'),
    ('rulemoor/core.py', 'accept-mismatched-recovery-baseline', "if s['phase'] in {'PREPARED','APPLYING','AWAITING_CONFIRM','ROLLING_BACK','ROLLED_BACK'} and s['current']!=s['baseline']:", "if False:", 'tests.test_startup_state.StartupStateTests.test_unfinished_baseline_must_match_current_before_recovery'),
    ('rulemoor/core.py', 'skip-persisted-state-validation', 'return validate_snapshot(json.loads(raw, parse_constant=invalid_constant))', 'return json.loads(raw, parse_constant=invalid_constant)', 'tests.test_startup_state.StartupStateTests.test_invalid_policy_and_generation_are_diagnostic'),
    ('rulemoor/core.py', 'ignore-snapshot-size-bound', 'not 0 < size[0] <= MAX_SNAPSHOT_BYTES', 'not 0 < size[0]', 'tests.test_startup_state.StartupStateTests.test_oversized_valid_snapshot_is_diagnostic'),
    ('rulemoor/core.py', 'cancel-new-operation-with-old-request', "or (op, generation) != (self.s['op'], self.s['generation'])", 'or False', 'tests.test_core.CoreTests.test_pre_recovery_requests_cannot_finalize_new_pending_operation'),
    ('rulemoor/core.py', 'skip-boot-table-restore', 'self.backend.initialize(policy)', 'pass', 'tests.test_core.CoreTests.test_reboot_missing_table_restores_unconfirmed_baseline'),
    ('rulemoor/core.py', 'restore-same-boot-deletion', 'if rebooted and self.backend.read() is None:', 'if self.backend.read() is None:', 'tests.test_core.CoreTests.test_same_boot_missing_table_is_not_recreated'),
    ('rulemoor/core.py', 'reuse-preboot-generation', "elif rebooted:\n                            self.s['generation'] += 1", 'elif rebooted:\n                            pass', 'tests.test_core.CoreTests.test_reboot_restores_committed_policy_and_fences_old_base'),
    ('rulemoor/core.py', 'accept-old-connection', "or connected_at <= s['applied_at']", 'or False', 'tests.test_core.CoreTests.test_old_connection'),
    ('rulemoor/core.py', 'accept-expired-confirmation', "self.backend.clock() >= s['deadline']", "False", 'tests.test_core.CoreTests.test_expired_confirm_without_timer'),
    ('rulemoor/core.py', 'bless-unknown-readback', 'self.backend.read() != expected(p):', 'False:', 'tests.test_core.CoreTests.test_unknown_before_readback_not_blessed'),
    ('rulemoor/core.py', 'skip-timeout-rollback', "self._rollback(fd, 'deadline')", 'pass', 'tests.test_core.CoreTests.test_timeout'),
    ('rulemoor/core.py', 'commit-before-durable-save', 'self.s = before', 'pass', 'tests.test_core.CoreTests.test_confirmation_persistence_failure'),
    ('rulemoor/core.py', 'misreport-post-commit-checkpoint', "self.checkpoint_warning = 'Journal checkpoint failed; transaction committed'", 'raise', 'tests.test_core.CoreTests.test_post_commit_checkpoint_failure_preserves_confirmation'),
    ('rulemoor/backend.py', 'fail-recovery-on-natural-exit', 'return  # Natural exit after identity check; caller still verifies writer.lock.', 'raise', 'tests.test_core.CoreTests.test_executor_exit_before_pidfd_open_recovers'),
    ('rulemoor/backend.py', 'unhandled-corrupt-executor-record', "raise RuntimeError('Invalid executor identity record; local operator recovery required') from None", 'raise', 'tests.test_core.RecoveryMetadataTests.test_corrupt_executor_metadata_is_degraded_without_signaling'),
    ('rulemoor/service.py', 'unbounded-header-trickle', 'threading.Timer(MAX_CONNECTION_SECONDS,', 'threading.Timer(60.0,', 'tests.test_api.APITests.test_absolute_lifetime_expires_dripping_unauthenticated_connections'),
]


def main():
    rows = []
    for file, name, old, new, test in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            for directory in ('rulemoor', 'tests', 'tools'):
                shutil.copytree(ROOT / directory, target / directory, ignore=shutil.ignore_patterns('__pycache__'))
            path = target / file; text = path.read_text()
            if old not in text:
                raise RuntimeError('Mutation anchor missing: ' + name)
            path.write_text(text.replace(old, new))
            outcome = run([sys.executable, '-m', 'unittest', test], timeout=10, cwd=target)
            # A test assertion failure is evidence; an import/syntax error is not.
            caught = outcome['exit_code'] == 1 and not outcome['timed_out'] and 'FAIL:' in outcome['stderr'] and 'ERROR:' not in outcome['stderr']
            rows.append({'name': name, 'test': test, 'caught_by_assertion': caught,
                         'exit_code': outcome['exit_code'], 'timed_out': outcome['timed_out']})
    value = {'passed': all(r['caught_by_assertion'] for r in rows), 'rows': rows,
             'source': manifest(), 'run_id': os.environ.get('RULEMOOR_RUN_ID')}
    save(os.environ.get('RULEMOOR_MUTATION_OUTPUT', 'results/mutations.json'), value)
    print(json.dumps({'passed': value['passed'], 'mutations': len(rows)}))
    raise SystemExit(0 if value['passed'] else 1)


if __name__ == '__main__':
    main()
