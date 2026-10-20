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
    ('accept-old-connection', "or connected_at <= s['applied_at']", 'or False', 'tests.test_core.CoreTests.test_old_connection'),
    ('accept-expired-confirmation', "self.backend.clock() >= s['deadline']", "False", 'tests.test_core.CoreTests.test_expired_confirm_without_timer'),
    ('bless-unknown-readback', 'self.backend.read() != expected(p):', 'False:', 'tests.test_core.CoreTests.test_unknown_before_readback_not_blessed'),
    ('skip-timeout-rollback', "self._rollback(fd, 'deadline')", 'pass', 'tests.test_core.CoreTests.test_timeout'),
    ('commit-before-durable-save', 'self.s = before', 'pass', 'tests.test_core.CoreTests.test_confirmation_persistence_failure'),
]


def main():
    rows = []
    for name, old, new, test in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            for directory in ('rulemoor', 'tests', 'tools'):
                shutil.copytree(ROOT / directory, target / directory, ignore=shutil.ignore_patterns('__pycache__'))
            path = target / 'rulemoor/core.py'; text = path.read_text()
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
