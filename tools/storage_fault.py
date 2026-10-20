"""Real ENOSPC and journal-corruption tests, invoked only in a bounded test tmpfs."""
import errno
import json
from pathlib import Path
import sys
import os
import subprocess
import time
import sqlite3
from contextlib import contextmanager
from unittest.mock import patch
from rulemoor.backend import NftBackend
from rulemoor.core import Controller, Store, Conflict
from rulemoor.policy import expected
from .linux_cases import BASE, NEXT


def main():
    root = Path(sys.argv[1])
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=16m,mode=0700', 'tmpfs', str(root)], check=True, timeout=3)
    fs = os.statvfs(root)
    assert fs.f_blocks * fs.f_frsize == 16 * 1024 * 1024, 'Refuse to fill a filesystem of unexpected capacity'
    assert any(line.split(' - ')[1].startswith('tmpfs ') and line.split()[4] == str(root) for line in Path('/proc/self/mountinfo').read_text().splitlines()), 'Not a private test tmpfs'
    c = Controller(root, NftBackend())
    result = None
    try:
        c.initialize(BASE)
        pending = c.apply('checkpoint-maintenance', c.s['generation'], NEXT, 1)
        original = c.store.connect
        calls = 0
        @contextmanager
        def fail_after_commit():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise sqlite3.OperationalError('injected post-commit checkpoint failure')
            with original() as connection:
                yield connection
        with patch.object(c.store, 'connect', fail_after_commit):
            committed = c.confirm(pending['op'], pending['generation'], pending['candidate_digest'],
                                  pending['challenge'], c.backend.clock())
        assert committed['phase'] == Store(root).load()['phase'] == 'COMMITTED'
        assert committed.get('journal_maintenance_warning')
        time.sleep(max(0, pending['deadline'] - c.backend.clock()) + .02)
        c.tick()
        assert c.backend.read() == expected(NEXT) and c.s['phase'] == 'COMMITTED'
        c.close(); c = Controller(root, NftBackend())
        assert c.start()['phase'] == 'COMMITTED' and c.backend.read() == expected(NEXT)
        reset = c.apply('restore-before-enospc', c.s['generation'], BASE, 2)
        c.confirm(reset['op'], reset['generation'], reset['candidate_digest'], reset['challenge'], c.backend.clock())
        c.apply('storage-full', c.s['generation'], NEXT, 1)
        filler = root / 'fill'
        full = False
        with filler.open('wb', buffering=0) as stream:
            try:
                for _ in range(257):
                    stream.write(bytes(65536))
                raise AssertionError('Test filesystem did not reach ENOSPC within its proven bound')
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise
                full = True
        assert full
        time.sleep(max(0, c.s['deadline'] - c.backend.clock()) + .02)
        c.tick()
        actual = c.backend.read()
        assert actual == expected(BASE), 'Real ENOSPC prevented restoring known baseline'
        assert c.s['phase'] == 'ROLLED_BACK' and Store(root).load()['phase'] == 'ROLLED_BACK'
        filler.unlink()
        # A second real admission guard checks the logical state-directory budget.
        filler.write_bytes(bytes(4 * 1024 * 1024))
        try:
            c.apply('over-budget', c.s['generation'], NEXT, 2)
        except Conflict:
            pass
        else:
            raise AssertionError('Oversized state directory accepted a new change')
        filler.unlink()
        assert c.backend.read() == expected(BASE)
        c.close()
        (root / 'state.sqlite').write_bytes(b'corrupt database')
        c = Controller(root, NftBackend())
        assert c.start()['phase'] == 'DEGRADED' and c.backend.read() == expected(BASE)
        result = {'post_commit_checkpoint_failure_preserved': True, 'enospc_observed': True, 'reserve_released': not (root / 'reserve').exists(),
                          'baseline_restored': True, 'rollback_journal_verified': True,
                          'directory_budget_rejected': True, 'corrupt_journal_blocked': True,
                          'scope': 'Actual 16 MiB tmpfs exhaustion; no power-loss or filesystem-corruption recovery claim',
                          'verified_filesystem_bytes': fs.f_blocks * fs.f_frsize, 'write_limit_bytes': 257 * 65536}
    finally:
        c.close()
        subprocess.run(['umount', str(root)], check=True, timeout=3)
    result['test_tmpfs_unmounted'] = True
    print(json.dumps(result))


if __name__ == '__main__':
    main()
