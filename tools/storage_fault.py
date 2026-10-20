"""Real ENOSPC and journal-corruption tests, invoked only in a bounded test tmpfs."""
import errno
import json
from pathlib import Path
import sys
import os
import subprocess
import time
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
        c.apply('storage-full', 0, NEXT, 1)
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
        result = {'enospc_observed': True, 'reserve_released': not (root / 'reserve').exists(),
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
