import json
import os
import platform
import resource
import sys
import time
import unittest
from .evidence import manifest, fingerprint, save


def main():
    began = time.monotonic()
    suite = unittest.defaultTestLoader.discover('tests', pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    usage = resource.getrusage(resource.RUSAGE_SELF)
    out = {'passed': result.wasSuccessful() and result.testsRun > 0, 'tests': result.testsRun,
           'failures': len(result.failures), 'errors': len(result.errors),
           'skipped': len(result.skipped), 'seconds': time.monotonic() - began,
           'source': manifest(), 'source_sha256': fingerprint(manifest()),
           'run_id': os.environ.get('RULEMOOR_RUN_ID'), 'platform': platform.system(),
           'architecture': platform.machine(), 'python': platform.python_version(),
           'test_process_peak_rss_bytes': usage.ru_maxrss * (1 if platform.system() == 'Darwin' else 1024),
           'scope': 'Portable production-core contracts with a memory backend; not real nft or network performance'}
    save(os.environ.get('RULEMOOR_UNIT_OUTPUT', 'results/unit.json'), out)
    print(json.dumps({k: v for k, v in out.items() if k != 'source'}))
    raise SystemExit(0 if out['passed'] else 1)


if __name__ == '__main__':
    main()
