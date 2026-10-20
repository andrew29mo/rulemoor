"""Revalidate retained evidence against current executable inputs, including HTML consistency."""
import argparse
import hashlib
import json
from pathlib import Path
from .evidence import manifest
from .report import verify, render


def main():
    p = argparse.ArgumentParser(); p.add_argument('directory'); a = p.parse_args()
    root = Path(a.directory)
    host, native, linux, combined = [json.loads((root / n).read_text()) for n in ('host.json', 'native.json', 'linux.json', 'combined.json')]
    verify(linux, native, host, manifest())
    assert combined == {'passed': host['passed'], 'cases': linux['cases'], 'host': host, 'native': native, 'linux': linux}
    assert (root / 'report.html').read_text() == render(combined)
    receipts = json.loads((root / 'mutations.json').read_text())
    assert receipts['source'] == manifest() and receipts['run_id'] == host['run_id'] and receipts['passed']
    assert receipts['rows'] == host['production_mutations']
    print(json.dumps({'passed': True, 'run_id': host['run_id'], 'files': {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ('host.json', 'native.json', 'linux.json', 'combined.json', 'report.html', 'mutations.json')}}))


if __name__ == '__main__':
    main()
