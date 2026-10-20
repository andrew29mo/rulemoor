"""Linux driver fails closed and retains every attempted case and cleanup outcome."""
import json
import os
from pathlib import Path
import tempfile
import time
import traceback
from . import linux_cases as cases
from .evidence import manifest, fingerprint, save
from .process import run


def main():
    output = Path('/app/results'); output.mkdir(exist_ok=True)
    source = manifest()
    value = {'schema': 1, 'run_id': os.environ.get('RULEMOOR_RUN_ID'), 'passed': False,
             'execution': 'Colima Linux VM; real nftables/netns/TLS', 'source': source,
             'source_sha256': fingerprint(source), 'cases': []}
    save(output / 'linux.json', value)
    initial = cases.call(['nft', '-j', 'list', 'ruleset']).stdout
    try:
        unit = run([os.sys.executable, '-m', 'tools.unit'], timeout=60)
        value['unit_stage'] = {k: v for k, v in unit.items() if k not in ('stdout', 'stderr')}
        (output / 'unit.log').write_text(unit['stdout'] + unit['stderr'])
        assert unit['passed'], 'Portable contracts failed on Linux'
        value['unit'] = json.loads(Path('results/unit.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            value['environment'] = cases.topology(parent)
            for name, fn in [('atomic_batches', cases.atomicity), ('management_path', cases.management),
                             ('crash_matrix', cases.crash_matrix), ('service_recovery', cases.service_recovery),
                             ('queued_connection_and_response_loss', cases.queued_connection_and_lost_response), ('storage_faults', cases.storage_faults), ('measurement', cases.measurement)]:
                began = time.monotonic(); row = {'name': name, 'passed': False}
                try:
                    row.update(evidence=fn(parent), passed=True)
                except Exception as exc:
                    row.update(error=type(exc).__name__ + ': ' + str(exc),
                               traceback=traceback.format_exc().replace(tmp, '<case-state>'))
                row['seconds'] = time.monotonic() - began
                value['cases'].append(row)
                save(output / 'linux.json', value)
                print(name, row['passed'], flush=True)
                # A failed case must not leave an active agent affecting later measurements.
                for p in cases.PROCESSES:
                    cases.stop(p)
    except BaseException as exc:
        value.update(error=type(exc).__name__ + ': ' + str(exc), traceback=traceback.format_exc())
    finally:
        try:
            value['cleanup'] = cases.cleanup()
            value['cleanup']['container_root_rules_unchanged'] = cases.call(['nft', '-j', 'list', 'ruleset']).stdout == initial
        except Exception as exc:
            value['cleanup'] = {'passed': False, 'error': type(exc).__name__}
        value['source_changed'] = manifest() != source
        value['passed'] = (len(value['cases']) == 7 and all(r['passed'] for r in value['cases'])
                           and value.get('unit_stage', {}).get('passed', False)
                           and value['cleanup']['passed'] and value['cleanup'].get('container_root_rules_unchanged', False)
                           and not value['source_changed'] and 'error' not in value)
        save(output / 'linux.json', value)
    raise SystemExit(0 if value['passed'] else 1)


if __name__ == '__main__':
    main()
