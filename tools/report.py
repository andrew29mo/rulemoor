"""Report only observed outcomes; unsuccessful runs remain visible."""
import html
import json
import statistics
from pathlib import Path
from .evidence import save


def render(value):
    rows = ''.join('<tr><td>' + html.escape(row['name']) + '</td><td>' +
                   ('PASS' if row['passed'] else 'FAIL') + '</td></tr>' for row in value.get('cases', []))
    measurements = next((r.get('evidence') for r in value.get('cases', []) if r['name'] == 'measurement' and r['passed']), None)
    metrics = '<p>No complete measurement case available.</p>'
    if measurements:
        metrics = '<h2>Observed Linux VM operations</h2><table><tr><th>TLS operation</th><th>Trials</th><th>Median ms</th><th>Range ms</th></tr>'
        for name in ('plan', 'apply', 'confirm', 'cancel'):
            item = measurements[name]
            metrics += f'<tr><td>{name}</td><td>{item["n"]}</td><td>{item["median_ms"]:.2f}</td><td>{item["min_ms"]:.2f}–{item["max_ms"]:.2f}</td></tr>'
        metrics += '</table><p>Agent VmHWM: ' + f'{measurements["rss"]["worker_high_water_bytes"] / 1048576:.2f} MiB' + '. Excludes nft children, clients and VM memory. State directory allocated: ' + str(measurements['disk']['allocated_bytes']) + ' bytes.</p>'
    return '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Rulemoor validation</title><style>body{font:16px system-ui;max-width:1000px;margin:3rem auto;padding:1rem;line-height:1.5}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:1rem}td,th{padding:.5rem;border:1px solid #ddd}table{border-collapse:collapse}</style>
<h1>Rulemoor validation: ''' + ('PASS' if value.get('passed') else 'FAIL') + '''</h1>
<p>Linux measurements are from a Colima VM. Native macOS validates portable contracts only.
Rule restoration and management reachability are separate observations. No production SLA or speedup is claimed.</p>
''' + metrics + '''
<table><tr><th>Case</th><th>Outcome</th></tr>''' + rows + '''</table>
<p>Complete observations, samples, memory scope and failure details:</p><pre>''' + html.escape(json.dumps(value, indent=2)) + '</pre></html>'


def verify(linux, native, host, source):
    assert linux['passed'] is True and native['passed'] is True and host['passed'] is True
    assert linux['source'] == native['source'] == source
    assert linux['unit']['source'] == source and linux['unit']['passed'] is True
    assert linux['unit']['run_id'] == host['run_id']
    assert linux['unit']['tests'] == native['tests'] and linux['unit']['errors'] == linux['unit']['failures'] == linux['unit']['skipped'] == 0
    assert linux['run_id'] == native['run_id'] == host['run_id']
    assert len(host['production_mutations']) == 5 and all(r['caught_by_assertion'] for r in host['production_mutations'])
    assert native['tests'] >= 39 and native['errors'] == native['failures'] == native['skipped'] == 0
    assert [r['name'] for r in linux['cases']] == ['atomic_batches', 'management_path', 'crash_matrix', 'service_recovery', 'queued_connection_and_response_loss', 'storage_faults', 'measurement']
    assert all(r['passed'] is True and 'evidence' in r for r in linux['cases'])
    atomic, network, crash, recovery, queued, storage, measured = [r['evidence'] for r in linux['cases']]
    assert atomic['unrelated_table_unchanged']
    assert atomic['nft_exec_lock_inherited']
    assert atomic['check_nonmutating'] and atomic['invalid_batch_atomic'] and atomic['invalid_batch_exit'] != 0
    assert network['old_connection']['old_confirm'] == 409 and network['fresh_access_restored']
    assert network['fresh_blocked_connect_errno'] != 0 and network['confirmed_survives_deadline']
    assert len(crash) == 8 and all(r['after_phase'] == 'ROLLED_BACK' and r['baseline_verified'] and r['idempotent'] for r in crash[:6])
    assert all(r['after_phase'] == 'DEGRADED' and r['unknown_preserved'] for r in crash[6:])
    assert all(recovery.values())
    assert queued['queued_before_apply_accepted_later']['confirm_status'] == 409
    assert queued['confirmed_response_lost'] and queued['committed_survived_restart']
    assert storage['verified_filesystem_bytes'] == 16 * 1024 * 1024 and storage['write_limit_bytes'] == 257 * 65536
    assert all(storage[k] for k in ('enospc_observed', 'reserve_released', 'baseline_restored', 'rollback_journal_verified', 'directory_budget_rejected', 'corrupt_journal_blocked', 'test_tmpfs_unmounted'))
    assert len(measured['trials']) == 10
    assert [r['index'] for r in measured['trials']] == list(range(10))
    for row in measured['trials']:
        assert row['before_policy'] != row['candidate_policy']
        assert row['phase'] == ('COMMITTED' if row['action'] == 'confirm' else 'ROLLED_BACK')
        assert all(row[k] > 0 for k in ('plan_ms', 'apply_ms', 'finalize_ms'))
    for key, column, action in [('plan', 'plan_ms', None), ('apply', 'apply_ms', None), ('confirm', 'finalize_ms', 'confirm'), ('cancel', 'finalize_ms', 'cancel')]:
        samples = [r[column] for r in measured['trials'] if action is None or r['action'] == action]
        assert measured[key] == {'n': len(samples), 'median_ms': statistics.median(samples), 'min_ms': min(samples), 'max_ms': max(samples), 'samples_ms': samples}
    assert measured['disk']['logical_bytes'] == sum(f['logical_bytes'] for f in measured['disk']['files'].values())
    assert measured['disk']['allocated_bytes'] == sum(f['allocated_bytes'] for f in measured['disk']['files'].values())
    assert measured['rss']['worker_high_water_bytes'] >= measured['rss']['initial_bytes'] > 0
    assert measured['rss']['worker_high_water_bytes'] >= measured['rss']['final_bytes'] > 0
    assert measured['disk']['logical_bytes'] > 0 and measured['disk']['allocated_bytes'] > 0
    assert linux['cleanup']['passed'] and not linux['cleanup']['remaining_processes'] and not linux['cleanup']['remaining_namespaces']
    assert linux['cleanup']['container_root_rules_unchanged'] and not linux['source_changed']
    assert host['container_removed'] and host['vm_final_state'] == 'Stopped' and not host['source_changed']
    assert host['container_exit']['ExitCode'] == 0 and not host['container_exit']['OOMKilled']
    assert all(s['exit_code'] == 0 and not s['timed_out'] for s in host['stages'])
