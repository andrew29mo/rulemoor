"""Fail-closed deployment evidence checks and standalone HTML rendering."""
import html
import json
from .evidence import fingerprint
from .deployment_guest import BASE, NEXT, NEW
from rulemoor.policy import expected

PHASES = ['setup', 'crash', 'held_writer', 'prepare_pending_boot', 'after_pending_boot', 'after_committed_boot', 'cleanup']


def verify(value, source):
    assert value['passed'] is True and value['source'] == source
    assert value['source_sha256'] == fingerprint(source) and not value['source_changed']
    assert value['vm_initial_state'] == value['vm_final_state'] == 'Stopped'
    assert value['scope']['power_loss_tested'] is False
    assert value['scope']['reboot_method'] == 'Orderly Colima VM stop/start; pending agent stopped using SIGKILL'
    assert [r['name'] for r in value['cases']] == PHASES
    assert all(r['passed'] is True for r in value['cases'])
    assert value['stages'] and all(s['exit_code'] == 0 and not s['timed_out'] for s in value['stages'])
    rows = {r['name']: r['evidence'] for r in value['cases']}
    setup = rows['setup']
    assert setup['pid1'] == 'systemd' and setup['installed_modules_match_source']
    assert setup['production_unit_sha256'] == source['deploy/rulemoor.service']
    p = setup['unit_properties']
    assert p['Restart'] == 'on-failure' and p['KillMode'] == 'control-group' and p['NoNewPrivileges'] == 'yes'
    assert p['NetworkNamespacePath'] == '/run/netns/rm_deployment'
    crash = rows['crash']; held = rows['held_writer']; pending = rows['after_pending_boot']; committed = rows['after_committed_boot']
    assert all(row['stale_requests_rejected_during_new_pending'] for row in (crash, held, pending))
    assert crash['automatic_systemd_restart'] and crash['restart_count_after'] > crash['restart_count_before']
    assert crash['pending_baseline_restored'] and crash['stale_requests_rejected_after_new_commit']
    assert crash['new_generation'] > crash['recovered_generation'] > crash['old_generation']
    assert crash['restored_kernel'] == expected(BASE) and crash['kernel_after_stale'] == expected(NEW)
    assert crash['kill_to_tls_ready_observed_ms'] > 0
    assert held['test_only_fault_override'] and held['old_executor_retired'] and held['systemd_cgroup_restart_observed']
    assert held['late_release_did_not_overwrite_new_policy'] and held['stale_requests_rejected']
    assert held['old_executor_identity'] and held['old_executor_identity_after'] != held['old_executor_identity']
    assert held['new_generation'] > held['recovered_generation'] > held['old_generation']
    assert held['kernel_after_late_release'] == expected(BASE)
    prep = rows['prepare_pending_boot']
    assert prep['journal_pending_after_service_stop'] and prep['graceful_rollback_deliberately_bypassed'] and prep['unit_enabled']
    assert prep['kernel_before_shutdown'] == expected(NEXT)
    for row in (pending, committed):
        assert row['boot_id_before'] != row['boot_id_after'] and row['pre_agent_table_absent']
        assert row['recovered_generation'] > row['old_generation'] and row['generation_advanced']
    assert setup['boot_id'] == prep['boot_id'] == pending['boot_id_before']
    assert pending['boot_id_after'] == committed['boot_id_before']
    assert prep['pending_generation'] == pending['old_generation']
    assert pending['pending_baseline_restored'] and pending['stale_requests_rejected_after_new_commit']
    assert pending['new_generation'] > pending['recovered_generation']
    assert pending['restored_kernel'] == expected(BASE) and pending['kernel_after_stale'] == expected(NEW)
    assert committed['committed_policy_restored'] and committed['old_base_rejected']
    assert committed['restored_kernel'] == expected(NEW)
    assert committed['same_boot_foreign_policy_preserved'] and committed['foreign_kernel'] == committed['kernel_after_restart']
    assert committed['foreign_kernel'] != expected(NEW)
    assert set(rows['cleanup']) == {'namespace_removed', 'service_stopped_and_removed', 'credentials_and_state_removed', 'vm_root_firewall_unchanged'}
    assert all(x is True for x in rows['cleanup'].values()) and value['source_snapshot_removed']
    for row in (setup, crash, pending, committed):
        m = row['memory']; assert m['agent_vmhwm_bytes'] >= m['agent_rss_bytes'] > 0
        assert m['service_cgroup_memory_current_bytes'] > 0


def render(value):
    rows = ''.join('<tr><td>' + html.escape(r['name']) + '</td><td>' + ('PASS' if r['passed'] else 'FAIL') + '</td></tr>' for r in value.get('cases', []))
    observations = ''
    by_name = {r['name']: r.get('evidence', {}) for r in value.get('cases', []) if r['passed']}
    if 'crash' in by_name:
        observations += '<p>Observed Agent SIGKILL to fresh TLS ready with restored baseline: ' + f"{by_name['crash']['kill_to_tls_ready_observed_ms']:.1f} ms" + ' (one trial; includes client probes and systemctl overhead).</p>'
    if 'pending_vm_restart_control_seconds' in value:
        observations += '<p>Orderly VM stop/start plus post-boot validation: ' + f"{value['pending_vm_restart_control_seconds']:.2f} s" + ' pending / ' + f"{value.get('committed_vm_restart_control_seconds', 0):.2f} s" + ' committed (each one trial; includes VM control, SSH and assertions, not boot-time bounds).</p>'
    if by_name:
        observations += '<table><tr><th>Stage</th><th>Agent VmHWM MiB</th><th>Service cgroup MiB</th></tr>'
        for name,row in by_name.items():
            if 'memory' in row:
                m=row['memory']; observations += f'<tr><td>{html.escape(name)}</td><td>{m["agent_vmhwm_bytes"]/1048576:.2f}</td><td>{m["service_cgroup_memory_current_bytes"]/1048576:.2f}</td></tr>'
        observations += '</table>'
    return '''<!doctype html><html lang="en"><meta charset="utf-8"><title>Rulemoor systemd and VM recovery</title>
<style>body{font:16px system-ui;max-width:1000px;margin:2rem auto;padding:1rem}pre{white-space:pre-wrap;overflow-wrap:anywhere}td{padding:.5rem;border:1px solid #ccc}</style>
<h1>Rulemoor deployment validation: ''' + ('PASS' if value.get('passed') else 'FAIL') + '''</h1>
<p>Actual systemd in an isolated Linux VM. Firewall writes confined to a disposable network namespace.
VM reboots are orderly stop/start, not power-loss tests. Timings are observations including probe/control overhead, not SLA bounds.
Daemon/cgroup memory is distinct from total VM memory. No native macOS deployment claim.</p><table>''' + rows + '</table>' + observations + '<pre>' + html.escape(json.dumps(value, indent=2)) + '</pre></html>'
