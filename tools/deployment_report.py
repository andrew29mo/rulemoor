"""Fail-closed deployment evidence checks and standalone HTML rendering."""
import copy
import math
import html
import json
from .evidence import fingerprint
from .deployment_guest import BASE, NEXT, NEW
from rulemoor.policy import expected

PHASES = ['setup', 'poisoned_journal', 'restart_limit', 'crash', 'held_writer', 'prepare_pending_boot', 'after_pending_boot', 'after_committed_boot', 'cleanup']

STAGES = ['vm-initial','vm-start','preflight','guest-prerequisites','wheel-build','snapshot-upload',
          'guest-setup','guest-poisoned_journal','guest-restart_limit','guest-crash','guest-held_writer','guest-prepare_pending_boot',
          'pending-vm-stop','pending-vm-start','guest-after_pending_boot',
          'committed-vm-stop','committed-vm-start','guest-after_committed_boot',
          'guest-cleanup','snapshot-remove','vm-final-stop','vm-final']
CONTROL_NAMES = ['boot-identity','missing-case','stale-kernel','missing-cleanup','timeout','source',
                 'missing-stage','wrong-package-origin','wrong-preboot-journal','stale-pending-generation',
                 'infinite-timing','missing-vm-interval','memory-identity','invalid-memory','poison-kernel-write','restart-still-running','failed-journal-changed','missing-limit-receipt']


def positive(value):
    assert type(value) in (int, float) and math.isfinite(value) and value > 0


def interval(clock, summary_seconds):
    assert clock['clock'] == 'monotonic_ns'
    assert type(clock['started_ns']) is int and type(clock['finished_ns']) is int
    assert 0 < clock['started_ns'] < clock['finished_ns']
    positive(summary_seconds)
    assert math.isclose(summary_seconds, (clock['finished_ns']-clock['started_ns'])/1e9, rel_tol=1e-10, abs_tol=1e-9)


def memory_sample(m):
    assert type(m['agent_rss_bytes']) is int and type(m['agent_vmhwm_bytes']) is int
    positive(m['agent_rss_bytes']); positive(m['agent_vmhwm_bytes'])
    assert m['agent_vmhwm_bytes'] >= m['agent_rss_bytes']
    assert type(m['service_cgroup_memory_current_bytes']) is int
    positive(m['service_cgroup_memory_current_bytes'])
    i = m['process_identity']
    assert type(i['pid']) is int and i['pid'] > 1 and type(i['start_ticks']) is int and i['start_ticks'] >= 0
    assert i['boot'] and m['main_pid_after'] == i['pid']
    assert m['invocation_id'] and m['invocation_id'] == m['invocation_id_after']
    assert m['process_namespace_inode'] > 0 and m['process_namespace_inode'] == m['target_namespace_inode']
    assert m['entrypoint'] == '/opt/rulemoor/venv/bin/rulemoor-agent' and m['cwd'] == '/'
    assert m['python_path_environment_clean'] is True and m['control_group'] == '/system.slice/rulemoor.service'
    assert 0 < m['sample_started_ns'] < m['sample_finished_ns']


def stale_trace(t, policy, require_confirmation):
    before, after, committed = t['pending_before'], t['pending_after'], t['committed']
    assert before == after and after['phase'] == 'AWAITING_CONFIRM'
    assert t['pending_kernel'] == expected(policy) == t['committed_kernel']
    assert committed['phase'] == 'COMMITTED' and committed['generation'] == before['generation']
    assert committed['op'] == before['op'] and committed['current'] == policy
    paths = (['confirm'] if require_confirmation else []) + ['cancel','apply']
    assert t['rejected_pending'] == t['rejected_committed'] == paths



def verify(value, source):
    assert value['passed'] is True and value['source'] == source
    assert value['source_sha256'] == fingerprint(source) and not value['source_changed']
    assert value['vm_initial_state'] == value['vm_final_state'] == 'Stopped'
    assert value['scope']['power_loss_tested'] is False
    assert value['scope']['reboot_method'] == 'Orderly Colima VM stop/start; pending agent stopped using SIGKILL'
    assert [r['name'] for r in value['cases']] == PHASES
    assert all(r['passed'] is True for r in value['cases'])
    assert not any(k in value for k in ('error','cleanup_error','vm_cleanup_error','verification_error'))
    assert [s['name'] for s in value['stages']] == STAGES
    assert value['stages'] and all(s['exit_code'] == 0 and not s['timed_out'] for s in value['stages'])
    for stage in value['stages']: positive(stage['seconds'])
    rows = {r['name']: r['evidence'] for r in value['cases']}
    setup = rows['setup']
    assert setup['pid1'] == 'systemd' and setup['installed_modules_match_source']
    assert setup['production_unit_sha256'] == source['deploy/rulemoor.service']
    pkg = setup['installed_package']
    assert pkg['origin'].startswith('/opt/rulemoor/venv/lib/python') and pkg['origin'].endswith('/site-packages/rulemoor')
    assert pkg['hashes'] == {k:v for k,v in source.items() if k.startswith('rulemoor/')}
    p = setup['unit_properties']
    assert p['Restart'] == 'on-failure' and p['KillMode'] == 'control-group' and p['NoNewPrivileges'] == 'yes'
    assert p['NetworkNamespacePath'] == '/run/netns/rm_deployment'
    poison, limited = rows['poisoned_journal'], rows['restart_limit']
    assert poison['diagnostic_phase']=='DEGRADED' and poison['original_snapshot_preserved'] and poison['mutations_rejected']
    assert poison['invocation_before']==poison['invocation_after']
    assert poison['restart_count_before']==poison['restart_count_after']
    assert poison['kernel_before']==poison['kernel_after_diagnostic']==expected(BASE)
    assert poison['fixture_only_reprovision_and_token_rotation'] and poison['production_auto_repair_claimed'] is False
    memory_sample(poison['memory'])
    assert limited['unit_limits']=={'Restart':'on-failure','RestartUSec':'1s','StartLimitIntervalUSec':'1min','StartLimitBurst':'5'}
    f, stable=limited['failed'],limited['stable']
    assert f['MainPID']==stable['MainPID']=='0' and f['ActiveState']==stable['ActiveState']=='failed'
    assert f['Result']==stable['Result'] and f['Result'] in ('exit-code','start-limit-hit') and f['NRestarts']==stable['NRestarts']
    assert limited['start_limit_receipts']
    for receipt in limited['start_limit_receipts']:
        assert receipt['MESSAGE']=='rulemoor.service: Start request repeated too quickly.' and receipt['UNIT']=='rulemoor.service'
        assert receipt['_BOOT_ID'].replace('-','')==setup['boot_id'].replace('-','')
        assert int(receipt['__MONOTONIC_TIMESTAMP'])*1000>=limited['failure_started_monotonic_ns']
    assert 1<=int(stable['NRestarts'])<=6
    interval(limited['observation_clock'],limited['observation_seconds']);assert limited['observation_seconds']>=2
    assert limited['journal_before_failure']==limited['journal_while_failed']
    assert limited['journal_while_failed']['phase']=='AWAITING_CONFIRM' and limited['kernel_while_failed']==expected(NEXT)
    assert limited['blocked_start_exit_code']!=0 and limited['local_cause_fixed_and_reset_started']
    assert limited['restored_kernel']==expected(BASE) and limited['new_generation']>limited['recovered_generation']>limited['old_generation']
    stale_trace(limited['stale_trace'],NEW,True);memory_sample(limited['memory'])
    assert limited['segmentation_fault_tested'] is False and limited['uninterruptible_io_tested'] is False
    crash = rows['crash']; held = rows['held_writer']; pending = rows['after_pending_boot']; committed = rows['after_committed_boot']
    assert all(row['stale_requests_rejected_during_new_pending'] for row in (crash, held, pending))
    assert crash['automatic_systemd_restart'] and crash['restart_count_after'] > crash['restart_count_before']
    assert crash['pending_baseline_restored'] and crash['stale_requests_rejected_after_new_commit']
    assert crash['new_generation'] > crash['recovered_generation'] > crash['old_generation']
    assert crash['restored_kernel'] == expected(BASE) and crash['kernel_after_stale'] == expected(NEW)
    c = crash['recovery_clock']
    assert c['clock'] == 'monotonic_ns'
    interval({'clock':c['clock'],'started_ns':c['kill_started_ns'],'finished_ns':c['tls_observed_ns']}, crash['kill_to_tls_ready_observed_ms']/1000)
    assert c['baseline_verified_ns'] >= c['tls_observed_ns']
    stale_trace(crash['stale_trace'], NEW, True)
    stale_trace(held['stale_trace'], BASE, False)
    stale_trace(pending['stale_trace'], NEW, True)
    durations = {x['name']:x['seconds'] for x in value['stages']}
    for prefix, guest in (('pending','guest-after_pending_boot'),('committed','guest-after_committed_boot')):
        seconds = value[prefix+'_vm_restart_control_seconds']
        interval(value[prefix+'_vm_restart_clock'], seconds)
        assert seconds >= sum(durations[k] for k in (prefix+'-vm-stop',prefix+'-vm-start',guest))
    assert held['test_only_fault_override'] and held['old_executor_retired'] and held['systemd_cgroup_restart_observed']
    assert held['late_release_did_not_overwrite_new_policy'] and held['stale_requests_rejected']
    assert held['old_executor_identity'] and held['old_executor_identity_after'] != held['old_executor_identity']
    assert held['new_generation'] > held['recovered_generation'] > held['old_generation']
    assert held['kernel_after_late_release'] == expected(BASE)
    prep = rows['prepare_pending_boot']
    assert prep['journal_pending_after_service_stop'] and prep['graceful_rollback_deliberately_bypassed'] and prep['unit_enabled']
    assert prep['kernel_before_shutdown'] == expected(NEXT)
    j = prep['journal_after_stop']
    assert j['phase'] == 'AWAITING_CONFIRM' and j['candidate'] == NEXT and j['current'] == j['baseline'] == BASE
    assert pending['journal_before_agent'] == j
    assert j['generation'] == prep['pending_generation'] and j['boot'] == pending['boot_id_before']
    j = committed['journal_before_agent']
    assert j['phase'] == 'COMMITTED' and j['current'] == NEW
    assert j['generation'] == pending['new_generation'] == committed['old_generation']
    assert j['boot'] == committed['boot_id_before']
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
        memory_sample(row['memory'])
    assert committed['memory_stage'] == 'committed_after_boot_before_foreign_policy_probe'
    assert setup['memory']['process_identity']['boot'] == crash['memory']['process_identity']['boot'] == setup['boot_id']
    assert pending['memory']['process_identity']['boot'] == pending['boot_id_after']
    assert committed['memory']['process_identity']['boot'] == committed['boot_id_after']


def negative_controls(value, source):
    rows=[]
    for name in CONTROL_NAMES:
        broken=copy.deepcopy(value)
        by_name={r['name']:r['evidence'] for r in broken['cases']}
        if name=='boot-identity':by_name['after_pending_boot']['boot_id_after']=by_name['after_pending_boot']['boot_id_before']
        elif name=='missing-case':broken['cases'].pop(2)
        elif name=='stale-kernel':by_name['after_pending_boot']['kernel_after_stale']=[]
        elif name=='missing-cleanup':broken['cases'][-1]['evidence']={}
        elif name=='timeout':broken['stages'][0]['timed_out']=True
        elif name=='source':broken['source']={}
        elif name=='missing-stage':broken['stages'].pop(10)
        elif name=='wrong-package-origin':by_name['setup']['installed_package']['origin']='/opt/rulemoor-validation/rulemoor'
        elif name=='wrong-preboot-journal':by_name['after_pending_boot']['journal_before_agent']['phase']='ROLLED_BACK'
        elif name=='stale-pending-generation':by_name['after_pending_boot']['stale_trace']['pending_after']['generation']+=1
        elif name=='infinite-timing':by_name['crash']['kill_to_tls_ready_observed_ms']=float('inf')
        elif name=='missing-vm-interval':del broken['pending_vm_restart_control_seconds']
        elif name=='memory-identity':by_name['crash']['memory']['main_pid_after']+=1
        elif name=='invalid-memory':by_name['crash']['memory']['agent_rss_bytes']=float('nan')
        elif name=='poison-kernel-write':by_name['poisoned_journal']['kernel_after_diagnostic']=[]
        elif name=='restart-still-running':by_name['restart_limit']['stable']['MainPID']='123'
        elif name=='missing-limit-receipt':by_name['restart_limit']['start_limit_receipts']=[]
        elif name=='failed-journal-changed':by_name['restart_limit']['journal_while_failed']['phase']='ROLLED_BACK'
        try:verify(broken,source)
        except (AssertionError,KeyError):rows.append({'name':name,'rejected':True})
        else:raise AssertionError('Verifier accepted '+name)
    return rows


def render(value):
    rows = ''.join('<tr><td>' + html.escape(r['name']) + '</td><td>' + ('PASS' if r['passed'] else 'FAIL') + '</td></tr>' for r in value.get('cases', []))
    observations = ''
    by_name = {r['name']: r.get('evidence', {}) for r in value.get('cases', []) if r['passed']}
    if 'poisoned_journal' in by_name:
        observations += '<p>Malformed snapshot: DEGRADED; original data and kernel policy preserved. Test-only local reprovision is not automatic repair.</p>'
    if 'restart_limit' in by_name:
        limited = by_name['restart_limit']
        observations += '<p>Persistent missing-key startup failure: ' + html.escape(limited['failed']['Result']) + '; pending candidate remains installed while stopped. No further restart observed for ' + f"{limited['observation_seconds']:.2f} s" + '. Baseline recovery required local cause repair and explicit reset/start. Native segmentation fault and uninterruptible I/O were not tested.</p>'
    if 'crash' in by_name:
        observations += '<p>Observed Agent SIGKILL to fresh TLS ready with restored baseline: ' + f"{by_name['crash']['kill_to_tls_ready_observed_ms']:.1f} ms" + ' (one trial; includes client probes and systemctl overhead).</p>'
    if 'pending_vm_restart_control_seconds' in value:
        committed_seconds = value.get('committed_vm_restart_control_seconds')
        committed_text = f'{committed_seconds:.2f} s' if committed_seconds is not None else 'not observed'
        observations += '<p>Orderly VM stop/start plus post-boot validation: ' + f"{value['pending_vm_restart_control_seconds']:.2f} s" + ' pending / ' + committed_text + ' committed (each observed case one trial; includes VM control, SSH and assertions, not boot-time bounds).</p>'
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
