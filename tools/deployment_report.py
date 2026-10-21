"""Fail-closed deployment evidence checks and standalone HTML rendering."""
import copy
import math
import html
import json
from .evidence import fingerprint
from .deployment_guest import BASE, NEXT, NEW
from rulemoor.policy import expected

PHASES = ['setup', 'management_diagnostics', 'dual_stack', 'poisoned_journal', 'restart_limit', 'crash', 'held_writer', 'prepare_pending_boot', 'after_pending_boot', 'after_committed_boot', 'prepare_dual_boot', 'after_dual_boot', 'dual_held_executor', 'cleanup']

STAGES = ['vm-initial','vm-start','preflight','guest-prerequisites','wheel-build','snapshot-upload',
          'guest-setup','guest-management_diagnostics','guest-dual_stack','guest-poisoned_journal','guest-restart_limit','guest-crash','guest-held_writer','guest-prepare_pending_boot',
          'pending-vm-stop','pending-vm-start','guest-after_pending_boot',
          'committed-vm-stop','committed-vm-start','guest-after_committed_boot',
          'guest-prepare_dual_boot','dual-pending-vm-stop','dual-pending-vm-start','guest-after_dual_boot','guest-dual_held_executor',
          'guest-cleanup','snapshot-remove','vm-final-stop','vm-final']
CONTROL_NAMES = ['boot-identity','missing-case','stale-kernel','missing-cleanup','timeout','source',
                 'missing-stage','wrong-package-origin','wrong-preboot-journal','stale-pending-generation',
                 'infinite-timing','missing-vm-interval','memory-identity','invalid-memory','poison-kernel-write','restart-still-running','failed-journal-changed','missing-limit-receipt','future-limit-receipt','unrelated-startup-memory','wrong-poison-invocation','guard-admitted','foreign-rule-modified','uncertainty-hidden','old-confirmation-admitted','false-tcp-observation',
                 'connection-refused','missing-tcp-recovery','changed-tcp-listener','configuration-recovery-skipped','dual-v4-masks-v6','dual-wrong-rollback','dual-wrong-transport','dual-foreign-modified','dual-missing-timing','dual-partial-crash-not-restored','dual-missing-cleanup',
                 'dual-invalid-restart-identity','dual-failure-wrong-boot','dual-unrelated-success-operation','dual-success-wrong-boot','dual-skipped-generation','dual-stale-kernel-modified','dual-reboot-pre-agent-journal','dual-reboot-missing-family','dual-reboot-fresh-family','dual-reboot-wrong-boot','dual-orphan-did-not-survive','dual-orphan-not-retired','dual-orphan-overwrites-one-family','dual-orphan-missing-release-clock']


def positive(value):
    assert type(value) in (int, float) and math.isfinite(value) and value > 0


def process_identity(identity, boot):
    assert type(boot) is str and boot
    assert type(identity['pid']) is int and identity['pid']>1
    assert type(identity['start_ticks']) is int and identity['start_ticks']>=0
    assert identity['boot']==boot


def dual_projection_identity(projection, boot):
    assert type(boot) is str and boot
    assert projection['boot']==boot
    assert type(projection['generation']) is int and projection['generation']>=0


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


def rate_limit_receipts(limited, boot):
    began=limited['failure_started_monotonic_ns']
    observed=limited['observation_clock']['started_ns']
    assert type(began) is int and type(observed) is int and 0<began<observed
    assert isinstance(limited['start_limit_receipts'],list) and limited['start_limit_receipts']
    for receipt in limited['start_limit_receipts']:
        assert receipt['MESSAGE']=='rulemoor.service: Start request repeated too quickly.' and receipt['UNIT']=='rulemoor.service'
        assert receipt['_BOOT_ID'].replace('-','')==boot.replace('-','')
        raw=receipt['__MONOTONIC_TIMESTAMP']
        assert isinstance(raw,str) and raw.isascii() and raw.isdecimal()
        assert began<=int(raw)*1000<=observed


def stale_trace(t, policy, require_confirmation):
    before, after, committed = t['pending_before'], t['pending_after'], t['committed']
    assert before == after and after['phase'] == 'AWAITING_CONFIRM'
    assert t['pending_kernel'] == expected(policy) == t['committed_kernel']
    assert committed['phase'] == 'COMMITTED' and committed['generation'] == before['generation']
    assert committed['op'] == before['op'] and committed['current'] == policy
    paths = (['confirm'] if require_confirmation else []) + ['cancel','apply']
    assert t['rejected_pending'] == t['rejected_committed'] == paths



def tcp_probe_evidence(probe, listener_identity, connected):
    assert probe['connected'] is connected and type(probe['errno']) is int
    assert probe['errno'] in ((0,) if connected else (11,110))
    for point in ('listener_before','listener_after'):
        assert probe[point]['poll'] is None and probe[point]['identity']==listener_identity


def tcp_drop_cycle(before, drop, recovered, listener_identity):
    tcp_probe_evidence(before,listener_identity,True)
    tcp_probe_evidence(drop,listener_identity,False)
    tcp_probe_evidence(recovered,listener_identity,True)


def configuration_recovery_evidence(cases, boot):
    assert [case['kind'] for case in cases]==['missing','null']
    for case in cases:
        pending=case['pending_journal'];recovered=case['recovered_journal']
        assert pending==case['pending_journal_before_kill'] and pending['phase']=='AWAITING_CONFIRM'
        assert pending['candidate']==NEXT and pending['current']==pending['baseline']==BASE
        assert case['pending_kernel']==case['pending_kernel_before_kill']==expected(NEXT)
        before,at_kill=case['unit_before_kill'],case['unit_at_kill']
        assert int(before['MainPID'])>1 and before['MainPID']==at_kill['MainPID']
        assert before['InvocationID'] and before['InvocationID']==at_kill['InvocationID']
        assert before['ActiveState']==at_kill['ActiveState']=='active' and case['signal']=='SIGKILL'
        assert recovered['phase']=='ROLLED_BACK' and recovered['generation']>pending['generation']
        assert recovered['op']==pending['op'] and recovered['current']==recovered['baseline']==BASE
        assert recovered['boot']==pending['boot']==case['boot_before']==case['boot_after']==boot
        assert case['recovered_kernel']==expected(BASE) and case['ready_after_repair']==recovered
        failed=case['failed_unit']
        assert failed['ActiveState']=='failed' and failed['MainPID']=='0' and failed['Result'] in ('exit-code','start-limit-hit')
        assert 1<=int(failed['NRestarts'])<=6
        rate_limit_receipts({**case,'observation_clock':{'started_ns':case['failure_observed_monotonic_ns']}},boot)


def preflight_evidence(row, boot):
    configuration_recovery_evidence(row['configuration_recovery_cases'],boot)
    assert row['configuration']=='explicit-local-ipv4-tcp-ports' and row['supported_configuration_override']
    for diag in [row['denied_plan'],row['ordered_plan'],row['unsupported_condition'],*[r['diagnostics'] for r in row['foreign_priority_cases']]]:
        assert diag['configuration']=='configured' and diag['fresh_connection_confirmation_required'] is True and diag['reachability_verified'] is False
        assert diag['schema']==1 and [p['port'] for p in diag['own_policy']['paths']]==[18443,59999]
    assert row['denied_plan']['own_policy']['status']=='blocked'
    assert row['ordered_plan']['own_policy']['status']=='allowed'
    assert row['state_before_denial']==row['state_after_denial']
    assert row['state_before_denial']['phase']=='COMMITTED'
    assert row['own_kernel_before']==row['own_kernel_after_denial']==expected(BASE)
    listener=row['listener_identity']
    assert type(listener['pid']) is int and listener['pid']>1
    assert type(listener['start_ticks']) is int and listener['start_ticks']>=0 and listener['boot']==boot
    tcp_probe_evidence(row['tcp_probe_before_foreign_drop'],listener,True)
    assert [r['priority'] for r in row['foreign_priority_cases']]==[-100,10]
    for case in row['foreign_priority_cases']:
        assert case['foreign_before']==case['foreign_after'] and case['foreign_before']
        chain=next(r['chain'] for r in case['foreign_before'] if 'chain' in r)
        assert chain['prio']==case['priority'] and chain['table']=='rm_preflight_external' and chain['hook']=='input'
        rule=next(r['rule'] for r in case['foreign_before'] if 'rule' in r)
        assert rule['expr']==[{'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':59999}},{'drop':None}]
        assert case['diagnostics']['external']['status']=='blocked'
        found=next(c for c in case['diagnostics']['external']['input_chains'] if c['table']=='rm_preflight_external')
        assert found['priority']==case['priority'] and [p['status'] for p in found['paths']]==['no_observed_input_conflict','blocked']
        tcp_drop_cycle(case['tcp_probe_before'],case['tcp_probe'],case['tcp_probe_recovered'],listener)
        interval(case['plan_clock'],case['plan_observed_ms']/1000)
    assert row['unsupported_condition']['external']['status']=='risk'
    assert row['foreign_before_allowed_apply']==row['foreign_after_allowed_apply'] and row['foreign_before_allowed_apply']
    tcp_drop_cycle(row['tcp_probe_before_unknown_condition'],row['tcp_probe_after_unknown_condition'],row['tcp_probe_recovered_unknown_condition'],listener)
    c=row['confirmation'];assert c['old_status']==200 and c['old_confirm']==409 and c['fresh_phase']=='COMMITTED'
    s=row['state_after_allowed_apply'];assert s['phase']=='COMMITTED' and s['generation']==c['generation']>row['state_before_denial']['generation']
    assert row['own_kernel_after_allowed_apply']==expected(NEXT)
    memory_sample(row['memory']);assert row['memory']['process_identity']['boot']==boot


def dual_evidence(row, boot):
    assert type(boot) is str and boot
    # Bind every observed journal/status projection to this run, including
    # otherwise internally consistent receipts copied from another boot.
    projections = [*row['initial'].values(), row['failure']['pending'],
                   *row['failure']['partial'], row['restored'],
                   *row['fresh_after_rollback'].values(),
                   row['success']['ipv4_partial'], row['success']['ipv6_committed'],
                   row['partial_before_kill'], row['recovered'],
                   row['stale']['before'], row['stale']['after']]
    for projection in projections:
        dual_projection_identity(projection,boot)
    for key in ('same_service_identity_during_timeout','identity_after_timeout','identity_after_restart'):
        process_identity(row[key],boot)
    assert row['mode']=='fresh-dual-no-migration'
    assert row['cleanup']=={'client_namespace_removed':True,'veth_removed':True,'legacy_state_and_unit_restored':True}
    assert type(row['legacy_adoption_exit_code']) is int and row['legacy_adoption_exit_code']!=0
    assert row['legacy_table_after_refused_init']==expected(BASE)
    baseline,blocked,candidate,newer=(row[k] for k in ('baseline','blocked_candidate','candidate','newer'))
    assert all(set(p)=={'ipv4','ipv6'} for p in (baseline,blocked,candidate,newer))
    assert blocked['ipv6']=={'default':'drop','rules':[]}
    assert row['initial']['ipv4']==row['initial']['ipv6']
    assert row['initial']['ipv4']['phase']=='COMMITTED' and row['initial']['ipv4']['current']==baseline
    initial=row['initial']['ipv4']
    assert initial['op']=='initial' and initial['generation']==0 and initial['candidate'] is None
    assert row['initial_kernel']==row['kernel_after_atomic_rejection']==expected(baseline)
    assert type(row['atomic_rejection_exit_code']) is int and row['atomic_rejection_exit_code']!=0
    f=row['failure'];pending=f['pending']
    assert pending['op']=='dual-v6-blocked' and pending['generation']==initial['generation']+1
    assert pending['phase']=='AWAITING_CONFIRM' and pending['confirmed_families']==[]
    assert pending['candidate']==blocked and pending['baseline']==pending['current']==baseline
    assert f['old_confirmation_status']=={'ipv4':409,'ipv6':409} and f['spoof_rejected'] is True
    assert type(f['ipv6_connect_errno']) is int and f['ipv6_connect_errno'] in (11,110)
    assert len(f['partial'])==2 and f['partial'][0]==f['partial'][1]
    partial=f['partial'][0]
    assert partial=={**pending,'confirmed_families':['ipv4']} and partial['phase']=='AWAITING_CONFIRM'
    assert row['pending_kernel']==expected(blocked)
    restored=row['restored']
    assert restored['phase']=='ROLLED_BACK' and restored['current']==restored['baseline']==baseline
    assert restored['op']==pending['op'] and restored['generation']==pending['generation']
    assert restored=={**partial,'phase':'ROLLED_BACK'}
    assert row['restored_kernel']==expected(baseline)
    assert row['fresh_after_rollback']['ipv4']==row['fresh_after_rollback']['ipv6']==restored
    c=row['rollback_clock'];assert c['clock']=='CLOCK_BOOTTIME' and c['deadline']==f['deadline']
    for key in ('deadline','rollback_started_at','rollback_completed_at','observed_at'):positive(c[key])
    assert c['deadline']<=c['rollback_started_at']<=c['rollback_completed_at']<=c['observed_at']
    i=row['same_service_identity_during_timeout']
    assert i==row['identity_after_timeout'] and i['boot']==boot and type(i['pid']) is int and i['pid']>1
    success=row['success'];first,last=success['ipv4_partial'],success['ipv6_committed']
    assert first['op']=='dual-both-success' and first['generation']==restored['generation']+1
    assert first['phase']=='AWAITING_CONFIRM' and first['confirmed_families']==['ipv4']
    assert last=={**first,'phase':'COMMITTED','confirmed_families':['ipv4','ipv6'],'current':candidate}
    assert first['candidate']==last['candidate']==candidate and first['baseline']==first['current']==baseline
    assert first['generation']>restored['generation'] and row['committed_kernel']==expected(candidate)
    c=success['confirmation_clock'];assert c['clock']=='monotonic_ns' and type(c['partial_ns']) is int
    interval({'clock':c['clock'],'started_ns':c['started_ns'],'finished_ns':c['partial_ns']},success['partial_ms']/1000)
    interval({'clock':c['clock'],'started_ns':c['partial_ns'],'finished_ns':c['finished_ns']},success['commit_ms']/1000)
    assert '2001:db8:44::2' in row['ipv6_neighbour_observation'] and 'lladdr' in row['ipv6_neighbour_observation']
    memory_sample(row['memory']);assert row['memory']['process_identity']==i
    partial=row['partial_before_kill'];recovered=row['recovered']
    assert partial['op']=='dual-partial-crash' and partial['generation']==last['generation']+1
    assert partial['phase']=='AWAITING_CONFIRM' and partial['confirmed_families']==['ipv4']
    assert partial['current']==partial['baseline']==candidate and partial['candidate']==baseline
    assert row['kernel_before_kill']==expected(baseline) and row['signal']=='SIGKILL'
    assert recovered['phase']=='ROLLED_BACK' and recovered['current']==candidate
    assert recovered['op']==partial['op'] and recovered['generation']>partial['generation']
    assert recovered=={**partial,'phase':'ROLLED_BACK','generation':partial['generation']+1}
    assert recovered['boot']==partial['boot']==boot
    assert row['recovered_kernel']==expected(candidate)
    assert row['identity_after_restart']!=i and row['identity_after_restart']['boot']==boot
    assert row['identity_after_restart']['start_ticks']>=i['start_ticks']
    stale=row['stale'];assert stale['rejected']==['/confirm','/cancel','/apply']
    assert stale['before']['op']=='dual-newer' and stale['before']['generation']==recovered['generation']+1
    assert stale['before']['phase']=='AWAITING_CONFIRM' and stale['before']['generation']>recovered['generation']
    assert stale['before']['candidate']==newer and stale['before']['current']==stale['before']['baseline']==candidate
    assert stale['before']['confirmed_families']==[]
    assert [observation['path'] for observation in stale['observations']]==stale['rejected']
    for observation in stale['observations']:
        assert type(observation['status']) is int and observation['status']==409
        assert observation['before']==observation['after']==stale['before']
        assert observation['kernel_before']==observation['kernel_after']==expected(newer)
    assert stale['after']=={**stale['before'],'phase':'COMMITTED','current':newer,'confirmed_families':['ipv4','ipv6']}
    assert row['kernel_after_stale']==expected(newer)
    assert len(row['foreign_before'])==2 and row['foreign_before']==row['foreign_after']
    for family,raw in zip(('ip','ip6'),row['foreign_before']):
        assert any(r.get('table',{}).get('name')=='rm_dual_foreign' and r['table']['family']==family for r in raw)


def recovery_stale_observations(observations, paths, state, policy):
    assert [r['path'] for r in observations]==list(paths)
    for row in observations:
        assert type(row['status']) is int and row['status']==409
        assert row['before']==row['after']==state
        assert row['kernel_before']==row['kernel_after']==expected(policy)


def dual_boot_recovery(prep, row):
    from .dual_recovery import INITIAL, BASELINE, PENDING, SUCCESSOR
    old_boot,new_boot=row['boot_id_before'],row['boot_id_after']
    assert old_boot==prep['boot_id'] and old_boot!=new_boot and type(new_boot) is str and new_boot
    baseline=prep['committed_baseline'];pending=prep['pending_before_stop']
    for s in (baseline,pending,prep['pending_after_stop']):dual_projection_identity(s,old_boot)
    assert baseline['op']=='dual-recovery-baseline' and baseline['phase']=='COMMITTED'
    assert baseline['generation']==1 and baseline['current']==baseline['candidate']==BASELINE and baseline['baseline']==INITIAL and baseline['confirmed_families']==['ipv4','ipv6']
    assert prep['baseline_kernel']==expected(BASELINE)
    assert pending['op']=='dual-pending-before-boot' and pending['generation']==baseline['generation']+1
    assert pending['phase']=='AWAITING_CONFIRM' and pending['confirmed_families']==['ipv4']
    assert pending['current']==pending['baseline']==BASELINE and pending['candidate']==PENDING
    assert prep['pending_after_stop']==pending
    assert prep['kernel_before_stop']==prep['kernel_after_stop']==expected(PENDING)
    assert prep['unit_enabled'] is True and prep['unit_after_stop']['MainPID']=='0'
    assert prep['unit_after_stop']['KillMode']=='control-group'
    assert prep['stop_method']=='SIGKILL with Restart=no; no graceful rollback'
    assert row['journal_before_agent']==pending and row['tables_before_agent']=={'ip':None,'ip6':None}
    restored=row['restored'];dual_projection_identity(restored,new_boot)
    assert restored=={**pending,'phase':'ROLLED_BACK','generation':pending['generation']+1,'boot':new_boot}
    assert row['restored_kernel']==expected(BASELINE)
    assert row['fresh_tls']=={'ipv4':restored,'ipv6':restored}
    successor=row['successor_pending'];committed=row['successor_committed']
    for s in (successor,committed):dual_projection_identity(s,new_boot)
    assert successor=={**restored,'phase':'AWAITING_CONFIRM','generation':restored['generation']+1,
                         'op':'dual-after-boot-successor','candidate':SUCCESSOR,'confirmed_families':[]}
    recovery_stale_observations(row['stale_observations'],('/confirm','/cancel','/apply'),successor,SUCCESSOR)
    assert committed=={**successor,'phase':'COMMITTED','current':SUCCESSOR,'confirmed_families':['ipv4','ipv6']}
    assert row['committed_kernel']==expected(SUCCESSOR)
    memory_sample(row['memory']);assert row['memory']['process_identity']['boot']==new_boot


def dual_orphan_recovery(row, boot, baseline):
    from .dual_recovery import SUCCESSOR, LATE, FINAL
    assert row['baseline']==baseline and baseline['current']==SUCCESSOR
    pending=row['pending'];restored=row['restored']
    for s in (pending,restored,row['successor_pending'],row['successor_committed']):dual_projection_identity(s,boot)
    assert pending=={**baseline,'phase':'APPLYING','generation':baseline['generation']+1,
                       'op':'dual-held-orphan','current':SUCCESSOR,'baseline':SUCCESSOR,'candidate':LATE,'confirmed_families':[]}
    old=row['old_executor_identity'];agent=row['held_agent_identity']
    process_identity(old,boot);process_identity(agent,boot);assert old!=agent
    assert row['after_agent_kill_identity']==old and row['writer_lock_held_before_recovery'] is True
    cgroups=row['old_executor_cgroup']
    assert isinstance(cgroups,list) and cgroups and all(isinstance(c,str) and '/system.slice/rulemoor.service' not in c for c in cgroups)
    assert row['kernel_before_recovery']==expected(SUCCESSOR)
    assert restored=={**pending,'phase':'ROLLED_BACK','generation':pending['generation']+1}
    assert row['restored_kernel']==expected(SUCCESSOR) and row['writer_lock_free_after_recovery'] is True
    for name in ('identity_after_recovery','identity_before_release','identity_after_release'):
        value=row[name]
        if value is not None:process_identity(value,boot)
        assert value!=old
    new=row['successor_pending'];committed=row['successor_committed']
    assert new=={**restored,'phase':'AWAITING_CONFIRM','generation':restored['generation']+1,
                   'op':'dual-after-orphan-new','candidate':FINAL,'confirmed_families':[]}
    assert committed=={**new,'phase':'COMMITTED','current':FINAL,'confirmed_families':['ipv4','ipv6']}
    recovery_stale_observations(row['pending_stale_observations'],('/cancel','/apply'),new,FINAL)
    recovery_stale_observations(row['committed_stale_observations'],('/cancel','/apply'),committed,FINAL)
    assert row['journal_before_release']==row['journal_after_release']==committed
    assert row['kernel_before_release']==row['kernel_after_release']==expected(FINAL)
    interval(row['release_clock'],row['release_observation_seconds']);assert row['release_observation_seconds']>=2
    memory_sample(row['memory']);assert row['memory']['process_identity']['boot']==boot
    assert row['memory']['process_identity'] not in (old,agent)
    for family in ('ipv4','ipv6'):
        from rulemoor.policy import digest
        assert len({digest(p[family]) for p in (SUCCESSOR,LATE,FINAL)})==3


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
    preflight_evidence(rows['management_diagnostics'],setup['boot_id'])
    dual_evidence(rows['dual_stack'],setup['boot_id'])
    poison, limited = rows['poisoned_journal'], rows['restart_limit']
    assert poison['diagnostic_phase']=='DEGRADED' and poison['original_snapshot_preserved'] and poison['mutations_rejected']
    assert poison['invocation_before']==poison['invocation_after']
    assert poison['restart_count_before']==poison['restart_count_after']
    assert poison['kernel_before']==poison['kernel_after_diagnostic']==expected(BASE)
    assert poison['fixture_only_reprovision_and_token_rotation'] and poison['production_auto_repair_claimed'] is False
    memory_sample(poison['memory'])
    assert poison['memory']['process_identity']['boot']==setup['boot_id']
    assert poison['memory']['invocation_id']==poison['invocation_after']
    assert limited['unit_limits']=={'Restart':'on-failure','RestartUSec':'1s','StartLimitIntervalUSec':'1min','StartLimitBurst':'5'}
    f, stable=limited['failed'],limited['stable']
    assert f['MainPID']==stable['MainPID']=='0' and f['ActiveState']==stable['ActiveState']=='failed'
    assert f['Result']==stable['Result'] and f['Result'] in ('exit-code','start-limit-hit') and f['NRestarts']==stable['NRestarts']
    rate_limit_receipts(limited,setup['boot_id'])
    assert 1<=int(stable['NRestarts'])<=6
    interval(limited['observation_clock'],limited['observation_seconds']);assert limited['observation_seconds']>=2
    assert limited['journal_before_failure']==limited['journal_while_failed']
    assert limited['journal_while_failed']['phase']=='AWAITING_CONFIRM' and limited['kernel_while_failed']==expected(NEXT)
    assert limited['blocked_start_exit_code']!=0 and limited['local_cause_fixed_and_reset_started']
    assert limited['restored_kernel']==expected(BASE) and limited['new_generation']>limited['recovered_generation']>limited['old_generation']
    stale_trace(limited['stale_trace'],NEW,True);memory_sample(limited['memory'])
    assert limited['memory']['process_identity']['boot']==setup['boot_id']
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
    dual_boot_recovery(rows['prepare_dual_boot'],rows['after_dual_boot'])
    assert rows['prepare_dual_boot']['boot_id']==committed['boot_id_after']
    dual_orphan_recovery(rows['dual_held_executor'],rows['after_dual_boot']['boot_id_after'],rows['after_dual_boot']['successor_committed'])
    durations = {x['name']:x['seconds'] for x in value['stages']}
    for prefix, guest in (('pending','guest-after_pending_boot'),('committed','guest-after_committed_boot'),('dual_pending','guest-after_dual_boot')):
        seconds = value[prefix+'_vm_restart_control_seconds']
        interval(value[prefix+'_vm_restart_clock'], seconds)
        assert seconds >= sum(durations[k] for k in (prefix.replace('_','-')+'-vm-stop',prefix.replace('_','-')+'-vm-start',guest))
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
    assert set(rows['cleanup']) == {'namespace_removed', 'service_stopped_and_removed', 'credentials_and_state_removed', 'vm_root_firewall_unchanged','dual_client_namespace_removed'}
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
        elif name=='future-limit-receipt':by_name['restart_limit']['start_limit_receipts'][0]['__MONOTONIC_TIMESTAMP']=str(10**30)
        elif name=='unrelated-startup-memory':by_name['restart_limit']['memory']['process_identity']['boot']='other-boot'
        elif name=='wrong-poison-invocation':by_name['poisoned_journal']['memory']['invocation_id']=by_name['poisoned_journal']['memory']['invocation_id_after']='other-invocation'
        elif name=='guard-admitted':by_name['management_diagnostics']['denied_plan']['own_policy']['status']='allowed'
        elif name=='foreign-rule-modified':by_name['management_diagnostics']['foreign_priority_cases'][0]['foreign_after']=[]
        elif name=='uncertainty-hidden':by_name['management_diagnostics']['unsupported_condition']['external']['status']='no_observed_input_conflict'
        elif name=='old-confirmation-admitted':by_name['management_diagnostics']['confirmation']['old_confirm']=200
        elif name=='false-tcp-observation':by_name['management_diagnostics']['foreign_priority_cases'][0]['tcp_probe']['connected']=True
        elif name=='connection-refused':by_name['management_diagnostics']['foreign_priority_cases'][0]['tcp_probe']['errno']=111
        elif name=='missing-tcp-recovery':del by_name['management_diagnostics']['foreign_priority_cases'][0]['tcp_probe_recovered']
        elif name=='changed-tcp-listener':by_name['management_diagnostics']['foreign_priority_cases'][0]['tcp_probe_recovered']['listener_after']['identity']['start_ticks']+=1
        elif name=='configuration-recovery-skipped':by_name['management_diagnostics']['configuration_recovery_cases'][0]['recovered_journal']['phase']='AWAITING_CONFIRM'
        elif name=='dual-missing-cleanup':by_name['dual_stack']['cleanup']={}
        elif name=='dual-v4-masks-v6':by_name['dual_stack']['failure']['partial'][0]['phase']='COMMITTED'
        elif name=='dual-wrong-rollback':by_name['dual_stack']['restored_kernel']=by_name['dual_stack']['pending_kernel']
        elif name=='dual-wrong-transport':by_name['dual_stack']['success']['ipv4_partial']['confirmed_families']=['ipv6']
        elif name=='dual-foreign-modified':by_name['dual_stack']['foreign_after']=[]
        elif name=='dual-missing-timing':del by_name['dual_stack']['success']['confirmation_clock']['partial_ns']
        elif name=='dual-partial-crash-not-restored':by_name['dual_stack']['recovered']['phase']='COMMITTED'
        elif name=='dual-reboot-pre-agent-journal':by_name['after_dual_boot']['journal_before_agent']['phase']='ROLLED_BACK'
        elif name=='dual-reboot-missing-family':by_name['after_dual_boot']['restored_kernel']=[]
        elif name=='dual-reboot-fresh-family':del by_name['after_dual_boot']['fresh_tls']['ipv6']
        elif name=='dual-reboot-wrong-boot':by_name['after_dual_boot']['boot_id_after']=by_name['after_dual_boot']['boot_id_before']
        elif name=='dual-orphan-did-not-survive':by_name['dual_held_executor']['after_agent_kill_identity']=None
        elif name=='dual-orphan-not-retired':by_name['dual_held_executor']['identity_after_recovery']=by_name['dual_held_executor']['old_executor_identity']
        elif name=='dual-orphan-overwrites-one-family':
            from .dual_recovery import FINAL, LATE
            by_name['dual_held_executor']['kernel_after_release']=expected({'ipv4':FINAL['ipv4'],'ipv6':LATE['ipv6']})
        elif name=='dual-orphan-missing-release-clock':del by_name['dual_held_executor']['release_clock']
        elif name=='dual-invalid-restart-identity':
            by_name['dual_stack']['identity_after_restart']={'pid':0,'start_ticks':0,'boot':by_name['setup']['boot_id']}
        elif name=='dual-failure-wrong-boot':
            dual=by_name['dual_stack']
            for receipt in [dual['failure']['pending'],*dual['failure']['partial'],dual['restored'],*dual['fresh_after_rollback'].values()]:
                receipt['boot']='other-boot'
        elif name=='dual-unrelated-success-operation':
            for receipt in by_name['dual_stack']['success'].values():
                if isinstance(receipt,dict) and 'op' in receipt:receipt['op']='unrelated-operation'
        elif name=='dual-success-wrong-boot':
            for key in ('ipv4_partial','ipv6_committed'):by_name['dual_stack']['success'][key]['boot']='other-boot'
        elif name=='dual-skipped-generation':
            for key in ('ipv4_partial','ipv6_committed'):by_name['dual_stack']['success'][key]['generation']+=1
        elif name=='dual-stale-kernel-modified':by_name['dual_stack']['stale']['observations'][0]['kernel_after']=[]
        elif name=='failed-journal-changed':by_name['restart_limit']['journal_while_failed']['phase']='ROLLED_BACK'
        try:verify(broken,source)
        except (AssertionError,KeyError):rows.append({'name':name,'rejected':True})
        else:raise AssertionError('Verifier accepted '+name)
    return rows


def render(value):
    rows = ''.join('<tr><td>' + html.escape(r['name']) + '</td><td>' + ('PASS' if r['passed'] else 'FAIL') + '</td></tr>' for r in value.get('cases', []))
    observations = ''
    by_name = {r['name']: r.get('evidence', {}) for r in value.get('cases', []) if r['passed']}
    if 'management_diagnostics' in by_name:
        observations += '<p>Configured management-port denial was rejected before mutation. Earlier/later foreign input drops were diagnosed and tested with real TCP; unsupported conditions remained risk. Foreign rules were unchanged. Old TLS confirmation was rejected; a fresh connection confirmed. These are namespace-local checks, not route/WAN reachability proof. Plan observations include CLI process and namespace overhead.</p>'
    if 'dual_stack' in by_name:
        d=by_name['dual_stack'];s=d['success']
        observations += '<p>Dual-stack static veth peers: repeated IPv4 confirmation could not mask a blocked fresh IPv6 connection; both policies rolled back at the common deadline. Old IPv4/IPv6 TLS and family spoofing were rejected. Fresh IPv4 partial + IPv6 confirmation committed; partial-confirmation SIGKILL restored the prior dual commit. Foreign tables remained unchanged.</p>'
        observations += f'<p>Single observed dual confirmation round trips: IPv4 partial {s["partial_ms"]:.2f} ms; IPv6 final commit {s["commit_ms"]:.2f} ms. Different state transitions, not a family performance comparison. Includes fresh TLS and durable writes; client-process startup excluded. Static-neighbour discovery observed. This case does not test VM boot; any separate partial-confirmation dual VM boot observation is reported below. Committed-only dual VM boot, routed PMTU, SLAAC and power loss remain untested.</p>'
    if 'after_dual_boot' in by_name:
        seconds=value.get('dual_pending_vm_restart_control_seconds')
        text=f'{seconds:.2f} s' if seconds is not None else 'not yet observed'
        observations += '<p>Dual partial-confirmation VM reboot: pre-Agent journal still pending, both owned tables absent before service startup; both baseline policies restored and fresh IPv4/IPv6 TLS succeeded. Orderly VM stop/start plus validation: '+text+' (one observation including control/probing, not a recovery bound).</p>'
    if 'dual_held_executor' in by_name:
        observations += '<p>Dual delayed orphan executor: deliberately kept outside the service cgroup and alive with writer.lock after its Agent was killed. The installed systemd Agent retired it before restoring the known baseline. A distinct two-family successor survived releasing the retired intent and a finite '+f"{by_name['dual_held_executor']['release_observation_seconds']:.2f} s"+' observation. This is explicit fault injection, not sudden power-loss or arbitrary-hang recovery.</p>'
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
