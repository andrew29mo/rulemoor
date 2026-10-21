"""Evidence checks for installed Boot Guard; no zero-gap or power-loss claim."""
import copy
import html
import json
from .evidence import fingerprint
from .boot_report import installed_provenance,verify_native
from rulemoor.policy import expected,digest

CASES=('setup','guard_setup','guard_portable','guard_failures','guard_delay','guard_crashes','guard_executor','guard_pending','guard_after_pending','guard_after_committed','guard_cleanup','cleanup')
STAGES=('vm-initial','vm-start','preflight','guest-prerequisites','wheel-build','snapshot-upload',
        'guest-setup','guest-guard_setup','guest-guard_portable','guest-guard_failures','guest-guard_delay','guest-guard_crashes','guest-guard_executor','guest-guard_pending',
        'pending-vm-stop','pending-vm-start','guest-guard_after_pending','committed-vm-stop','committed-vm-start',
        'guest-guard_after_committed','guest-guard_cleanup','guest-cleanup','snapshot-remove','vm-final-stop','vm-final')


def opened(r,j):
    assert r['status']=='OPEN' and r['phase']==j['phase'] and r['boot']==j['boot']
    assert r['generation']==j['generation'] and type(r['generation']) is int
    assert r['policy']==j['current'] and set(r['policy'])=={'ipv4','ipv6'}
    assert r['kernel']==expected(j['current']) and r['policy_digest']==digest(r['kernel'])
    assert r['link']['up'] is True and r['verified_link']['up'] is False
    assert {k:v for k,v in r['link'].items() if k!='up'}=={k:v for k,v in r['verified_link'].items() if k!='up'}
    assert r['link']['boot']==j['boot'] and r['link']['kind']=='veth'
    assert r['link']['namespace_inode']!=r['link']['host_namespace_inode']
    assert r['addresses']==['192.0.2.42/24','2001:db8:88::2/64']
    times=[r[k] for k in ('started_ns','verified_ns','opened_ns','observed_ns')]
    assert all(type(t) is int and t>=0 for t in times) and times==sorted(times)


def data(d):
    assert d['listener_identity_before']==d['listener_identity_after']
    assert type(d['listener_identity_before']['pid']) is int and d['listener_identity_before']['pid']>1
    assert d['listening_socket_counts']=={'19001':2,'19002':2}
    assert [(r['family'],r['port']) for r in d['rows']]==[(f,p) for f in ('ipv4','ipv6') for p in (19001,19002)]
    for r in d['rows']:
        if r['port']==19001:assert r['connected'] is True and r['echo']==r['family']+'-canary'
        else:assert r['connected'] is False and r['stage']=='connect' and r['errno'] in (None,11,110)


def verify(v,source):
    assert v['passed'] is True and v['source']==source and v['source_sha256']==fingerprint(source)
    assert v['source_changed'] is False and v['source_snapshot_removed'] is True
    assert v['vm_initial_state']==v['vm_final_state']=='Stopped'
    assert not any(k.endswith('error') for k in v)
    assert v['scope']['power_loss_tested'] is False and v['scope']['early_boot_zero_gap_tested'] is False
    assert v['scope']['production_boot_guard_implemented'] is True
    assert [r['name'] for r in v['stages']]==list(STAGES)
    assert all(r['exit_code']==0 and r['timed_out'] is False for r in v['stages'])
    assert [r['name'] for r in v['cases']]==list(CASES) and all(r['passed'] is True for r in v['cases'])
    c={r['name']:r['evidence'] for r in v['cases']}
    s=c['guard_setup'];installed_provenance(s['installed'],source)
    assert s['production_unit_sha256']==s['source_unit_sha256']==source['deploy/rulemoor-boot-guard.service']
    assert s['namespace_only_guard_override'] is True
    opened(s['opened']['receipt'],s['opened']['journal']);data(s['data'])
    assert s['opened']['receipt']['profile_digest']==digest(s['profile'])
    assert s['tls']['ipv4']==s['tls']['ipv6']==s['opened']['journal']
    p=c['guard_portable'];assert p['passed'] is True and p['platform']=='Linux' and p['source']==source
    assert p['source_sha256']==fingerprint(source) and p['tests']==len(p['test_ids'])==len(set(p['test_ids']))
    assert p['tests']>0 and all(p[k]==0 for k in ('errors','failures','skipped'))
    f=c['guard_failures'];bad=f['failed']
    assert bad['exit_code']!=0 and bad['unit']['ActiveState']=='failed' and bad['link']['up'] is False
    assert bad['receipt']['status']=='CLOSED' and bad['receipt']['link']['up'] is False
    assert bad['journal']['phase']=='DEGRADED' and bad['kernel']==f['candidate_kernel']==expected(f['pending']['candidate'])
    assert f['write_attempts']==['rejected-write']
    opened(f['repaired']['receipt'],f['repaired']['journal']);data(f['data'])
    d=c['guard_delay'];opened(d['early_without_tls_key']['receipt'],d['early_without_tls_key']['journal'])
    assert d['tls_failed_unit']['Result']=='exit-code' and d['tls_failed_unit']['ExecMainStatus']!='0'
    assert d['tls_unavailable_observed'] is True
    assert d['delayed']['agent']['SubState']=='start-pre' and d['delayed']['agent']['MainPID']=='0'
    assert d['delayed']['link']['up'] is True and d['guard_receipt_unchanged'] is True
    m=d['restart_link_monitor'];assert m['namespace_inode']==d['delayed']['link']['namespace_inode']
    assert m['finished_ns']>m['subscribed_ns'] and m['events']==[]
    assert d['delayed']['kernel']==d['early_without_tls_key']['kernel']
    for k in ('data_without_agent','data_after_restart'):data(d[k])
    data(d['delayed']['data'])
    assert d['tls_after_delay']['ipv4']==d['tls_after_delay']['ipv6']==d['tls_after_restart']['ipv4']==d['tls_after_restart']['ipv6']
    crashes=c['guard_crashes'];assert [r['point'] for r in crashes['kills']]==['before-up','after-up']
    for i,r in enumerate(crashes['kills']):
        assert r['link_before']['up']==bool(i) and r['link_after']['up'] is False
        assert r['receipt_after']['status']=='CLOSED' and r['receipt_after']['link']['up'] is False
        assert r['unit_after']['Result']=='signal' and r['unit_after']['ExecMainStatus']=='9'
        assert r['unit_before']['InvocationID']==r['unit_after']['InvocationID']
        assert int(r['unit_before']['MainPID'])==r['main_identity']['pid']
        assert r['main_identity']['boot']==r['link_before']['boot']==r['child_identity']['boot']
        assert r['child_retired'] is True
        mem=r['process_memory'];assert mem['identity']==r['main_identity']
        assert mem['entrypoint']=='/opt/rulemoor/venv/bin/rulemoor-boot-guard'
        assert type(mem['rss_bytes']) is int and type(mem['vmhwm_bytes']) is int
        assert 0<mem['rss_bytes']<=mem['vmhwm_bytes']
        for k in ('boot','namespace_inode','ifindex'):
            assert r['link_before'][k]==r['link_after'][k]==r['receipt_after']['link'][k]
    fault=crashes['close_failure'];assert fault['receipt']['status']=='FAULTED' and fault['link']['up'] is True
    assert fault['unit']['ActiveState']=='failed' and fault['manual_rescue_link']['up'] is False
    for k in ('boot','namespace_inode','ifindex'):assert fault['link'][k]==fault['manual_rescue_link'][k]
    opened(crashes['reopened']['receipt'],crashes['reopened']['journal']);data(crashes['data'])
    e=c['guard_executor'];assert e['parent_returncode']==-9 and e['old_phase']=='APPLYING'
    assert e['orphan_observed_alive'] is True and e['retired_before_open_return'] is True
    opened(e['opened']['receipt'],e['opened']['journal'])
    assert e['successor']['generation']>e['opened']['journal']['generation']
    assert e['retired_at_ns']<e['release_ns']<e['observed_ns'] and e['observed_ns']-e['release_ns']>=2_000_000_000
    assert e['kernel_before_release']==e['kernel_after_release']==expected(e['successor']['current']);data(e['data'])
    b=c['guard_pending'];assert b['journal_before_stop']==b['journal_after_stop']
    assert b['journal_after_stop']['confirmed_families']==['ipv4'] and b['journal_after_stop']['phase']=='AWAITING_CONFIRM'
    assert b['kernel_after_stop']==expected(b['journal_after_stop']['candidate']) and b['agent_stopped'] is True and b['link']['up'] is False
    for kind in ('pending','committed'):
        a=c['guard_after_'+kind];pre=a['pre_guard'];before=a['before'];j=a['journal']
        if kind=='pending':assert before==b
        else:assert before['journal_after_stop']==c['guard_after_pending']['next_committed']
        assert before['boot']!=pre['boot']==j['boot'] and pre['kernel'] is None and pre['link']['up'] is False
        assert pre['family_kernel']=={'ip':None,'ip6':None}
        assert pre['journal']==before['journal_after_stop']
        assert j['generation']>before['journal_after_stop']['generation']
        assert j['phase']==('ROLLED_BACK' if kind=='pending' else 'COMMITTED')
        assert j['current']==before['journal_after_stop']['baseline' if kind=='pending' else 'current']
        opened(a['guard'],j);data(a['data']);assert a['tls']['ipv4']==a['tls']['ipv6']==j
        assert a['power_loss_tested'] is False
        clock=v[kind+'_restart_clock'];seconds=v[kind+'_restart_control_seconds']
        assert clock['clock']=='monotonic_ns' and seconds>0
        assert abs(seconds-(clock['finished_ns']-clock['started_ns'])/1e9)<1e-9
    stale=c['guard_after_committed']['stale_confirmations']
    assert stale['rows']==[{'family':f,'status':409} for f in ('ipv4','ipv6')]
    assert stale['before']==stale['after'] and stale['kernel_before']==stale['kernel_after']
    assert all(c['guard_cleanup'][k] is True for k in ('guard_removed','peer_removed','root_firewall_unchanged'))
    assert c['cleanup']['vm_root_firewall_unchanged'] is True


def negative_controls(v,source):
    def case(x,n):return next(r['evidence'] for r in x['cases'] if r['name']==n)
    changes=[('missing-stage',lambda x:x['stages'].pop()),('missing-case',lambda x:x['cases'].pop()),
        ('timeout',lambda x:x['stages'][0].update(timed_out=True)),
        ('power-loss-claim',lambda x:x['scope'].update(power_loss_tested=True)),
        ('write-failed-but-up',lambda x:case(x,'guard_failures')['failed']['link'].update(up=True)),
        ('no-production-write-attempt',lambda x:case(x,'guard_failures').update(write_attempts=[])),
        ('ipv6-allowed-missing',lambda x:case(x,'guard_setup')['data']['rows'][2].update(connected=False)),
        ('ipv6-denied-but-accepted',lambda x:case(x,'guard_setup')['data']['rows'][3].update(connected=True)),
        ('listener-not-present',lambda x:case(x,'guard_setup')['data'].update(listening_socket_counts={'19001':2,'19002':0})),
        ('crash-cleanup-still-up',lambda x:case(x,'guard_crashes')['kills'][1]['link_after'].update(up=True)),
        ('invalid-guard-rss',lambda x:case(x,'guard_crashes')['kills'][0]['process_memory'].update(rss_bytes=0)),
        ('not-sigkill',lambda x:case(x,'guard_crashes')['kills'][0]['unit_after'].update(Result='success',ExecMainStatus='0')),
        ('writer-not-retired',lambda x:case(x,'guard_executor').update(retired_before_open_return=False)),
        ('late-writer-changed-policy',lambda x:case(x,'guard_executor')['kernel_after_release'].pop()),
        ('pre-shutdown-rollback',lambda x:case(x,'guard_after_pending')['pre_guard']['journal'].update(phase='ROLLED_BACK')),
        ('missing-second-family',lambda x:case(x,'guard_after_pending')['guard']['kernel'].pop()),
        ('open-before-policy',lambda x:case(x,'guard_after_pending')['guard'].update(verified_ns=case(x,'guard_after_pending')['guard']['opened_ns']+1)),
        ('stale-confirm-accepted',lambda x:case(x,'guard_after_committed')['stale_confirmations']['rows'][1].update(status=200)),
        ('echo-timeout-not-block',lambda x:case(x,'guard_setup')['data']['rows'][3].update(stage='echo')),
        ('restart-link-flap',lambda x:case(x,'guard_delay')['restart_link_monitor']['events'].append({'up':False})),
        ('close-failure-mislabeled',lambda x:case(x,'guard_crashes')['close_failure']['receipt'].update(status='CLOSED')),
        ('one-family-preexisting',lambda x:case(x,'guard_after_pending')['pre_guard']['family_kernel'].update(ip6=[{'unexpected':True}])),
        ('source-drift',lambda x:x.update(source_sha256='0'*64)),
        ('cleanup-incomplete',lambda x:x.update(source_snapshot_removed=False))]
    out=[]
    for n,mut in changes:
        x=copy.deepcopy(v);mut(x)
        try:verify(x,source)
        except (AssertionError,KeyError,TypeError,ValueError):out.append({'name':n,'rejected':True})
        else:raise AssertionError('Accepted broken evidence: '+n)
    return out


def render(v):
    good=False
    if v.get('passed') is True:
        try:
            verify(v,v['source']);assert v['evidence_controls']==negative_controls(v,v['source'])
        except (AssertionError,KeyError,TypeError,ValueError):pass
        else:good=True
    rows=''.join('<tr><td>'+html.escape(r['name'])+'</td><td>'+('observed' if r.get('passed') else 'incomplete')+'</td></tr>' for r in v.get('cases',[]))
    return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Rulemoor Boot Guard MVP</title><style>body{font:16px system-ui;max-width:1000px;margin:30px auto;padding:20px}td{padding:8px;border:1px solid #bbb}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Installed Boot Guard: '+('PASS' if good else 'FAIL / INCOMPLETE')+'</h1><p>Isolated Linux VM, static dual-stack veth profile; two orderly stop/start cycles. Installed production recovery and unit. Sampled readbacks and finite canary observations, not whole-host early-boot zero-gap or sudden power-loss validation. Timing is a single observation, not an SLA; Agent RSS and guard cgroup memory are different scopes.</p><table>'+rows+'</table><pre>'+html.escape(json.dumps(v,indent=2,allow_nan=False))+'</pre></html>\n'


if __name__=='__main__':
    import argparse
    from pathlib import Path
    from .evidence import manifest
    p=argparse.ArgumentParser();p.add_argument('directory');p.add_argument('--current-source',action='store_true');a=p.parse_args()
    root=Path(a.directory);v=json.loads((root/'guard.json').read_text());verify(v,manifest() if a.current_source else v['source'])
    assert v['evidence_controls']==negative_controls(v,v['source']) and (root/'report.html').read_text()==render(v)
    if (root/'native-unit.json').exists():verify_native(json.loads((root/'native-unit.json').read_text()),v['source'])
    print('PASS: installed Guard, exact report, provenance and negative controls')
