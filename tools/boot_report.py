"""Independent structural checks for experimental boot receipts; no safety SLA."""
import copy
import html
import json
import math
from pathlib import PurePosixPath
from .evidence import fingerprint
from rulemoor.policy import expected, digest

CASES=('setup','setup_probe','failures','ownership','crashes','handoff','after_boot','cleanup_probe','cleanup')
STAGES=('vm-initial','vm-start','preflight','guest-prerequisites','wheel-build','snapshot-upload',
        'guest-setup','guest-setup_probe','guest-failures','guest-ownership','guest-crashes','guest-handoff',
        'probe-vm-stop','probe-vm-start','guest-after_boot','guest-cleanup_probe','guest-cleanup',
        'snapshot-remove','vm-final-stop','vm-final')


def verify_stages(rows):
    assert [r['name'] for r in rows]==list(STAGES)
    for r in rows:
        assert type(r['exit_code']) is int and r['exit_code']==0 and r['timed_out'] is False
        assert type(r['seconds']) in (int,float) and math.isfinite(r['seconds']) and r['seconds']>=0


def link_identity(link):
    assert isinstance(link['boot'],str) and link['boot']
    assert type(link['up']) is bool
    for k in ('ifindex','namespace_inode'):assert type(link[k]) is int and link[k]>0
    return {k:link[k] for k in ('boot','ifindex','namespace_inode')}


def installed_provenance(row, source):
    origin=PurePosixPath(row['origin'])
    assert '..' not in origin.parts and origin.is_relative_to('/opt/rulemoor/venv/lib')
    assert origin.name=='rulemoor' and origin.parent.name=='site-packages'
    assert row['hashes']=={k:h for k,h in source.items() if k.startswith('rulemoor/')}


def verify_native(v, source):
    assert v['passed'] is True and v['platform']=='Darwin'
    assert v['source']==source and v['source_sha256']==fingerprint(source)
    assert type(v['tests']) is int and v['tests']>0
    assert len(v['test_ids'])==len(set(v['test_ids']))==v['tests']
    assert all(isinstance(t,str) and t for t in v['test_ids'])
    assert all(type(v[k]) is int and v[k]==0 for k in ('failures','errors','skipped'))


def verify_closed(r):
    assert type(r['exit_code']) is int and r['exit_code']!=0
    assert r['link']['up'] is False and r['unit']['ActiveState']=='failed'
    assert r['unit']['MainPID']=='0'
    assert r['cleanup']['status']=='CLOSED' and r['cleanup']['link']['up'] is False
    assert link_identity(r['link'])==link_identity(r['cleanup']['link'])


def verify_kill(r):
    assert r['unit']['ActiveState']=='failed' and r['unit']['MainPID']=='0'
    assert r['unit']['Result']=='signal' and r['unit']['ExecMainStatus']=='9'
    before=r['unit_before'];process=r['process_before']
    assert before['ActiveState']=='activating'
    assert before['InvocationID'] and before['InvocationID']==r['unit']['InvocationID']
    assert type(process['pid']) is int and process['pid']>1
    assert int(before['MainPID'])==r['held']['pid']==process['pid']
    assert r['held']['point']==r['point']
    assert type(process['start_ticks']) is int and process['start_ticks']>=0
    assert process['boot']==r['link_before']['boot']
    assert r['process_namespace_inode']==r['link_before']['namespace_inode']
    assert r['contending_controller_exit']==7
    for k in ('owner_lock_contender','writer_lock_contender'):
        assert r[k]=={'exit_code':7,'blocked':True}
    assert r['cleanup']['status']=='CLOSED' and r['cleanup']['link']['up'] is False
    assert r['link_after']['up'] is False
    assert link_identity(r['link_before'])==link_identity(r['cleanup']['link'])==link_identity(r['link_after'])
    t=r['signal_clock'];assert t['clock']=='monotonic_ns'
    assert all(type(t[k]) is int and t[k]>=0 for k in ('sent_ns','observed_closed_ns'))
    assert t['observed_closed_ns']>t['sent_ns']


def verify_open_receipt(a, j):
    assert a['status']=='OPEN' and a['kernel']==expected(j['current']) and a['link']['up'] is True
    r=a['receipt'];assert r['up'] is False
    assert type(r['generation']) is int and r['generation']>=0
    assert r['boot']==j['boot']==a['link']['boot'] and r['generation']==j['generation']
    assert r['phase']==j['phase'] and r['policy_digest']==digest(expected(j['current']))
    assert link_identity(r)==link_identity(a['link']) and r['clock']=='monotonic_ns'
    times=[a['started_ns'],r['verified_ns'],a['opened_ns'],a['finished_ns']]
    assert all(type(t) is int and t>=0 for t in times) and times==sorted(times)


def verify(v, source):
    assert v['passed'] is True and v['source']==source and v['source_sha256']==fingerprint(source)
    assert v['source_changed'] is False and v['source_snapshot_removed'] is True and v['vm_final_state']=='Stopped'
    assert not any(k.endswith('error') for k in v)
    assert v['scope']['power_loss_tested'] is False and v['scope']['early_boot_zero_gap_tested'] is False
    assert v['scope']['production_boot_guard_implemented'] is False
    assert v['vm_initial_state']=='Stopped'
    verify_stages(v['stages'])
    assert [r['name'] for r in v['cases']]==list(CASES) and all(r['passed'] is True for r in v['cases'])
    c={r['name']:r['evidence'] for r in v['cases']}
    assert c['setup']['installed_modules_match_source'] is True
    installed_provenance(c['setup']['installed_package'],source)
    installed_provenance(c['setup_probe']['installed_modules'],source)
    assert c['setup_probe']['initial_link']['up'] is False
    f=c['failures'];assert [r['fault'] for r in f['failures']]==['journal','nft','timeout','ipv6-drift','ipv6-batch']
    for r in f['failures']:
        verify_closed(r)
    assert f['failures'][2]['unit']['Result']=='timeout'
    drift=f['failures'][3];assert drift['kernel_after']==drift['kernel_drift']!=drift['kernel_before']
    def family(rows,f):return [r for r in rows if next(iter(r.values())).get('family')==f]
    assert family(drift['kernel_before'],'ip')==family(drift['kernel_after'],'ip')
    assert family(drift['kernel_before'],'ip6')!=family(drift['kernel_after'],'ip6')
    batch=f['failures'][4];assert batch['kernel_before']==batch['kernel_after']
    assert f['condition_skip_counterexample']['exit_code']==0 and f['condition_skip_counterexample']['link']['up'] is True
    assert f['repaired']['exit_code']==0 and f['repaired']['link']['up'] is True
    # This repair precedes any transaction: initialized committed generation 0.
    initial={'current':c['handoff']['journal']['baseline'],'boot':c['setup_probe']['boot'],
             'generation':0,'phase':'COMMITTED'}
    verify_open_receipt(f['repaired']['receipt'],initial)
    o=c['ownership'];assert [r['action'] for r in o['observations']]==[
        'manual-start','manual-restart-closed','manual-restart-open','manual-reconfigure-closed',
        'competing-up-counterexample','networkd-stop-leaves-open']
    assert [r['link']['up'] for r in o['observations']]==[False,False,True,False,True,True]
    d=o['delay'];assert d['during']['agent']['MainPID']=='0' and d['during']['agent']['SubState']=='start-pre'
    assert d['after']['agent_namespace_inode']==d['after']['link']['namespace_inode']
    assert d['during']['kernel']==d['after']['kernel']==d['restarted']['kernel']
    assert all(d[k]['link']['up'] is True for k in ('during','after','restarted'))
    assert d['after']['agent']['MainPID']!=d['restarted']['agent']['MainPID']
    assert d['finished_ns']>d['started_ns']
    crash=c['crashes'];assert [r['point'] for r in crash['kills']]==['before-up','after-up']
    for i,r in enumerate(crash['kills']):
        assert r['link_before']['up']==bool(i)
        verify_kill(r)
        assert r['reopened']['exit_code']==0 and r['reopened']['link']['up'] is True
    assert crash['close_failure']['exit_code']!=0 and crash['close_failure']['cleanup']['status']=='FAULTED'
    assert crash['close_failure']['link']['up'] is True and crash['close_failure']['manual_rescue_link']['up'] is False
    assert crash['close_failure']['cleanup']['boot']==crash['close_failure']['link']['boot']
    assert link_identity(crash['close_failure']['link'])==link_identity(crash['close_failure']['manual_rescue_link'])
    verify_closed(crash['post_up_exception'])
    b=c['after_boot'];before=c['handoff'];assert b['before']==before
    assert before['journal']['phase']=='AWAITING_CONFIRM' and before['link']['up'] is False
    assert before['kernel']==expected(before['journal']['candidate'])
    assert before['journal']==b['pre_agent']['journal'] and before['boot']!=b['pre_agent']['link']['boot']
    assert b['pre_agent']['link']['up'] is False
    assert all(set(row)=={'metainfo'} for row in b['pre_agent']['kernel']['nftables'])
    j=b['journal_after'];assert j['phase']=='ROLLED_BACK' and j['current']==before['journal']['baseline']
    assert j['generation']>before['journal']['generation'] and j['boot']==b['pre_agent']['link']['boot']
    a=b['after'];verify_open_receipt(a,j)
    assert link_identity(a['receipt'])==link_identity(b['pre_agent']['link'])
    assert b['stale_receipt_supplied']==before['old_receipt']
    verify_open_receipt(b['stale_receipt_revalidation'],j)
    assert b['stale_receipt_revalidated']==b['stale_receipt_revalidation']['receipt']
    assert link_identity(b['stale_receipt_revalidated'])==link_identity(a['receipt'])
    assert j['boot']!=before['old_receipt']['boot']
    recreated=b['same_boot_namespace_recreation']
    assert recreated['old_namespace_pinned'] is True
    assert recreated['old_inode']==a['link']['namespace_inode']
    assert recreated['new_link']['namespace_inode']!=recreated['old_inode']
    assert recreated['new_link']['boot']==j['boot'] and recreated['new_link']['up'] is False
    r=recreated['rejected'];verify_closed(r)
    assert link_identity(r['link'])==link_identity(recreated['new_link'])
    assert b['power_loss_tested'] is False
    assert all(c['cleanup_probe'][k] is True for k in ('namespace_removed','units_removed','root_firewall_unchanged'))
    assert c['cleanup']['vm_root_firewall_unchanged'] is True
    clock=v['vm_restart_clock'];s=v['vm_restart_control_seconds']
    assert type(s) in (int,float) and math.isfinite(s) and s>0
    assert clock['clock']=='monotonic_ns' and clock['finished_ns']>clock['started_ns']
    assert abs(s-(clock['finished_ns']-clock['started_ns'])/1e9)<1e-9


def negative_controls(v, source):
    changes=[('missing-case',lambda x:x['cases'].pop()),
             ('timeout',lambda x:x['stages'][0].update(timed_out=True)),
             ('claim-zero-gap',lambda x:x['scope'].update(early_boot_zero_gap_tested=True)),
             ('source-drift',lambda x:x.update(source_sha256='0'*64)),
             ('cleanup-failed',lambda x:x.update(source_snapshot_removed=False))]
    def case(x,n):return next(r['evidence'] for r in x['cases'] if r['name']==n)
    changes += [('failed-open',lambda x:case(x,'failures')['failures'][0]['link'].update(up=True)),
                ('missing-second-family',lambda x:case(x,'after_boot')['after']['kernel'].pop()),
                ('wrong-boot',lambda x:case(x,'after_boot')['after']['receipt'].update(boot='old')),
                ('fake-preboot-rollback',lambda x:case(x,'after_boot')['pre_agent']['journal'].update(phase='ROLLED_BACK')),
                ('crash-remained-open',lambda x:case(x,'crashes')['kills'][1]['link_after'].update(up=True)),
                ('false-closed',lambda x:case(x,'crashes')['close_failure']['cleanup'].update(status='CLOSED')),
                ('wrong-digest',lambda x:case(x,'after_boot')['after']['receipt'].update(policy_digest='0'*64)),
                ('wrong-namespace',lambda x:case(x,'after_boot')['after']['receipt'].update(namespace_inode=0)),
                ('missing-stages',lambda x:x.update(stages=x['stages'][:1])),
                ('duplicate-stage',lambda x:x['stages'].append(copy.deepcopy(x['stages'][-1]))),
                ('non-kill-exit',lambda x:case(x,'crashes')['kills'][0]['unit'].update(Result='exit-code',ExecMainStatus='1')),
                ('wrong-killed-pid',lambda x:case(x,'crashes')['kills'][0]['held'].update(pid=1)),
                ('wrong-invocation',lambda x:case(x,'crashes')['kills'][0]['unit'].update(InvocationID='other')),
                ('cleanup-still-up',lambda x:case(x,'crashes')['kills'][1]['cleanup']['link'].update(up=True)),
                ('cleanup-wrong-identity',lambda x:case(x,'crashes')['kills'][1]['cleanup']['link'].update(boot='old')),
                ('writer-not-blocked',lambda x:case(x,'crashes')['kills'][0]['writer_lock_contender'].update(blocked=False)),
                ('stale-generation',lambda x:case(x,'after_boot')['stale_receipt_revalidated'].update(generation=-1)),
                ('stale-digest',lambda x:case(x,'after_boot')['stale_receipt_revalidated'].update(policy_digest='0'*64)),
                ('stale-namespace',lambda x:case(x,'after_boot')['stale_receipt_revalidated'].update(namespace_inode=0)),
                ('reused-namespace',lambda x:case(x,'after_boot')['same_boot_namespace_recreation']['new_link'].update(namespace_inode=case(x,'after_boot')['same_boot_namespace_recreation']['old_inode'])),
                ('recreated-wrong-boot',lambda x:case(x,'after_boot')['same_boot_namespace_recreation']['new_link'].update(boot='other')),
                ('source-import',lambda x:case(x,'setup_probe')['installed_modules'].update(origin='/opt/rulemoor-validation/rulemoor'))]
    rows=[]
    for name,change in changes:
        x=copy.deepcopy(v);change(x)
        try:verify(x,source)
        except (AssertionError,KeyError,TypeError,ValueError):rows.append({'name':name,'rejected':True})
        else:raise AssertionError('Accepted broken evidence: '+name)
    return rows


def render(v):
    # A partial run must never render green because a producer toggled its flag
    # before cleanup, or because a copied JSON object contains passed=true.
    verified=False
    if v.get('passed') is True:
        try:
            verify(v,v['source'])
            assert v['evidence_controls']==negative_controls(v,v['source'])
        except (AssertionError,KeyError,TypeError,ValueError):pass
        else:verified=True
    status='PASS' if verified else 'FAIL / INCOMPLETE'
    rows=''.join('<tr><td>'+html.escape(r['name'])+'</td><td>'+('PASS' if r.get('passed') else 'FAIL / INCOMPLETE')+'</td></tr>' for r in v.get('cases',[]))
    return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Rulemoor boot design experiments</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:20px}td,th{padding:8px;border:1px solid #ccc}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Boot design experiments: '+status+'</h1><p>Experimental orchestration with installed production Controller/Agent. Isolated Linux VM veth; not a production Boot Guard. No early-boot zero-gap or sudden power-loss claim. Timings describe single control/observation intervals, not recovery SLAs. No RSS comparison or performance benefit is established.</p><p>PASS means expected observations, including unsafe counterexamples: a skipped prerequisite and competing activation open the interface. Injected cleanup failure leaves it UP/FAULTED until a separately observed manual close. Post-UP crash cleanup does not establish zero exposure. Direct nft prerequisite faults do not test production backend recovery-write failure.</p><table><tr><th>Case</th><th>Observation</th></tr>'+rows+'</table><h2>Receipts</h2><pre>'+html.escape(json.dumps(v,indent=2,allow_nan=False))+'</pre></html>\n'


if __name__=='__main__':
    import argparse
    from pathlib import Path
    from .evidence import manifest
    p=argparse.ArgumentParser();p.add_argument('directory');p.add_argument('--current-source',action='store_true')
    a=p.parse_args();root=Path(a.directory);v=json.loads((root/'exploration.json').read_text())
    verify(v,manifest() if a.current_source else v['source'])
    assert v['evidence_controls']==negative_controls(v,v['source'])
    assert (root/'report.html').read_text()==render(v)
    native=root/'native-unit.json'
    if native.exists():verify_native(json.loads(native.read_text()),v['source'])
    print('PASS: boot experiment receipts, negative controls and exact HTML renderer; native receipt '+('verified' if native.exists() else 'not present (VM-only audit)'))
