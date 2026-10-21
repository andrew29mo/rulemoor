"""Disposable VM fixture: installed production service, real systemd and nftables.

Only the fixed test namespace is mutated. Credentials and operational receipts stay
inside the VM; exported evidence excludes tokens and confirmation challenges.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import signal
import subprocess
import sys
import time

from rulemoor.backend import identity, boot_id
from rulemoor.policy import expected, canonical

SOURCE = Path('/opt/rulemoor-validation')
STATE = Path('/var/lib/rulemoor')
FIXTURE = Path('/var/lib/rulemoor-validation')
CONFIG = Path('/etc/rulemoor')
NS = 'rm_deployment'
PYTHON = '/opt/rulemoor/venv/bin/python'
UNIT = 'rulemoor.service'
BASE = {'default': 'accept', 'rules': [{'port': 59991, 'verdict': 'drop'}]}
NEXT = {'default': 'accept', 'rules': [{'port': 59992, 'verdict': 'drop'}]}
NEW = {'default': 'accept', 'rules': [{'port': 59993, 'verdict': 'drop'}]}
BLOCK = {'default': 'accept', 'rules': [{'port': 18443, 'verdict': 'drop'}]}


def cmd(args, check=True, timeout=30, **kwargs):
    p = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout, **kwargs)
    if check and p.returncode:
        raise RuntimeError('Fixture command failed: ' + str(args[:3]) + ': ' + p.stderr[-1200:])
    return p


def save(name, value):
    (FIXTURE / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def load(name):
    return json.loads((FIXTURE / (name + '.json')).read_text())


def wait(fn, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            value = fn()
            if value:
                return value
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
            pass
        time.sleep(.03)
    raise AssertionError('Deployment observation timed out')


def props():
    keys = ['MainPID', 'NRestarts', 'InvocationID', 'ActiveState', 'SubState', 'KillMode',
            'Restart', 'NoNewPrivileges', 'ProtectSystem', 'ProtectHome', 'PrivateTmp',
            'CapabilityBoundingSet', 'NetworkNamespacePath', 'MemoryCurrent', 'ControlGroup','Result','ExecMainStatus','StartLimitIntervalUSec','StartLimitBurst','RestartUSec']
    out = cmd(['systemctl', 'show', UNIT, *['--property=' + k for k in keys]]).stdout
    return dict(row.split('=', 1) for row in out.splitlines())


def kernel():
    p = cmd(['ip', 'netns', 'exec', NS, 'nft', '-j', '-s', 'list', 'table', 'ip', 'rulemoor'], check=False)
    if p.returncode:
        assert 'No such file or directory' in p.stderr, p.stderr
        return None
    return canonical(json.loads(p.stdout))


def root_rules_digest():
    rows = canonical(json.loads(cmd(['nft', '-j', '-s', 'list', 'ruleset']).stdout))
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def request(path='/status', payload=None, rejected=False):
    # Invoke the installed production CLI transport in a fresh namespace connection.
    code = '''import json,sys
from pathlib import Path
from rulemoor.cli import request
try:
 value=request('https://127.0.0.1:18443','/etc/rulemoor/server.pem',Path('/etc/rulemoor/token').read_text().strip(),sys.argv[1],json.loads(sys.argv[2]) if len(sys.argv)>2 else None)
 print(json.dumps({'ok':True,'value':value}))
except RuntimeError as e:
 print(json.dumps({'ok':False,'conflict':str(e).startswith('409:')}))
'''
    args = ['ip', 'netns', 'exec', NS, PYTHON, '-c', code, path]
    if payload is not None:
        args.append(json.dumps(payload))
    result = json.loads(cmd(args, timeout=7, cwd='/').stdout)
    if rejected:
        assert result == {'ok': False, 'conflict': True}, result
        return True
    assert result['ok'], result
    return result['value']


def ready(phase=None):
    def observed():
        s = request()
        return s if phase is None or s['phase'] == phase else False
    return wait(observed)


def apply(op, policy, window=60):
    s = request()
    return request('/apply', {'op': op, 'generation': s['generation'], 'policy': policy, 'window': window})


def confirm(s):
    return request('/confirm', {k: s[k] for k in ('op', 'generation', 'candidate_digest', 'challenge')})


def stale_rejected(old):
    if old.get('challenge'):
        request('/confirm', {k: old[k] for k in ('op', 'generation', 'candidate_digest', 'challenge')}, rejected=True)
    request('/cancel', {'op': old['op'], 'generation': old['generation']}, rejected=True)
    request('/apply', {'op': 'stale-' + old['op'], 'generation': old['generation'], 'policy': NEXT, 'window': 30}, rejected=True)
    return (['confirm'] if old.get('challenge') else []) + ['cancel', 'apply']


def commit_under_stale_requests(old, op, policy):
    fresh = apply(op, policy)
    rejected_pending = stale_rejected(old)
    status = request()
    assert status['phase'] == 'AWAITING_CONFIRM' and status['generation'] == fresh['generation']
    pending_kernel = kernel(); assert pending_kernel == expected(policy)
    committed = confirm(fresh)
    rejected_committed = stale_rejected(old)
    committed_kernel = kernel(); assert committed['phase'] == 'COMMITTED' and committed_kernel == expected(policy)
    return committed, {'pending_before': project(fresh), 'pending_after': project(status),
                       'pending_kernel': pending_kernel, 'committed': project(committed),
                       'committed_kernel': committed_kernel, 'rejected_pending': rejected_pending,
                       'rejected_committed': rejected_committed}


def journal_projection():
    from rulemoor.core import Store
    if not Store(STATE).path.exists():
        return None
    return project(Store(STATE).load())


def project(state):
    return {key: state[key] for key in ('phase', 'generation', 'op', 'boot', 'current', 'baseline', 'candidate') if key in state}


def installed_modules():
    # -I removes cwd/PYTHONPATH influence; cwd=/ also prevents fixture shadowing.
    code = "import rulemoor,pathlib,json,hashlib;p=pathlib.Path(rulemoor.__file__).parent;print(json.dumps({'origin':str(p),'hashes':{'rulemoor/'+f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in p.glob('*.py')}}))"
    result = json.loads(cmd([PYTHON, '-I', '-c', code], cwd='/').stdout)
    origin = Path(result['origin'])
    assert origin.is_relative_to('/opt/rulemoor/venv/lib') and origin.parent.name == 'site-packages'
    hashes = {'rulemoor/' + f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in (SOURCE / 'rulemoor').glob('*.py')}
    assert result['hashes'] == hashes
    return result


def memory():
    began = time.monotonic_ns()
    p = props(); pid = int(p['MainPID']); before = identity(pid)
    assert before is not None and before['boot'] == boot_id()
    proc = Path('/proc') / str(pid)
    argv = proc.joinpath('cmdline').read_bytes().decode().split('\0')
    assert '/opt/rulemoor/venv/bin/rulemoor-agent' in argv
    cwd = str(proc.joinpath('cwd').resolve()); assert cwd == '/'
    environment = dict(x.split('=', 1) for x in proc.joinpath('environ').read_bytes().decode().split('\0') if '=' in x)
    assert not environment.get('PYTHONPATH') and not environment.get('PYTHONHOME')
    process_namespace = proc.joinpath('ns/net').stat().st_ino
    target_namespace = Path('/run/netns', NS).stat().st_ino
    assert process_namespace == target_namespace
    assert p['ControlGroup'] == '/system.slice/rulemoor.service'
    assert '0::' + p['ControlGroup'] in proc.joinpath('cgroup').read_text().splitlines()
    fields = dict(line.split(':', 1) for line in proc.joinpath('status').read_text().splitlines() if ':' in line)
    after = props()
    assert before == identity(pid) and p['MainPID'] == after['MainPID'] and p['InvocationID'] == after['InvocationID']
    return {'agent_rss_bytes': int(fields['VmRSS'].split()[0]) * 1024,
            'agent_vmhwm_bytes': int(fields['VmHWM'].split()[0]) * 1024,
            'service_cgroup_memory_current_bytes': int(p['MemoryCurrent']),
            'process_identity': before, 'main_pid_after': int(after['MainPID']),
            'invocation_id': p['InvocationID'], 'invocation_id_after': after['InvocationID'],
            'process_namespace_inode': process_namespace, 'target_namespace_inode': target_namespace,
            'entrypoint': '/opt/rulemoor/venv/bin/rulemoor-agent', 'cwd': cwd,
            'python_path_environment_clean': True, 'control_group': p['ControlGroup'],
            'sample_started_ns': began, 'sample_finished_ns': time.monotonic_ns(),
            'scope': 'Linux VM installed daemon; VmHWM excludes nft children/client/VM; cgroup includes service children and charged memory, not VM'}


def topology():
    assert FIXTURE.is_dir()
    cmd(['ip', 'netns', 'add', NS]); cmd(['ip', '-n', NS, 'link', 'set', 'lo', 'up'])
    assert kernel() is None
    save('pre-agent-boot', {'boot_id': boot_id(), 'owned_table_absent': True, 'journal': journal_projection()})


def setup():
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert not STATE.exists() and not CONFIG.exists() and not Path('/opt/rulemoor').exists()
    FIXTURE.mkdir(mode=0o700)
    save('ownership', {'fixture': 'rulemoor-deployment-v1'})
    save('root-rules-before', {'sha256': root_rules_digest()})
    cmd(['python3', '-m', 'venv', '/opt/rulemoor/venv'])
    wheel = next(SOURCE.glob('*.whl'))
    cmd([PYTHON, '-m', 'pip', 'install', '--no-deps', wheel])
    provenance = installed_modules()
    CONFIG.mkdir(mode=0o700)
    cmd(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
         '-keyout', CONFIG / 'server.key', '-out', CONFIG / 'server.pem',
         '-subj', '/CN=rulemoor-deployment-test', '-addext', 'subjectAltName=IP:127.0.0.1'])
    (CONFIG / 'server.key').chmod(0o600)
    (CONFIG / 'token').write_text(secrets.token_hex(32)); (CONFIG / 'token').chmod(0o600)
    (FIXTURE / 'baseline.json').write_text(json.dumps(BASE))
    namespace_unit = '''[Unit]
Description=Disposable Rulemoor validation namespace
Before=rulemoor.service
[Service]
Type=oneshot
ExecStart=/opt/rulemoor/venv/bin/python /opt/rulemoor-validation/tools/deployment_guest.py topology
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''
    Path('/etc/systemd/system/rulemoor-test-namespace.service').write_text(namespace_unit)
    shutil.copyfile(SOURCE / 'deploy/rulemoor.service', '/etc/systemd/system/rulemoor.service')
    drop = Path('/etc/systemd/system/rulemoor.service.d'); drop.mkdir()
    (drop / '10-test-namespace.conf').write_text('''[Unit]
Requires=rulemoor-test-namespace.service
After=rulemoor-test-namespace.service
[Service]
NetworkNamespacePath=/run/netns/rm_deployment
MemoryAccounting=yes
''')
    cmd(['systemd-analyze', 'verify', '/etc/systemd/system/rulemoor.service', '/etc/systemd/system/rulemoor-test-namespace.service'])
    cmd(['systemctl', 'daemon-reload']); cmd(['systemctl', 'start', 'rulemoor-test-namespace.service'])
    cmd(['ip', 'netns', 'exec', NS, PYTHON, '-m', 'rulemoor.service', '--state', STATE,
         'init', '--policy', FIXTURE / 'baseline.json'])
    cmd(['systemctl', 'enable', '--now', UNIT]); ready('COMMITTED')
    p = props()
    assert p['Restart'] == 'on-failure' and p['KillMode'] == 'control-group'
    assert p['NoNewPrivileges'] == 'yes' and p['ProtectSystem'] == 'strict'
    assert p['NetworkNamespacePath'] == '/run/netns/' + NS
    assert set(p['CapabilityBoundingSet'].split()) == {'cap_kill', 'cap_net_admin'}
    return {'pid1': 'systemd', 'systemd': cmd(['systemctl', '--version']).stdout.splitlines()[0],
            'kernel': platform.release(), 'architecture': platform.machine(), 'python': platform.python_version(),
            'nft': cmd(['nft', '--version']).stdout.strip(), 'installed_modules_match_source': True, 'installed_package': provenance,
            'production_unit_sha256': hashlib.sha256(Path('/etc/systemd/system/rulemoor.service').read_bytes()).hexdigest(),
            'namespace_only_override': True, 'unit_properties': {k:v for k,v in p.items() if k != 'InvocationID'},
            'boot_id': boot_id(), 'memory': memory()}


def management_diagnostics():
    """Configured production service: admission, foreign-rule diagnosis and real TCP."""
    config=CONFIG/'management-paths.json'
    config.write_text(json.dumps({'paths':[{'name':'api','port':18443},{'name':'probe','port':59999}]}))
    drop=Path('/etc/systemd/system/rulemoor.service.d/20-management-paths.conf')
    executable=next(line for line in Path('/etc/systemd/system/rulemoor.service').read_text().splitlines() if line.startswith('ExecStart='))
    drop.write_text('[Service]\nExecStart=\n'+executable+' --management-paths /etc/rulemoor/management-paths.json\n')
    cmd(['systemctl','daemon-reload']);cmd(['systemctl','reset-failed',UNIT]);cmd(['systemctl','restart',UNIT]);ready('COMMITTED')
    listener=subprocess.Popen(['ip','netns','exec',NS,PYTHON,'-c',
        'import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",59999));s.listen();\nwhile True:\n c,a=s.accept();c.close()'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    table='rm_preflight_external'
    listener_identity=identity(listener.pid)
    assert listener_identity is not None
    def listener_observation():
        observed={'poll':listener.poll(),'identity':identity(listener.pid)}
        assert observed['poll'] is None and observed['identity']==listener_identity
        return observed
    def foreign():
        return canonical(json.loads(cmd(['ip','netns','exec',NS,'nft','-j','-s','list','table','ip',table]).stdout))
    def install(priority,rule):
        cmd(['ip','netns','exec',NS,'nft','-f','-'],input=f'table ip {table} {{\n chain input {{\n type filter hook input priority {priority}; policy accept;\n {rule}\n }}\n}}\n')
    def remove():
        cmd(['ip','netns','exec',NS,'nft','delete','table','ip',table])
    def probe():
        before=listener_observation()
        code='import socket,json;s=socket.socket();s.settimeout(.25);e=s.connect_ex(("127.0.0.1",59999));s.close();print(json.dumps({"connected":e==0,"errno":e}))'
        result=json.loads(cmd(['ip','netns','exec',NS,PYTHON,'-c',code]).stdout)
        result.update(listener_before=before,listener_after=listener_observation())
        return result
    try:
        wait(lambda: probe()['connected']);before_probe=probe()
        own_before=kernel();state_before=project(request())
        plan=request('/plan',{'policy':BLOCK})
        assert plan['diagnostics']['own_policy']['status']=='blocked'
        request('/apply',{'op':'guard-denied','generation':state_before['generation'],'policy':BLOCK,'window':30},rejected=True)
        own_after_denial=kernel();state_after=project(request())
        assert own_before==own_after_denial==expected(BASE) and state_before==state_after
        ordered={'default':'drop','rules':[{'port':18443,'verdict':'accept'},{'port':59999,'verdict':'accept'},{'port':18443,'verdict':'drop'}]}
        ordered_plan=request('/plan',{'policy':ordered})
        assert ordered_plan['diagnostics']['own_policy']['status']=='allowed'
        observations=[]
        for priority in (-100,10):
            before=probe();assert before['connected'] and before['errno']==0
            install(priority,'tcp dport 59999 drop')
            original=foreign();blocked_probe=probe()
            assert not blocked_probe['connected'] and blocked_probe['errno'] in (11,110)
            began=time.monotonic_ns()
            diag=request('/plan',{'policy':BASE})['diagnostics'];ended=time.monotonic_ns()
            assert diag['external']['status']=='blocked' and not diag['reachability_verified']
            assert diag['fresh_connection_confirmation_required']
            assert foreign()==original
            unchanged=foreign();remove()
            recovered=probe();assert recovered['connected'] and recovered['errno']==0
            observations.append({'priority':priority,'diagnostics':diag,'foreign_before':original,'foreign_after':unchanged,
                                 'tcp_probe_before':before,'tcp_probe':blocked_probe,'tcp_probe_recovered':recovered,
                                 'plan_clock':{'clock':'monotonic_ns','started_ns':began,'finished_ns':ended},'plan_observed_ms':(ended-began)/1e6})
        before_unknown=probe();assert before_unknown['connected'] and before_unknown['errno']==0
        install(10,'ip saddr 127.0.0.1 tcp dport 59999 drop')
        original=foreign();uncertain=request('/plan',{'policy':BASE})['diagnostics']
        assert uncertain['external']['status']=='risk' and not uncertain['reachability_verified']
        # Keep an actual TLS connection open across an admitted change. Production
        # CLI transport must confirm over a fresh connection; the old one gets 409.
        code='''import http.client,json,ssl
from pathlib import Path
from rulemoor.cli import request
base='https://127.0.0.1:18443';ca='/etc/rulemoor/server.pem';token=Path('/etc/rulemoor/token').read_text().strip()
def call(path,payload=None):return request(base,ca,token,path,payload)
c=http.client.HTTPSConnection('127.0.0.1',18443,context=ssl.create_default_context(cafile=ca),timeout=4)
headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}
c.request('GET','/status',headers=headers);r=c.getresponse();old_status=r.status;r.read()
s=call('/status');p={'op':'guard-admitted','generation':s['generation'],'policy':{'default':'accept','rules':[{'port':59992,'verdict':'drop'}]},'window':60}
pending=call('/apply',p);payload={k:pending[k] for k in ('op','generation','candidate_digest','challenge')}
c.request('POST','/confirm',body=json.dumps(payload),headers=headers);r=c.getresponse();old_confirm=r.status;r.read();c.close()
committed=call('/confirm',payload)
print(json.dumps({'old_status':old_status,'old_confirm':old_confirm,'fresh_phase':committed['phase'],'generation':committed['generation']}))
'''
        freshness=json.loads(cmd(['ip','netns','exec',NS,PYTHON,'-c',code],cwd='/',timeout=15).stdout)
        assert freshness['old_status']==200 and freshness['old_confirm']==409 and freshness['fresh_phase']=='COMMITTED'
        allowed_kernel=kernel();allowed_state=project(request())
        assert allowed_kernel==expected(NEXT) and foreign()==original
        uncertain_after=foreign();still_blocked=probe()
        assert not still_blocked['connected'] and still_blocked['errno'] in (11,110)
        remove()
        recovered_unknown=probe();assert recovered_unknown['connected'] and recovered_unknown['errno']==0
        sample=memory()
        confirm(apply('after-diagnostics-baseline',BASE));assert kernel()==expected(BASE)
        recovery_cases=[]
        configured_text=config.read_text()
        for kind in ('missing','null'):
            cmd(['systemctl','reset-failed',UNIT])
            pending=apply('configuration-recovery-'+kind,NEXT,window=300)
            pending_journal=journal_projection();pending_kernel=kernel()
            assert pending_journal==project(pending) and pending_journal['phase']=='AWAITING_CONFIRM'
            assert pending_kernel==expected(NEXT)
            unit_before=props();before_boot=boot_id()
            assert int(unit_before['MainPID'])>1
            try:
                if kind=='missing':config.unlink()
                else:config.write_text('null\n')
                # Observe pending state after damaging the config, immediately
                # before SIGKILL: graceful shutdown must not supply the rollback.
                before_kill=journal_projection();kernel_before_kill=kernel();unit_at_kill=props()
                assert before_kill==pending_journal and kernel_before_kill==pending_kernel
                assert unit_at_kill['MainPID']==unit_before['MainPID'] and unit_at_kill['InvocationID']==unit_before['InvocationID']
                failure_started=time.monotonic_ns()
                cmd(['systemctl','kill','--kill-whom=main','--signal=SIGKILL',UNIT])
                def rolled_back():
                    state=journal_projection()
                    return state if state['phase']=='ROLLED_BACK' and kernel()==expected(BASE) else False
                recovered=wait(rolled_back,timeout=20);recovered_kernel=kernel()
                assert recovered['generation']>pending['generation'] and recovered['boot']==before_boot
                def limited():
                    unit=props()
                    if unit['ActiveState']!='failed' or unit['MainPID']!='0':return False
                    entries=cmd(['journalctl','-u',UNIT,'-b','-o','json','--no-pager']).stdout.splitlines()
                    receipts=[{k:r[k] for k in ('MESSAGE','UNIT','_BOOT_ID','__MONOTONIC_TIMESTAMP')}
                              for line in entries for r in [json.loads(line)]
                              if r.get('UNIT')==UNIT and r.get('MESSAGE')==UNIT+': Start request repeated too quickly.'
                              and int(r['__MONOTONIC_TIMESTAMP'])*1000>=failure_started]
                    return (unit,receipts) if receipts else False
                failed,receipts=wait(limited,timeout=20);failure_observed=time.monotonic_ns()
                assert journal_projection()==recovered and kernel()==recovered_kernel==expected(BASE)
                after_boot=boot_id();assert after_boot==before_boot
            finally:
                config.write_text(configured_text)
            cmd(['systemctl','reset-failed',UNIT]);cmd(['systemctl','start',UNIT]);repaired=ready('ROLLED_BACK')
            assert project(repaired)==recovered and kernel()==expected(BASE)
            keys=('MainPID','InvocationID','ActiveState','Result','NRestarts')
            recovery_cases.append({'kind':kind,'pending_journal':pending_journal,'pending_kernel':pending_kernel,
                                   'unit_before_kill':{k:unit_before[k] for k in keys},
                                   'unit_at_kill':{k:unit_at_kill[k] for k in keys},
                                   'pending_journal_before_kill':before_kill,'pending_kernel_before_kill':kernel_before_kill,
                                   'signal':'SIGKILL','recovered_journal':recovered,'recovered_kernel':recovered_kernel,
                                   'failed_unit':{k:failed[k] for k in keys},'start_limit_receipts':receipts,
                                   'failure_started_monotonic_ns':failure_started,
                                   'failure_observed_monotonic_ns':failure_observed,
                                   'boot_before':before_boot,'boot_after':after_boot,'ready_after_repair':project(repaired)})
        return {'configuration':'explicit-local-ipv4-tcp-ports','supported_configuration_override':True,
                'configuration_recovery_cases':recovery_cases,
                'denied_plan':plan['diagnostics'],'ordered_plan':ordered_plan['diagnostics'],
                'state_before_denial':state_before,'state_after_denial':state_after,
                'own_kernel_before':own_before,'own_kernel_after_denial':own_after_denial,
                'listener_identity':listener_identity,'tcp_probe_before_foreign_drop':before_probe,'foreign_priority_cases':observations,
                'unsupported_condition':uncertain,'foreign_before_allowed_apply':original,'foreign_after_allowed_apply':uncertain_after,
                'tcp_probe_before_unknown_condition':before_unknown,'tcp_probe_after_unknown_condition':still_blocked,
                'tcp_probe_recovered_unknown_condition':recovered_unknown,'confirmation':freshness,'memory':sample,
                'own_kernel_after_allowed_apply':allowed_kernel,'state_after_allowed_apply':allowed_state,
                'scope':'Actual installed service in VM namespace; loopback TCP, not WAN/NAT/bridge/legacy-firewall verification'}
    finally:
        cmd(['ip','netns','exec',NS,'nft','delete','table','ip',table],check=False)
        listener.terminate()
        try:listener.wait(timeout=2)
        except subprocess.TimeoutExpired:listener.kill();listener.wait(timeout=2)
        drop.unlink(missing_ok=True);config.unlink(missing_ok=True)
        cmd(['systemctl','daemon-reload']);cmd(['systemctl','reset-failed',UNIT]);cmd(['systemctl','restart',UNIT]);ready()


def poisoned_journal():
    """Known malformed state stays diagnostic; fixture reprovision is explicit."""
    import sqlite3
    cmd(['systemctl','stop',UNIT])
    with sqlite3.connect(STATE / 'state.sqlite') as db:
        db.execute('UPDATE snapshot SET value=? WHERE id=1',(json.dumps([]),))
    before_kernel=kernel()
    cmd(['systemctl','start',UNIT]); status=ready('DEGRADED'); before=props()
    request('/apply',{'op':'poison-write','generation':0,'policy':NEXT,'window':30},rejected=True)
    time.sleep(2.2); after=props()
    with sqlite3.connect(STATE / 'state.sqlite') as db:
        preserved=db.execute('SELECT value FROM snapshot WHERE id=1').fetchone()[0]
    assert preserved==json.dumps([]) and before['InvocationID']==after['InvocationID']
    after_kernel=kernel()
    assert before['NRestarts']==after['NRestarts'] and after_kernel==before_kernel==expected(BASE)
    sample=memory()
    # Test-only operator reprovision: preserve evidence, stop all service writers,
    # establish a reviewed baseline, rotate credentials, then production init.
    cmd(['systemctl','stop',UNIT]); assert props()['MainPID']=='0'
    shutil.copytree(STATE,FIXTURE/'poison-evidence')
    shutil.rmtree(STATE)
    cmd(['ip','netns','exec',NS,'nft','delete','table','ip','rulemoor'])
    previous_token=(CONFIG/'token').read_text()
    (CONFIG/'token').write_text(secrets.token_hex(32));(CONFIG/'token').chmod(0o600)
    assert (CONFIG/'token').read_text()!=previous_token
    cmd(['ip','netns','exec',NS,PYTHON,'-m','rulemoor.service','--state',STATE,'init','--policy',FIXTURE/'baseline.json'],cwd='/')
    cmd(['systemctl','reset-failed',UNIT]);cmd(['systemctl','start',UNIT]);ready('COMMITTED')
    assert kernel()==expected(BASE)
    return {'invalid_snapshot_kind':'JSON list in valid SQLite snapshot',
            'diagnostic_phase':status['phase'],'diagnostic_reason':status['reason'],
            'original_snapshot_preserved':True,'mutations_rejected':True,
            'invocation_before':before['InvocationID'],'invocation_after':after['InvocationID'],
            'restart_count_before':int(before['NRestarts']),'restart_count_after':int(after['NRestarts']),
            'kernel_before':before_kernel,'kernel_after_diagnostic':after_kernel,
            'memory':sample,'fixture_only_reprovision_and_token_rotation':True,
            'production_auto_repair_claimed':False}


def restart_limit():
    """Persistent real ExecStart failure must stop retrying, not pretend to heal."""
    old=apply('initial',NEXT,window=300)
    before_journal=journal_projection()
    cmd(['systemctl','reset-failed',UNIT]); config=props()
    key=CONFIG/'server.key'; unavailable=CONFIG/'server.key.unavailable'
    key.rename(unavailable)
    try:
        failure_started=time.monotonic_ns()
        cmd(['systemctl','kill','--kill-whom=main','--signal=SIGKILL',UNIT])
        def limit_receipts():
            entries=cmd(['journalctl','-u',UNIT,'-b','-o','json','--no-pager']).stdout.splitlines()
            return [{k:r[k] for k in ('MESSAGE','UNIT','_BOOT_ID','__MONOTONIC_TIMESTAMP')}
                    for line in entries for r in [json.loads(line)]
                    if r.get('UNIT')==UNIT and r.get('MESSAGE')==UNIT+': Start request repeated too quickly.'
                    and int(r['__MONOTONIC_TIMESTAMP'])*1000>=failure_started]
        def hit_limit():
            observed=props()
            return observed if observed['Result'] in ('exit-code','start-limit-hit') and observed['ActiveState']=='failed' and observed['MainPID']=='0' and limit_receipts() else False
        try:
            failed=wait(hit_limit,timeout=20)
        except AssertionError:
            # Private host log keeps the actual failure instead of guessing why.
            import sys
            print(json.dumps({'unit_at_timeout':props()}),file=sys.stderr)
            print(cmd(['journalctl','-u',UNIT,'-n','45','--no-pager'],check=False).stdout,file=sys.stderr)
            raise
        receipts=limit_receipts()
        observed_started=time.monotonic_ns();time.sleep(2.2);stable=props();observed_finished=time.monotonic_ns()
        assert stable['Result']==failed['Result'] and stable['ActiveState']=='failed' and stable['MainPID']=='0'
        assert stable['NRestarts']==failed['NRestarts']
        assert int(config['StartLimitBurst'])==5 and 1<=int(stable['NRestarts'])<=6
        failed_journal=journal_projection();failed_kernel=kernel()
        assert failed_journal==before_journal and failed_journal['phase']=='AWAITING_CONFIRM'
        assert failed_kernel==expected(NEXT)
    finally:
        if unavailable.exists():unavailable.rename(key)
    # Fixing the file alone is not treated as proof that the failed service is ready.
    blocked=cmd(['systemctl','start',UNIT],check=False)
    assert blocked.returncode!=0 and props()['ActiveState']=='failed' and props()['MainPID']=='0'
    cmd(['systemctl','reset-failed',UNIT]);cmd(['systemctl','start',UNIT]);recovered=ready('ROLLED_BACK')
    restored=kernel();assert restored==expected(BASE) and recovered['generation']>old['generation']
    fresh,trace=commit_under_stale_requests(old,'after-limit-new',NEW)
    # Leave the original suite's reviewed baseline in place via normal API calls.
    confirm(apply('after-limit-baseline',BASE));assert kernel()==expected(BASE)
    keys=('MainPID','NRestarts','ActiveState','SubState','Result','ExecMainStatus')
    return {'failure_mode':'Missing TLS key: installed production ExecStart exits nonzero before recovery',
            'unit_limits':{k:config[k] for k in ('Restart','RestartUSec','StartLimitIntervalUSec','StartLimitBurst')},
            'failed':{k:failed[k] for k in keys},'stable':{k:stable[k] for k in keys},
            'failure_started_monotonic_ns':failure_started,'start_limit_receipts':receipts,
            'observation_clock':{'clock':'monotonic_ns','started_ns':observed_started,'finished_ns':observed_finished},
            'observation_seconds':(observed_finished-observed_started)/1e9,
            'journal_before_failure':before_journal,'journal_while_failed':failed_journal,
            'kernel_while_failed':failed_kernel,'blocked_start_exit_code':blocked.returncode,
            'local_cause_fixed_and_reset_started':True,'restored_kernel':restored,
            'old_generation':old['generation'],'recovered_generation':recovered['generation'],
            'new_generation':fresh['generation'],'stale_trace':trace,'memory':memory(),
            'segmentation_fault_tested':False,'uninterruptible_io_tested':False}


def crash():
    old = apply('crash-pending', NEXT); before = props(); pid = int(before['MainPID'])
    assert kernel() == expected(NEXT)
    began = time.monotonic_ns()
    cmd(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', UNIT])
    s = ready('ROLLED_BACK'); tls_observed = time.monotonic_ns(); after = props()
    assert after['InvocationID'] != before['InvocationID'] and int(after['MainPID']) != pid
    assert int(after['NRestarts']) > int(before['NRestarts']) and s['generation'] > old['generation']
    restored_kernel = kernel()
    assert restored_kernel == expected(BASE)
    verified = time.monotonic_ns()
    observed = (tls_observed - began) / 1_000_000
    newer, stale_trace = commit_under_stale_requests(old, 'after-crash-new', NEW)
    assert kernel() == expected(NEW) and newer['phase'] == 'COMMITTED'
    return {'automatic_systemd_restart': True, 'restart_count_before': int(before['NRestarts']),
            'restart_count_after': int(after['NRestarts']), 'main_pid_changed': True,
            'pending_baseline_restored': True, 'stale_requests_rejected_during_new_pending': True, 'stale_requests_rejected_after_new_commit': True,
            'new_policy_preserved': True, 'stale_trace': stale_trace, 'kill_to_tls_ready_observed_ms': observed,
            'recovery_clock': {'clock': 'monotonic_ns', 'kill_started_ns': began, 'tls_observed_ns': tls_observed, 'baseline_verified_ns': verified}, 'memory': memory(),
            'old_generation': old['generation'], 'recovered_generation': s['generation'],
            'new_generation': newer['generation'], 'restored_kernel': restored_kernel, 'kernel_after_stale': kernel()}


def held_writer():
    # Explicit test-only override of the production fault-hook clearing directive.
    drop = Path('/etc/systemd/system/rulemoor.service.d/90-test-fault.conf')
    drop.write_text('[Service]\nUnsetEnvironment=\nEnvironment=RULEMOOR_FAULT=executor-held\n')
    cmd(['systemctl', 'daemon-reload']); cmd(['systemctl', 'restart', UNIT]); ready('COMMITTED')
    from rulemoor.core import Store
    s = request(); payload = {'op': 'held-executor', 'generation': s['generation'], 'policy': NEXT, 'window': 60}
    code = "import sys,json;from tools.deployment_guest import request;request('/apply',json.loads(sys.argv[1]))"
    process = subprocess.Popen([PYTHON, '-c', code, json.dumps(payload)], cwd=SOURCE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        wait(lambda: (STATE / 'executor-held.reached').exists(), timeout=1.5)
        old = Store(STATE).load(); token = old['executor_token']
        rec = json.loads((STATE / ('executor-' + token + '.json')).read_text())
        old_identity = {k: rec[k] for k in ('pid', 'start_ticks', 'boot')}
        assert identity(rec['pid']) == old_identity
        before = props()
        # Next systemd invocation uses the ordinary production environment.
        drop.unlink(); cmd(['systemctl', 'daemon-reload'])
        cmd(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', UNIT])
        restored = ready('ROLLED_BACK')
        assert restored['generation'] > old['generation']
        assert identity(rec['pid']) != old_identity and props()['InvocationID'] != before['InvocationID']
        assert kernel() == expected(NEW)
        newer, stale_trace = commit_under_stale_requests(old, 'after-held-new', BASE)
        (STATE / 'executor-held.go').touch()
        time.sleep(2.1)
        stale_rejected(old)
        assert kernel() == expected(BASE) and newer['phase'] == 'COMMITTED'
        return {'test_only_fault_override': True, 'old_executor_identity': old_identity,
                'old_executor_retired': True, 'systemd_cgroup_restart_observed': True,
                'known_baseline_restored': True, 'late_release_did_not_overwrite_new_policy': True,
                'stale_requests_rejected_during_new_pending': True, 'stale_requests_rejected': True, 'new_policy_preserved': True, 'stale_trace': stale_trace,
                'old_generation': old['generation'], 'recovered_generation': restored['generation'],
                'new_generation': newer['generation'], 'kernel_after_late_release': kernel(),
                'old_executor_identity_after': identity(rec['pid'])}
    finally:
        drop.unlink(missing_ok=True)
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=8)


def prepare_pending_boot():
    old = apply('pending-before-boot', NEXT)
    save('pending-receipt', old)  # Private fixture state; never exported.
    drop = Path('/etc/systemd/system/rulemoor.service.d/91-test-kill.conf')
    drop.write_text('[Service]\nKillSignal=SIGKILL\nRestart=no\n')
    cmd(['systemctl', 'daemon-reload']); cmd(['systemctl', 'stop', UNIT])
    drop.unlink(); cmd(['systemctl', 'daemon-reload'])
    from rulemoor.core import Store
    assert Store(STATE).load()['phase'] == 'AWAITING_CONFIRM'
    assert kernel() == expected(NEXT) and props()['MainPID'] == '0'
    stopped_journal = journal_projection()
    save('pending-boot-before', {'boot_id': boot_id(), 'generation': old['generation'], 'journal': stopped_journal})
    return {'boot_id': boot_id(), 'journal_pending_after_service_stop': True,
            'candidate_still_installed': True, 'graceful_rollback_deliberately_bypassed': True,
            'pending_generation': old['generation'], 'kernel_before_shutdown': kernel(), 'journal_after_stop': stopped_journal,
            'unit_enabled': cmd(['systemctl', 'is-enabled', UNIT]).stdout.strip() == 'enabled'}


def after_pending_boot():
    old = load('pending-receipt'); before = load('pending-boot-before'); pre = load('pre-agent-boot')
    assert boot_id() != before['boot_id'] and pre['boot_id'] == boot_id() and pre['owned_table_absent']
    assert pre['journal'] == before['journal'] and pre['journal']['phase'] == 'AWAITING_CONFIRM'
    s = ready('ROLLED_BACK')
    restored_kernel = kernel()
    assert s['boot'] == boot_id() and s['generation'] > before['generation'] and restored_kernel == expected(BASE)
    fresh, stale_trace = commit_under_stale_requests(old, 'post-boot-new', NEW)
    assert fresh['phase'] == 'COMMITTED' and kernel() == expected(NEW)
    save('committed-boot-before', {'boot_id': boot_id(), 'generation': fresh['generation'], 'journal': journal_projection()})
    return {'boot_id_before': before['boot_id'], 'boot_id_after': boot_id(),
            'pre_agent_table_absent': True, 'journal_before_agent': pre['journal'], 'pending_baseline_restored': True,
            'generation_advanced': True, 'stale_requests_rejected_during_new_pending': True, 'stale_requests_rejected_after_new_commit': True,
            'new_policy_preserved': True, 'stale_trace': stale_trace, 'vm_uptime_after_validation_seconds': time.clock_gettime(time.CLOCK_BOOTTIME),
            'memory': memory(), 'old_generation': before['generation'], 'recovered_generation': s['generation'],
            'new_generation': fresh['generation'], 'restored_kernel': restored_kernel, 'kernel_after_stale': kernel()}


def after_committed_boot():
    before = load('committed-boot-before'); pre = load('pre-agent-boot')
    assert boot_id() != before['boot_id'] and pre['boot_id'] == boot_id() and pre['owned_table_absent']
    assert pre['journal'] == before['journal'] and pre['journal']['phase'] == 'COMMITTED'
    s = ready('COMMITTED')
    boot_memory = memory()
    restored_kernel = kernel()
    assert s['boot'] == boot_id() and s['generation'] > before['generation'] and restored_kernel == expected(NEW)
    request('/apply', {'op': 'old-committed-base', 'generation': before['generation'], 'policy': BASE, 'window': 30}, rejected=True)
    assert kernel() == expected(NEW)
    # Same-boot foreign policy must still block writes, even after boot support.
    script = 'delete table ip rulemoor\ntable ip rulemoor {\n chain foreign {\n }\n}\n'
    cmd(['ip', 'netns', 'exec', NS, 'nft', '-f', '-'], input=script)
    foreign = kernel(); cmd(['systemctl', 'restart', UNIT]); ready('DEGRADED')
    assert kernel() == foreign
    request('/apply', {'op':'foreign-change','generation':s['generation'],'policy':BASE,'window':30}, rejected=True)
    return {'boot_id_before': before['boot_id'], 'boot_id_after': boot_id(),
            'pre_agent_table_absent': True, 'journal_before_agent': pre['journal'], 'committed_policy_restored': True,
            'generation_advanced': True, 'old_base_rejected': True,
            'same_boot_foreign_policy_preserved': True, 'memory': boot_memory,
            'memory_stage': 'committed_after_boot_before_foreign_policy_probe',
            'old_generation': before['generation'], 'recovered_generation': s['generation'],
            'restored_kernel': restored_kernel, 'foreign_kernel': foreign, 'kernel_after_restart': kernel()}


def cleanup():
    assert load('ownership') == {'fixture': 'rulemoor-deployment-v1'}
    cmd(['systemctl', 'disable', '--now', UNIT], check=False)
    cmd(['systemctl', 'stop', 'rulemoor-test-namespace.service'], check=False)
    pids = cmd(['ip', 'netns', 'pids', NS], check=False).stdout.split()
    for pid in pids:
        os.kill(int(pid), signal.SIGKILL)
    wait(lambda: not cmd(['ip', 'netns', 'pids', NS], check=False).stdout.strip())
    cmd(['ip', 'netns', 'delete', NS], check=False)
    for f in ('rulemoor.service', 'rulemoor-test-namespace.service'):
        Path('/etc/systemd/system', f).unlink(missing_ok=True)
    shutil.rmtree('/etc/systemd/system/rulemoor.service.d', ignore_errors=True)
    cmd(['systemctl', 'daemon-reload']); cmd(['systemctl', 'reset-failed', UNIT], check=False)
    assert NS not in cmd(['ip', 'netns', 'list']).stdout
    assert props()['MainPID'] == '0'
    unchanged = root_rules_digest() == load('root-rules-before')['sha256']
    for p in (STATE, CONFIG, Path('/opt/rulemoor')):
        shutil.rmtree(p, ignore_errors=True)
    assert unchanged, 'VM root firewall changed outside fixture namespace'
    shutil.rmtree(FIXTURE)
    return {'namespace_removed': True, 'service_stopped_and_removed': True,
            'credentials_and_state_removed': True, 'vm_root_firewall_unchanged': True}


def main():
    p = argparse.ArgumentParser(); p.add_argument('phase', choices=['setup','topology','management_diagnostics','poisoned_journal','restart_limit','crash','held_writer','prepare_pending_boot','after_pending_boot','after_committed_boot','cleanup'])
    a = p.parse_args(); assert os.geteuid() == 0
    result = globals()[a.phase]()
    if result is not None:
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
