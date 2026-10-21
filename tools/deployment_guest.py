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
from rulemoor.policy import expected, canonical, compile_policy

# Direct VM entrypoints run from /: append only fixture helpers after installed
# site-packages. Production rulemoor is already imported from the installed wheel.
if __package__ in (None, ''):
    sys.path.append(str(Path(__file__).resolve().parents[1]))

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
    return {key: state[key] for key in ('phase', 'generation', 'op', 'boot', 'current', 'baseline', 'candidate', 'confirmed_families') if key in state}


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
    pre={'boot_id':boot_id(),'owned_table_absent':True,'journal':journal_projection()}
    if (FIXTURE/'dual-recovery-mode.json').exists():
        from tools import dual_recovery
        dual_recovery.topology();pre['dual_tables']=dual_recovery.families()
        assert pre['dual_tables']=={'ip':None,'ip6':None}
    save('pre-agent-boot',pre)


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


def dual_stack():
    """Fresh dual deployment, actual two-family TLS across disposable veth peers."""
    client_ns='rm_dual_client'
    baseline={'ipv4':{'default':'drop','rules':[{'port':18443,'verdict':'accept'},{'port':59991,'verdict':'drop'}]},
              'ipv6':{'default':'drop','rules':[{'port':18443,'verdict':'accept'},{'port':59991,'verdict':'drop'}]}}
    blocked={'ipv4':{'default':'drop','rules':[{'port':18443,'verdict':'accept'},{'port':59992,'verdict':'drop'}]},
             'ipv6':{'default':'drop','rules':[]}}
    candidate={'ipv4':blocked['ipv4'],'ipv6':{'default':'drop','rules':[{'port':18443,'verdict':'accept'},{'port':59993,'verdict':'drop'}]}}
    drop=Path('/etc/systemd/system/rulemoor.service.d/30-dual-stack.conf')
    cmd(['systemctl','stop',UNIT]);assert props()['MainPID']=='0'
    backup=FIXTURE/'legacy-state';shutil.copytree(STATE,backup);shutil.rmtree(STATE)
    cert=(CONFIG/'server.pem').read_bytes();key=(CONFIG/'server.key').read_bytes()
    def dual_kernel():
        return sum((canonical(json.loads(cmd(['ip','netns','exec',NS,'nft','-j','-s','list','table',family,'rulemoor']).stdout)) for family in ('ip','ip6')),[])
    def peer(code,*args):
        return json.loads(cmd(['ip','netns','exec',client_ns,PYTHON,'-c',code,*args],cwd='/',timeout=20).stdout)
    common='''import http.client,json,ssl,socket,time
from pathlib import Path
from rulemoor.cli import request
ca='/etc/rulemoor/server.pem';token=Path('/etc/rulemoor/token').read_text().strip()
urls={'ipv4':'https://192.0.2.2:18443','ipv6':'https://[2001:db8:44::2]:18443'}
def call(f,path='/status',payload=None):return request(urls[f],ca,token,path,payload,family=f)
def projection(s):return {k:s[k] for k in ('phase','generation','op','boot','current','baseline','candidate','confirmed_families') if k in s}
def payload(s):return {k:s[k] for k in ('op','generation','candidate_digest','challenge')}
'''
    foreign_name='rm_dual_foreign'
    cleanup_evidence={}
    def foreign():
        return [canonical(json.loads(cmd(['ip','netns','exec',NS,'nft','-j','-s','list','table',family,foreign_name]).stdout)) for family in ('ip','ip6')]
    try:
        policy=FIXTURE/'dual-baseline.json';policy.write_text(json.dumps(baseline))
        adoption=cmd(['ip','netns','exec',NS,'/opt/rulemoor/venv/bin/rulemoor-agent','--state',FIXTURE/'adopt-refused','init','--dual-stack','--policy',policy],check=False)
        legacy_preserved=kernel();assert adoption.returncode!=0 and legacy_preserved==expected(BASE)
        cmd(['ip','netns','exec',NS,'nft','delete','table','ip','rulemoor'])
        cmd(['ip','netns','add',client_ns]);cmd(['ip','-n',client_ns,'link','set','lo','up'])
        cmd(['ip','-n',NS,'link','add','rmds','type','veth','peer','name','rmdc','netns',client_ns])
        for ns,dev,v4,v6 in ((NS,'rmds','192.0.2.2/24','2001:db8:44::2/64'),(client_ns,'rmdc','192.0.2.1/24','2001:db8:44::1/64')):
            cmd(['ip','-n',ns,'addr','add',v4,'dev',dev]);cmd(['ip','-n',ns,'-6','addr','add',v6,'dev',dev,'nodad']);cmd(['ip','-n',ns,'link','set',dev,'up'])
        cmd(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',CONFIG/'server.key','-out',CONFIG/'server.pem','-subj','/CN=rulemoor-test','-addext','subjectAltName=IP:127.0.0.1,IP:::1,IP:192.0.2.2,IP:2001:db8:44::2'])
        (CONFIG/'server.key').chmod(0o600)
        policy=FIXTURE/'dual-baseline.json';policy.write_text(json.dumps(baseline))
        cmd(['ip','netns','exec',NS,'/opt/rulemoor/venv/bin/rulemoor-agent','--state',STATE,'init','--dual-stack','--policy',policy])
        executable=next(line for line in Path('/etc/systemd/system/rulemoor.service').read_text().splitlines() if line.startswith('ExecStart='))
        drop.write_text('[Service]\nExecStart=\n'+executable.replace('--listen 127.0.0.1','--listen 0.0.0.0')+' --dual-stack --listen6 ::\n')
        cmd(['systemctl','daemon-reload']);cmd(['systemctl','reset-failed',UNIT]);cmd(['systemctl','start',UNIT]);ready('COMMITTED')
        for family in ('ip','ip6'):
            cmd(['ip','netns','exec',NS,'nft','-f','-'],input=f'table {family} {foreign_name} {{\n chain marker {{\n }}\n}}\n')
        foreign_before=foreign();initial_kernel=dual_kernel();assert initial_kernel==expected(baseline)
        # A rejected second-family batch must leave the first family unchanged.
        broken=compile_policy(candidate)+'\nadd rule ip6 rulemoor missing_chain tcp dport 12345 drop\n'
        atomic=cmd(['ip','netns','exec',NS,'nft','-f','-'],input=broken,check=False)
        atomic_after=dual_kernel();assert atomic.returncode!=0 and atomic_after==initial_kernel
        initial=peer(common+"print(json.dumps({f:projection(call(f)) for f in urls}))")
        assert initial['ipv4']==initial['ipv6'] and initial['ipv4']['phase']=='COMMITTED'
        invocation_before=props();start_identity=identity(int(invocation_before['MainPID']))
        # Held old TLS sockets can traverse established rules, but cannot confirm.
        script=common+'''
import sys
old={}
for f,host in (('ipv4','192.0.2.2'),('ipv6','2001:db8:44::2')):
 c=http.client.HTTPSConnection(host,18443,context=ssl.create_default_context(cafile=ca),timeout=2)
 c.request('GET','/status',headers={'Authorization':'Bearer '+token});r=c.getresponse();assert r.status==200;r.read();old[f]=c
p=json.loads(sys.argv[1]);state=call('ipv4');s=call('ipv4','/apply',{'op':'dual-v6-blocked','generation':state['generation'],'policy':p,'window':5})
receipts={}
for f,c in old.items():
 c.request('POST','/confirm',json.dumps(payload(s)),{'Authorization':'Bearer '+token,'Content-Type':'application/json'})
 r=c.getresponse();receipts[f]=r.status;r.read();c.close();assert receipts[f]==409
partials=[]
for _ in range(2):
 v=call('ipv4','/confirm',payload(s));assert v['phase']=='AWAITING_CONFIRM' and v['confirmed_families']==['ipv4'];partials.append(projection(v))
try:call('ipv4','/confirm',{**payload(s),'transport_family':'ipv6'})
except RuntimeError as e:spoof=str(e).startswith('400:')
else:spoof=False
assert spoof
sock=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);sock.settimeout(.25);errno=sock.connect_ex(('2001:db8:44::2',18443));sock.close();assert errno in (11,110)
print(json.dumps({'pending':projection(s),'partial':partials,'old_confirmation_status':receipts,'spoof_rejected':spoof,'ipv6_connect_errno':errno,'deadline':s['deadline']}))
'''
        failure=peer(script,json.dumps(blocked));pending_kernel=dual_kernel();assert pending_kernel==expected(blocked)
        assert identity(int(props()['MainPID']))==start_identity
        wait(lambda: request()['phase']=='ROLLED_BACK',timeout=12)
        restored_full=request();restored=project(restored_full);restored_kernel=dual_kernel();assert restored_kernel==expected(baseline)
        rollback_clock={k:restored_full[k] for k in ('deadline','rollback_started_at','rollback_completed_at')}
        rollback_clock.update(clock='CLOCK_BOOTTIME',observed_at=time.clock_gettime(time.CLOCK_BOOTTIME))
        fresh_after=peer(common+"print(json.dumps({f:projection(call(f)) for f in urls}))")
        assert fresh_after['ipv4']==fresh_after['ipv6']==restored
        after_timeout_identity=identity(int(props()['MainPID']));assert after_timeout_identity==start_identity
        # Clear neighbour entries; fresh IPv6 access must recreate them over veth.
        cmd(['ip','-n',NS,'-6','neigh','flush','dev','rmds']);cmd(['ip','-n',client_ns,'-6','neigh','flush','dev','rmdc'])
        success=peer(common+'''
import sys
s0=call('ipv4');s=call('ipv4','/apply',{'op':'dual-both-success','generation':s0['generation'],'policy':json.loads(sys.argv[1]),'window':10})
p=payload(s);began=time.monotonic_ns();v4=call('ipv4','/confirm',p);middle=time.monotonic_ns();v6=call('ipv6','/confirm',p);ended=time.monotonic_ns()
assert v4['phase']=='AWAITING_CONFIRM' and v6['phase']=='COMMITTED'
print(json.dumps({'ipv4_partial':projection(v4),'ipv6_committed':projection(v6),'confirmation_clock':{'clock':'monotonic_ns','started_ns':began,'partial_ns':middle,'finished_ns':ended},'partial_ms':(middle-began)/1e6,'commit_ms':(ended-middle)/1e6}))
''',json.dumps(candidate))
        committed_kernel=dual_kernel();assert committed_kernel==expected(candidate)
        neighbours=cmd(['ip','-n',client_ns,'-6','neigh','show','dev','rmdc']).stdout.strip()
        assert '2001:db8:44::2' in neighbours and 'lladdr' in neighbours
        sample=memory();assert sample['process_identity']==start_identity
        # A partially confirmed successor must restore the entire last commit on restart.
        partial=peer(common+'''
import sys
state=call('ipv4');s=call('ipv4','/apply',{'op':'dual-partial-crash','generation':state['generation'],'policy':json.loads(sys.argv[1]),'window':60})
Path('/var/lib/rulemoor-validation/dual-old-receipt.json').write_text(json.dumps(s))
p=call('ipv4','/confirm',payload(s));assert p['phase']=='AWAITING_CONFIRM'
print(json.dumps({'pending':projection(p)}))
''',json.dumps(baseline))['pending']
        before_kill=journal_projection();before_kill_kernel=dual_kernel();assert before_kill==partial and before_kill_kernel==expected(baseline)
        cmd(['systemctl','kill','--kill-whom=main','--signal=SIGKILL',UNIT]);recovered=project(ready('ROLLED_BACK'))
        after_identity=identity(int(props()['MainPID']));recovered_kernel=dual_kernel()
        assert after_identity!=start_identity and recovered_kernel==expected(candidate) and recovered['generation']>partial['generation']
        newer={'ipv4':{'default':'drop','rules':candidate['ipv4']['rules']+[{'port':59994,'verdict':'drop'}]},
               'ipv6':{'default':'drop','rules':candidate['ipv6']['rules']+[{'port':59995,'verdict':'drop'}]}}
        new_pending=peer(common+'''
import sys
state=call('ipv4');new=call('ipv4','/apply',{'op':'dual-newer','generation':state['generation'],'policy':json.loads(sys.argv[1]),'window':20})
Path('/var/lib/rulemoor-validation/dual-new-receipt.json').write_text(json.dumps(new))
print(json.dumps(projection(new)))
''',json.dumps(newer))
        observations=[]
        for path in ('/confirm','/cancel','/apply'):
            before_stale=journal_projection();kernel_before_stale=dual_kernel()
            assert before_stale==new_pending and kernel_before_stale==expected(newer)
            rejected=peer(common+'''
import sys
old=json.loads(Path('/var/lib/rulemoor-validation/dual-old-receipt.json').read_text())
assert old['generation']==json.loads(sys.argv[1])['generation']
path=sys.argv[2]
if path=='/confirm':p=payload(old)
elif path=='/cancel':p={'op':old['op'],'generation':old['generation']}
else:p={'op':'dual-old-base','generation':old['generation'],'policy':json.loads(sys.argv[3]),'window':20}
try:call('ipv4',path,p)
except RuntimeError as e:
 assert str(e).startswith('409:');print(json.dumps({'status':409}))
else:raise AssertionError('Stale request accepted')
''',json.dumps(partial),path,json.dumps(newer))
            after_stale=journal_projection();kernel_after_stale=dual_kernel()
            assert after_stale==before_stale and kernel_after_stale==kernel_before_stale
            observations.append({'path':path,'status':rejected['status'],'before':before_stale,'after':after_stale,
                                 'kernel_before':kernel_before_stale,'kernel_after':kernel_after_stale})
        final=peer(common+'''
new=json.loads(Path('/var/lib/rulemoor-validation/dual-new-receipt.json').read_text())
call('ipv4','/confirm',payload(new));end=call('ipv6','/confirm',payload(new))
print(json.dumps(projection(end)))
''')
        stale={'rejected':[r['path'] for r in observations],'before':new_pending,'after':final,'observations':observations}
        stale_kernel=dual_kernel();assert stale_kernel==expected(newer)
        foreign_after=foreign();assert foreign_after==foreign_before
        return {'mode':'fresh-dual-no-migration','cleanup':cleanup_evidence,'legacy_adoption_exit_code':adoption.returncode,'legacy_table_after_refused_init':legacy_preserved,'baseline':baseline,'blocked_candidate':blocked,'candidate':candidate,
                'initial':initial,'initial_kernel':initial_kernel,'atomic_rejection_exit_code':atomic.returncode,
                'kernel_after_atomic_rejection':atomic_after,'failure':failure,'pending_kernel':pending_kernel,
                'restored':restored,'restored_kernel':restored_kernel,'fresh_after_rollback':fresh_after,'rollback_clock':rollback_clock,
                'same_service_identity_during_timeout':start_identity,'identity_after_timeout':after_timeout_identity,'success':success,'committed_kernel':committed_kernel,
                'ipv6_neighbour_observation':neighbours,'memory':sample,
                'partial_before_kill':before_kill,'kernel_before_kill':before_kill_kernel,'signal':'SIGKILL',
                'identity_after_restart':after_identity,'recovered':recovered,'recovered_kernel':recovered_kernel,
                'stale':stale,'newer':newer,'kernel_after_stale':stale_kernel,'foreign_before':foreign_before,'foreign_after':foreign_after,
                'scope':'Static veth peers, installed systemd service; not WAN, routed PMTU, SLAAC, dual boot or power-loss testing'}
    finally:
        cmd(['systemctl','stop',UNIT],check=False)
        for family in ('ip','ip6'):
            for table in ('rulemoor',foreign_name):cmd(['ip','netns','exec',NS,'nft','delete','table',family,table],check=False)
        for pid in cmd(['ip','netns','pids',client_ns],check=False).stdout.split():
            os.kill(int(pid),signal.SIGKILL)
        cmd(['ip','netns','delete',client_ns],check=False);cmd(['ip','-n',NS,'link','delete','rmds'],check=False)
        assert client_ns not in [line.split()[0] for line in cmd(['ip','netns','list']).stdout.splitlines()]
        assert 'rmds' not in [r['ifname'] for r in json.loads(cmd(['ip','-n',NS,'-j','link','show']).stdout)]
        shutil.rmtree(STATE,ignore_errors=True);shutil.copytree(backup,STATE);shutil.rmtree(backup)
        (CONFIG/'server.pem').write_bytes(cert);(CONFIG/'server.key').write_bytes(key);(CONFIG/'server.key').chmod(0o600)
        # Fixture restores the original known kernel before resuming its legacy unit.
        cmd(['ip','netns','exec',NS,'nft','-f','-'],input=compile_policy(BASE,False))
        drop.unlink(missing_ok=True);cmd(['systemctl','daemon-reload']);cmd(['systemctl','reset-failed',UNIT]);cmd(['systemctl','start',UNIT]);ready()
        cleanup_evidence.update(client_namespace_removed=True,veth_removed=True,legacy_state_and_unit_restored=True)


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


def prepare_dual_boot():
    from tools.dual_recovery import prepare
    return prepare()


def after_dual_boot():
    from tools.dual_recovery import after_boot
    return after_boot()


def dual_held_executor():
    from tools.dual_recovery import held_executor
    return held_executor()


def dual_management_diagnostics():
    from tools.dual_preflight import run
    return run()


def cleanup():
    assert load('ownership') == {'fixture': 'rulemoor-deployment-v1'}
    cmd(['systemctl', 'disable', '--now', UNIT], check=False)
    cmd(['systemctl', 'stop', 'rulemoor-test-namespace.service'], check=False)
    from tools.dual_recovery import cleanup as dual_cleanup
    dual_cleanup_result=dual_cleanup()
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
    return {**dual_cleanup_result,'namespace_removed': True, 'service_stopped_and_removed': True,
            'credentials_and_state_removed': True, 'vm_root_firewall_unchanged': True}


def main():
    p = argparse.ArgumentParser(); p.add_argument('phase', choices=['setup','topology','management_diagnostics','dual_stack','poisoned_journal','restart_limit','crash','held_writer','prepare_pending_boot','after_pending_boot','after_committed_boot','prepare_dual_boot','after_dual_boot','dual_held_executor','dual_management_diagnostics','cleanup'])
    a = p.parse_args(); assert os.geteuid() == 0
    result = globals()[a.phase]()
    if result is not None:
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
