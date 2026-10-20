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
            'CapabilityBoundingSet', 'NetworkNamespacePath', 'MemoryCurrent']
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
    return True


def commit_under_stale_requests(old, op, policy):
    fresh = apply(op, policy)
    stale_rejected(old)
    status = request()
    assert status['phase'] == 'AWAITING_CONFIRM' and status['generation'] == fresh['generation']
    assert kernel() == expected(policy)
    committed = confirm(fresh)
    stale_rejected(old)
    assert committed['phase'] == 'COMMITTED' and kernel() == expected(policy)
    return committed


def memory():
    p = props(); pid = int(p['MainPID'])
    fields = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    return {'agent_rss_bytes': int(fields['VmRSS'].split()[0]) * 1024,
            'agent_vmhwm_bytes': int(fields['VmHWM'].split()[0]) * 1024,
            'service_cgroup_memory_current_bytes': int(p['MemoryCurrent']),
            'scope': 'Linux VM installed daemon; VmHWM excludes nft children/client/VM; cgroup includes service children and charged memory, not VM'}


def topology():
    assert FIXTURE.is_dir()
    cmd(['ip', 'netns', 'add', NS]); cmd(['ip', '-n', NS, 'link', 'set', 'lo', 'up'])
    assert kernel() is None
    save('pre-agent-boot', {'boot_id': boot_id(), 'owned_table_absent': True})


def setup():
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert not STATE.exists() and not CONFIG.exists() and not Path('/opt/rulemoor').exists()
    FIXTURE.mkdir(mode=0o700)
    save('ownership', {'fixture': 'rulemoor-deployment-v1'})
    save('root-rules-before', {'sha256': root_rules_digest()})
    cmd(['python3', '-m', 'venv', '/opt/rulemoor/venv'])
    wheel = next(SOURCE.glob('*.whl'))
    cmd([PYTHON, '-m', 'pip', 'install', '--no-deps', wheel])
    # Compare every installed module against the immutable source snapshot.
    code = "import rulemoor,pathlib;print(pathlib.Path(rulemoor.__file__).parent)"
    installed = Path(cmd([PYTHON, '-c', code]).stdout.strip())
    for p in (SOURCE / 'rulemoor').glob('*.py'):
        assert (installed / p.name).read_bytes() == p.read_bytes()
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
            'nft': cmd(['nft', '--version']).stdout.strip(), 'installed_modules_match_source': True,
            'production_unit_sha256': hashlib.sha256(Path('/etc/systemd/system/rulemoor.service').read_bytes()).hexdigest(),
            'namespace_only_override': True, 'unit_properties': {k:v for k,v in p.items() if k != 'InvocationID'},
            'boot_id': boot_id(), 'memory': memory()}


def crash():
    old = apply('crash-pending', NEXT); before = props(); pid = int(before['MainPID'])
    assert kernel() == expected(NEXT)
    began = time.monotonic()
    cmd(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', UNIT])
    s = ready('ROLLED_BACK'); after = props()
    assert after['InvocationID'] != before['InvocationID'] and int(after['MainPID']) != pid
    assert int(after['NRestarts']) > int(before['NRestarts']) and s['generation'] > old['generation']
    restored_kernel = kernel()
    assert restored_kernel == expected(BASE)
    observed = (time.monotonic() - began) * 1000
    newer = commit_under_stale_requests(old, 'after-crash-new', NEW)
    assert kernel() == expected(NEW) and newer['phase'] == 'COMMITTED'
    return {'automatic_systemd_restart': True, 'restart_count_before': int(before['NRestarts']),
            'restart_count_after': int(after['NRestarts']), 'main_pid_changed': True,
            'pending_baseline_restored': True, 'stale_requests_rejected_during_new_pending': True, 'stale_requests_rejected_after_new_commit': True,
            'new_policy_preserved': True, 'kill_to_tls_ready_observed_ms': observed, 'memory': memory(),
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
        newer = commit_under_stale_requests(old, 'after-held-new', BASE)
        (STATE / 'executor-held.go').touch()
        time.sleep(2.1)
        stale_rejected(old)
        assert kernel() == expected(BASE) and newer['phase'] == 'COMMITTED'
        return {'test_only_fault_override': True, 'old_executor_identity': old_identity,
                'old_executor_retired': True, 'systemd_cgroup_restart_observed': True,
                'known_baseline_restored': True, 'late_release_did_not_overwrite_new_policy': True,
                'stale_requests_rejected_during_new_pending': True, 'stale_requests_rejected': True, 'new_policy_preserved': True,
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
    save('pending-boot-before', {'boot_id': boot_id(), 'generation': old['generation']})
    return {'boot_id': boot_id(), 'journal_pending_after_service_stop': True,
            'candidate_still_installed': True, 'graceful_rollback_deliberately_bypassed': True,
            'pending_generation': old['generation'], 'kernel_before_shutdown': kernel(),
            'unit_enabled': cmd(['systemctl', 'is-enabled', UNIT]).stdout.strip() == 'enabled'}


def after_pending_boot():
    old = load('pending-receipt'); before = load('pending-boot-before'); pre = load('pre-agent-boot')
    assert boot_id() != before['boot_id'] and pre['boot_id'] == boot_id() and pre['owned_table_absent']
    s = ready('ROLLED_BACK')
    restored_kernel = kernel()
    assert s['boot'] == boot_id() and s['generation'] > before['generation'] and restored_kernel == expected(BASE)
    fresh = commit_under_stale_requests(old, 'post-boot-new', NEW)
    assert fresh['phase'] == 'COMMITTED' and kernel() == expected(NEW)
    save('committed-boot-before', {'boot_id': boot_id(), 'generation': fresh['generation']})
    return {'boot_id_before': before['boot_id'], 'boot_id_after': boot_id(),
            'pre_agent_table_absent': True, 'pending_baseline_restored': True,
            'generation_advanced': True, 'stale_requests_rejected_during_new_pending': True, 'stale_requests_rejected_after_new_commit': True,
            'new_policy_preserved': True, 'vm_uptime_after_validation_seconds': time.clock_gettime(time.CLOCK_BOOTTIME),
            'memory': memory(), 'old_generation': before['generation'], 'recovered_generation': s['generation'],
            'new_generation': fresh['generation'], 'restored_kernel': restored_kernel, 'kernel_after_stale': kernel()}


def after_committed_boot():
    before = load('committed-boot-before'); pre = load('pre-agent-boot')
    assert boot_id() != before['boot_id'] and pre['boot_id'] == boot_id() and pre['owned_table_absent']
    s = ready('COMMITTED')
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
            'pre_agent_table_absent': True, 'committed_policy_restored': True,
            'generation_advanced': True, 'old_base_rejected': True,
            'same_boot_foreign_policy_preserved': True, 'memory': memory(),
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
    p = argparse.ArgumentParser(); p.add_argument('phase', choices=['setup','topology','crash','held_writer','prepare_pending_boot','after_pending_boot','after_committed_boot','cleanup'])
    a = p.parse_args(); assert os.geteuid() == 0
    result = globals()[a.phase]()
    if result is not None:
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
