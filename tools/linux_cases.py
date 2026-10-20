"""Real nft/netns/process/TLS validation and measured full API operations."""
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import statistics
import subprocess
import sys
import time
from rulemoor.backend import NftBackend
from rulemoor.core import Controller
from rulemoor.policy import TABLE, expected, compile_policy, canonical

CTL, TARGET = 'rm_control', 'rm_target'
BASE = {'default': 'accept', 'rules': [{'port': 59991, 'verdict': 'drop'}]}
NEXT = {'default': 'accept', 'rules': [{'port': 59992, 'verdict': 'drop'}]}
BLOCK = {'default': 'accept', 'rules': [{'port': 18443, 'verdict': 'drop'}]}
PROCESSES = []


def call(args, ns=None, timeout=8, check=True, **kwargs):
    r = subprocess.run((['ip', 'netns', 'exec', ns] if ns else []) + list(map(str, args)),
                       capture_output=True, text=True, timeout=timeout, **kwargs)
    if check and r.returncode:
        raise AssertionError('Command failed: ' + str(args[:4]) + ': ' + r.stderr[-3000:])
    return r


def start(args, ns=TARGET, env=None):
    p = subprocess.Popen((['ip', 'netns', 'exec', ns] if ns else []) + list(map(str, args)),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         start_new_session=True, env=env)
    PROCESSES.append(p)
    return p


def stop(p):
    if p.poll() is None:
        os.killpg(p.pid, signal.SIGKILL)
    p.communicate(timeout=4)


def wait(fn, timeout=5):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = fn()
        if result:
            return result
        time.sleep(.005)
    raise AssertionError('Observation timeout')


def kernel():
    r = call(['nft', '-j', '-s', 'list', 'table', 'ip', TABLE], ns=TARGET)
    return canonical(json.loads(r.stdout))


def state(root):
    from rulemoor.core import Store
    return Store(root).load()


def reset(root):
    call(['nft', 'delete', 'table', 'ip', TABLE], ns=TARGET, check=False)
    root.mkdir(mode=0o700)
    script = 'from rulemoor.core import Controller; from rulemoor.backend import NftBackend; import json,sys; c=Controller(sys.argv[1],NftBackend()); print(json.dumps(c.initialize(json.loads(sys.argv[2])))); c.close()'
    call([sys.executable, '-c', script, root, json.dumps(BASE)], ns=TARGET)


def client(root, path='/status', payload=None, wrong=False, timeout=7):
    args = [sys.executable, '-m', 'tools.client_driver', 'request', root, '--path', path]
    if payload is not None:
        args += ['--payload', json.dumps(payload)]
    if wrong:
        args += ['--wrong-token']
    return json.loads(call(args, ns=CTL, timeout=timeout).stdout)


def serve(root, fault=None):
    for src in ('cert.pem', 'key.pem', 'token'):
        dest = root / src
        dest.write_bytes((root.parent / src).read_bytes())
        dest.chmod(0o600)
    env = dict(os.environ)
    if fault: env['RULEMOOR_FAULT'] = fault
    p = start([sys.executable, '-m', 'rulemoor.service', '--state', root, 'serve',
               '--listen', '0.0.0.0', '--cert', root / 'cert.pem', '--key', root / 'key.pem',
               '--token-file', root / 'token'], env=env)
    wait(lambda: client(root)['ok'])
    return p


def apply(root, op='change', policy=NEXT, window=2):
    s = client(root)['value']
    result = client(root, '/apply', {'op': op, 'generation': s['generation'], 'policy': policy, 'window': window})
    assert result['ok'], result
    return result['value']


def confirm(root, s):
    return client(root, '/confirm', {k: s[k] for k in ('op', 'generation', 'candidate_digest', 'challenge')})


def topology(parent):
    assert hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal')
    for ns in (CTL, TARGET):
        call(['ip', 'netns', 'add', ns]); call(['ip', '-n', ns, 'link', 'set', 'lo', 'up'])
    call(['ip', 'link', 'add', 'rmc', 'type', 'veth', 'peer', 'name', 'rmt'])
    for dev, ns, addr in [('rmc', CTL, '192.0.2.1/24'), ('rmt', TARGET, '192.0.2.2/24')]:
        call(['ip', 'link', 'set', dev, 'netns', ns])
        call(['ip', '-n', ns, 'addr', 'add', addr, 'dev', dev])
        call(['ip', '-n', ns, 'link', 'set', dev, 'up'])
    call(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
          '-keyout', parent / 'key.pem', '-out', parent / 'cert.pem', '-subj', '/CN=rulemoor-test',
          '-addext', 'subjectAltName=IP:192.0.2.2,IP:127.0.0.1'])
    (parent / 'key.pem').chmod(0o600)
    (parent / 'token').write_text(secrets.token_hex(32)); (parent / 'token').chmod(0o600)
    return {'kernel': platform.release(), 'architecture': platform.machine(), 'python': platform.python_version(),
            'nft': call(['nft', '--version']).stdout.strip(),
            'packages': call(['dpkg-query', '-W', 'nftables', 'libnftables1', 'iproute2', 'openssl']).stdout.splitlines(),
            'scope': 'Real Linux kernel in Colima VM; no host firewall mutation; not native macOS'}


def atomicity(parent):
    root = parent / 'atomic'; reset(root)
    before = kernel()
    call(['nft', '-f', '-'], ns=TARGET, input='table ip rm_unrelated {\n chain retained {\n tcp dport 59999 drop\n }\n}\n')
    unrelated = call(['nft', '-j', '-s', 'list', 'table', 'ip', 'rm_unrelated'], ns=TARGET).stdout
    good = compile_policy(NEXT)
    call(['nft', '-c', '-f', '-'], ns=TARGET, input=good)
    assert kernel() == before
    bad = call(['nft', '-f', '-'], ns=TARGET, input=good + 'add rule ip rulemoor missing tcp dport 1 drop\n', check=False)
    assert bad.returncode != 0 and kernel() == before
    call(['nft', '-f', '-'], ns=TARGET, input=good)
    assert kernel() == expected(NEXT)
    full_policy = {'default': 'accept', 'rules': [{'port': 10000 + i, 'verdict': 'drop'} for i in range(32)]}
    call(['nft', '-f', '-'], ns=TARGET, input=compile_policy(full_policy))
    assert kernel() == expected(full_policy)
    # Independently check compiler/reference across ordered rules and default-drop.
    ordered = {'default': 'drop', 'rules': [{'port': 1234, 'verdict': 'accept'}, {'port': 1234, 'verdict': 'drop'}]}
    call(['nft', '-f', '-'], ns=TARGET, input=compile_policy(ordered))
    assert kernel() == expected(ordered)
    assert call(['nft', '-j', '-s', 'list', 'table', 'ip', 'rm_unrelated'], ns=TARGET).stdout == unrelated
    lock_test = '''
import os, subprocess, time
from rulemoor.backend import lock
fd=lock('/tmp/nft-exec-lock')
p=subprocess.Popen(['nft','-f','-'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(fd,))
os.close(fd); time.sleep(.1)
assert p.poll() is None
try: other=lock('/tmp/nft-exec-lock')
except RuntimeError: pass
else: os.close(other); raise AssertionError('nft closed inherited lock')
p.kill(); p.communicate(timeout=2)
other=lock('/tmp/nft-exec-lock'); os.close(other)
print('verified')
'''
    assert call([sys.executable, '-c', lock_test], ns=TARGET).stdout.strip() == 'verified'
    return {'unrelated_table_unchanged': True, 'nft_exec_lock_inherited': True, 'check_nonmutating': True, 'invalid_batch_exit': bad.returncode, 'invalid_batch_atomic': True,
            'candidate_readback': expected(NEXT), 'ordered_default_drop_readback': kernel()}


def management(parent):
    root = parent / 'management'; reset(root); p = serve(root)
    assert not client(root, wrong=True)['ok']
    persistent = start([sys.executable, '-m', 'tools.client_driver', 'persistent', root], ns=CTL)
    wait(lambda: (root / 'persistent.ready').exists())
    s = apply(root, policy=BLOCK, window=3)
    (root / 'persistent.go').touch()
    old = json.loads(persistent.communicate(timeout=3)[0])
    assert old['ok'] and old['first'] == old['old_status'] == 200 and old['old_confirm'] == 409, old
    # Bound the connect timeout so observation finishes before automatic rollback.
    script = 'import socket; s=socket.socket(); s.settimeout(.2); code=s.connect_ex(("192.0.2.2",18443)); print(code); s.close()'
    fresh_code = int(call([sys.executable, '-c', script], ns=CTL).stdout)
    assert fresh_code != 0
    wait(lambda: state(root)['phase'] == 'ROLLED_BACK', timeout=5)
    recovered = client(root); assert recovered['ok']
    final = state(root)
    assert kernel() == expected(BASE)
    assert final['rollback_started_at'] - s['deadline'] < 1
    assert final['rollback_completed_at'] - s['deadline'] < 3
    positive = apply(root, 'positive', window=2)
    assert confirm(root, positive)['ok']
    time.sleep(max(0, positive['deadline'] - time.clock_gettime(time.CLOCK_BOOTTIME)) + .05)
    assert state(root)['phase'] == 'COMMITTED' and kernel() == expected(NEXT)
    p.send_signal(signal.SIGTERM); out, err = p.communicate(timeout=5); assert p.returncode == 0, err
    return {'unauthorized_rejected': True, 'old_connection': old, 'fresh_blocked_connect_errno': fresh_code,
            'rollback_start_overdue_ms': (final['rollback_started_at'] - s['deadline']) * 1000,
            'rollback_complete_overdue_ms': (final['rollback_completed_at'] - s['deadline']) * 1000,
            'fresh_access_restored': recovered['ok'], 'confirmed_survives_deadline': True}


def crash_matrix(parent):
    rows = []
    for point in ('prepared', 'executor-intent', 'executor-held', 'kernel-applied', 'awaiting-confirm', 'rollback-applied'):
        root = parent / ('crash-' + point); reset(root)
        env = dict(os.environ)
        if point == 'executor-held': env['RULEMOOR_FAULT'] = point
        p = start([sys.executable, '-m', 'tools.agent_driver', 'apply', root, '--hold', point], env=env)
        wait(lambda: (root / (point + '.reached')).exists())
        before = state(root); actual = kernel()
        # Kill the controller only. Orphan executor must retain its inherited lock.
        p.kill(); p.communicate(timeout=3)
        if point == 'executor-held':
            code = 'from rulemoor.backend import lock; import sys; lock(sys.argv[1]+"/writer.lock")'
            assert call([sys.executable, '-c', code, root], ns=TARGET, check=False).returncode != 0
        result = json.loads(call([sys.executable, '-m', 'tools.agent_driver', 'recover', root], ns=TARGET).stdout)
        assert result['phase'] == 'ROLLED_BACK' and kernel() == expected(BASE), result
        again = json.loads(call([sys.executable, '-m', 'tools.agent_driver', 'recover', root], ns=TARGET).stdout)
        assert again['phase'] == 'ROLLED_BACK'
        if point == 'executor-held':
            new_agent = serve(root)
            new_state = apply(root, 'new-generation', window=3)
            assert confirm(root, new_state)['ok']
            (root / (point + '.go')).touch(); time.sleep(.1)
            assert kernel() == expected(NEXT), 'Old writer overwrote newer committed rules'
            new_agent.send_signal(signal.SIGTERM); new_agent.communicate(timeout=4)
        else:
            (root / (point + '.go')).touch(); time.sleep(.03)
            assert kernel() == expected(BASE)
        rows.append({'point': point, 'before_phase': before['phase'], 'after_phase': result['phase'],
                     'generation_before': before['generation'], 'generation_after': result['generation'],
                     'kernel_before': actual, 'baseline_verified': True, 'idempotent': True,
                     'newer_commit_survived_old_release': point == 'executor-held'})
    # Foreign policy at each meaningful interval must remain untouched.
    for point in ('kernel-applied', 'awaiting-confirm'):
        root = parent / ('drift-' + point); reset(root)
        p = start([sys.executable, '-m', 'tools.agent_driver', 'apply', root, '--hold', point])
        wait(lambda: (root / (point + '.reached')).exists())
        call(['nft', 'add', 'rule', 'ip', TABLE, 'input', 'tcp', 'dport', '59994', 'drop'], ns=TARGET)
        foreign = kernel()
        if point == 'kernel-applied':
            (root / (point + '.go')).touch()
            out, err = p.communicate(timeout=4); assert p.returncode == 2, err
        else:
            p.kill(); p.communicate(timeout=3)
            r = call([sys.executable, '-m', 'tools.agent_driver', 'recover', root], ns=TARGET, check=False)
            assert r.returncode == 2
        assert state(root)['phase'] == 'DEGRADED' and kernel() == foreign
        rows.append({'point': 'foreign-' + point, 'after_phase': 'DEGRADED', 'unknown_preserved': True})
    return rows


def service_recovery(parent):
    root = parent / 'service-recovery'; reset(root); p = serve(root)
    s = apply(root, window=4)
    p.kill(); p.communicate(timeout=3)
    p = serve(root)
    assert client(root)['value']['phase'] == 'ROLLED_BACK' and kernel() == expected(BASE)
    assert not confirm(root, s)['ok']
    s = apply(root, 'commit-response-loss', window=2)
    assert confirm(root, s)['ok']
    p.kill(); p.communicate(timeout=3)
    p = serve(root)
    assert client(root)['value']['phase'] == 'COMMITTED' and kernel() == expected(NEXT)
    s = apply(root, 'shutdown', policy=BASE, window=5)
    p.send_signal(signal.SIGTERM); out, err = p.communicate(timeout=5)
    assert p.returncode == 0 and state(root)['phase'] == 'ROLLED_BACK' and kernel() == expected(NEXT), err
    root = parent / 'executor-timeout'; reset(root); p = serve(root, fault='executor-held')
    outcome = client(root, '/apply', {'op': 'timeout', 'generation': 0, 'policy': NEXT, 'window': 5})
    assert not outcome['ok'] and state(root)['phase'] == 'ROLLED_BACK' and kernel() == expected(BASE)
    p.send_signal(signal.SIGTERM); out, err = p.communicate(timeout=5); assert p.returncode == 0, err
    return {'executor_timeout_reported_failure_and_restored': True, 'pending_restart_restored': True, 'stale_confirmation_rejected': True,
            'durably_confirmed_restart_preserved': True, 'graceful_shutdown_restored': True}



def queued_connection_and_lost_response(parent):
    root = parent / 'queued'; reset(root); p = serve(root, fault='prepared')
    sender = start([sys.executable, '-m', 'tools.client_driver', 'request', root,
                    '--path', '/apply', '--payload', json.dumps({'op': 'queued-change', 'generation': 0, 'policy': NEXT, 'window': 5})], ns=CTL)
    wait(lambda: (root / 'prepared.reached').exists())
    queued = start([sys.executable, '-m', 'tools.client_driver', 'queued', root], ns=CTL)
    wait(lambda: (root / 'queued.ready').exists())
    (root / 'prepared.go').touch()
    response = json.loads(sender.communicate(timeout=4)[0]); assert response['ok']
    (root / 'queued.go').touch()
    observed = json.loads(queued.communicate(timeout=4)[0])
    assert observed['ok'] and observed['confirm_status'] == 409, observed
    assert 'snapshot' in observed['reason'], 'Did not exercise the queued-TCP guard'
    p.send_signal(signal.SIGTERM); p.communicate(timeout=4)
    assert state(root)['phase'] == 'ROLLED_BACK'
    root = parent / 'lost-response'; reset(root); p = serve(root, fault='confirm-committed')
    pending = apply(root, window=4)
    confirmer = start([sys.executable, '-m', 'tools.client_driver', 'request', root,
                      '--path', '/confirm', '--payload', json.dumps({k: pending[k] for k in ('op', 'generation', 'candidate_digest', 'challenge')})], ns=CTL)
    wait(lambda: (root / 'confirm-committed.reached').exists())
    p.kill(); p.communicate(timeout=3)
    lost = json.loads(confirmer.communicate(timeout=4)[0]); assert not lost['ok']
    p = serve(root)
    assert state(root)['phase'] == 'COMMITTED' and kernel() == expected(NEXT)
    p.send_signal(signal.SIGTERM); p.communicate(timeout=4)
    return {'queued_before_apply_accepted_later': observed, 'confirmed_response_lost': True,
            'committed_survived_restart': True}



def storage_faults(parent):
    root = parent / 'bounded-filesystem'; root.mkdir(mode=0o700)
    call(['nft', 'delete', 'table', 'ip', TABLE], ns=TARGET, check=False)
    result = json.loads(call([sys.executable, '-m', 'tools.storage_fault', root], ns=TARGET, timeout=15).stdout)
    assert all(result[k] for k in ('enospc_observed', 'reserve_released', 'baseline_restored',
                                   'rollback_journal_verified', 'directory_budget_rejected', 'corrupt_journal_blocked', 'test_tmpfs_unmounted'))
    return result


def summary(samples):
    values = sorted(samples)
    return {'n': len(values), 'median_ms': statistics.median(values), 'min_ms': min(values),
            'max_ms': max(values), 'samples_ms': samples}


def measurement(parent):
    root = parent / 'measured'; reset(root); p = serve(root)
    initial = Path(f'/proc/{p.pid}/status').read_text()
    rows = []
    # One persistent client process measures production CLI transport without Python startup overhead.
    script = r'''
import json, sys, time
from pathlib import Path
from rulemoor.cli import request
root=Path(sys.argv[1]); token=(root/'token').read_text().strip(); ca=str(root/'cert.pem')
def call(path,payload=None): return request('https://192.0.2.2:18443',ca,token,path,payload)
rows=[]
for i in range(10):
 s=call('/status'); candidate={'default':'accept','rules':[{'port':59992 if s['current']['rules'][0]['port']==59991 else 59991,'verdict':'drop'}]}; started=time.perf_counter()
 plan=call('/plan',{'policy':candidate})
 planned=time.perf_counter()
 a=call('/apply',{'op':'measure-'+str(i),'generation':s['generation'],'policy':candidate,'window':5})
 applied=time.perf_counter()
 if i%2:
  final=call('/confirm',{k:a[k] for k in ['op','generation','candidate_digest','challenge']})
 else: final=call('/cancel',{'op':a['op'],'generation':a['generation']})
 ended=time.perf_counter()
 rows.append({'index':i,'plan_ms':(planned-started)*1000,'apply_ms':(applied-planned)*1000,'finalize_ms':(ended-applied)*1000,'action':'confirm' if i%2 else 'cancel','phase':final['phase'],'generation':final['generation'],'before_policy':s['current'],'candidate_policy':candidate})
print(json.dumps(rows))
'''
    rows = json.loads(call([sys.executable, '-c', script, root], ns=CTL, timeout=30).stdout)
    for row in rows:
        assert row['phase'] == ('COMMITTED' if row['action'] == 'confirm' else 'ROLLED_BACK')
    assert kernel() == expected(NEXT)
    current = Path(f'/proc/{p.pid}/status').read_text()
    def field(text, key):
        return int(next(x.split()[1] for x in text.splitlines() if x.startswith(key + ':'))) * 1024
    files = [f for f in root.iterdir() if f.is_file()]
    disk = {'logical_bytes': sum(f.stat().st_size for f in files),
            'allocated_bytes': sum(f.stat().st_blocks * 512 for f in files),
            'files': {f.name: {'logical_bytes': f.stat().st_size, 'allocated_bytes': f.stat().st_blocks * 512}
                      for f in files},
            'scope': 'Private state directory, including test TLS files; filesystem allocation, not container image size'}
    rss = {'initial_bytes': field(initial, 'VmRSS'), 'final_bytes': field(current, 'VmRSS'),
           'worker_high_water_bytes': field(current, 'VmHWM'),
           'scope': 'Agent process only; excludes transient nft children, clients and VM; kernel-reported VmHWM'}
    p.send_signal(signal.SIGTERM); out, err = p.communicate(timeout=5); assert p.returncode == 0, err
    return {'trials': rows, 'plan': summary([r['plan_ms'] for r in rows]),
            'apply': summary([r['apply_ms'] for r in rows]),
            'confirm': summary([r['finalize_ms'] for r in rows if r['action'] == 'confirm']),
            'cancel': summary([r['finalize_ms'] for r in rows if r['action'] == 'cancel']),
            'rss': rss, 'disk': disk, 'warmup': 'Service readiness only; all 10 operation trials retained',
            'timing_scope': 'TLS request/response including connection+handshake, checks, nft and durable journal; one client, loopback-veth path in VM; no baseline speedup claim'}


def cleanup():
    for p in PROCESSES:
        stop(p)
    remaining = []
    for ns in (CTL, TARGET):
        pids = call(['ip', 'netns', 'pids', ns], check=False).stdout.split()
        for pid in pids:
            try: os.kill(int(pid), signal.SIGKILL)
            except ProcessLookupError: pass
        if pids: time.sleep(.1)
        left = call(['ip', 'netns', 'pids', ns], check=False).stdout.split()
        remaining += left
        call(['ip', 'netns', 'delete', ns], check=False)
    names = call(['ip', 'netns', 'list']).stdout.strip()
    return {'remaining_processes': remaining, 'remaining_namespaces': names, 'passed': not remaining and not names}
