"""Same immutable snapshot on native macOS and isolated Linux VM; no host firewall edits."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import signal
import fcntl
import sys
import tempfile
from .evidence import ROOT, manifest, fingerprint, save
from .process import run
from .report import render, verify


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--toolchain', required=True, help='Directory containing colima, limactl and docker')
    p.add_argument('--colima-home', required=True, help='Existing dedicated Colima home')
    p.add_argument('--docker-config', required=True)
    p.add_argument('--profile', default='relay')
    p.add_argument('--output', default='results/local')
    a = p.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Validation interrupted')
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    if platform.system() != 'Darwin' or sys.version_info[:2] != (3, 12):
        p.error('Use native macOS Python 3.12')
    output = Path(a.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        p.error('Output must be a new or empty directory, so stale evidence cannot pass')
    source = manifest(); rid = secrets.token_hex(8)
    host = {'schema': 1, 'run_id': rid, 'passed': False, 'source_sha256': fingerprint(source),
            'source_changed': False, 'stages': [], 'scope': 'Native macOS portable contracts + Colima Linux real kernel'}
    save(output / 'host.json', host)
    (output / 'report.html').write_text('<h1>Validation in progress; no passing result</h1>')
    env = dict(os.environ, PATH=str(Path(a.toolchain).resolve()) + os.pathsep + os.environ.get('PATH', ''),
               COLIMA_HOME=str(Path(a.colima_home).resolve()), DOCKER_CONFIG=str(Path(a.docker_config).resolve()),
               DOCKER_HOST='unix://' + str(Path(a.colima_home).resolve() / a.profile / 'docker.sock'), RULEMOOR_RUN_ID=rid)
    env.pop('DOCKER_CONTEXT', None)
    docker = str(Path(a.toolchain).resolve() / 'docker')
    colima = str(Path(a.toolchain).resolve() / 'colima')
    name = 'rulemoor-check-' + rid
    created = started = False
    def call(label, command, timeout=90, check=True, **kw):
        result = run(command, timeout=timeout, env=env, **kw)
        # Raw logs may contain host paths; retained summary excludes them.
        logs = output / 'private-logs'; logs.mkdir(exist_ok=True)
        (logs / (label + '.log')).write_text(result['stdout'] + result['stderr'])
        host['stages'].append({'name': label, **{k: result[k] for k in ('exit_code', 'timed_out', 'seconds')}})
        save(output / 'host.json', host)
        if check and not result['passed']:
            raise RuntimeError(label + ' failed or timed out')
        return result
    def vm_state(label):
        rows = call(label, [colima, 'list', '--json'])['stdout'].splitlines()
        matches = [json.loads(x) for x in rows if json.loads(x)['name'] == a.profile]
        if len(matches) > 1:
            raise RuntimeError('Ambiguous dedicated profile')
        return matches[0]['status'] if matches else 'Absent'
    profile_fd = os.open(Path(a.colima_home) / ('.rulemoor-' + a.profile + '.lock'), os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(profile_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    linux = native = None
    try:
        with tempfile.TemporaryDirectory(prefix='rulemoor-snapshot-') as tmp:
            snapshot = Path(tmp)
            for file in source:
                dest = snapshot / file; dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / file, dest)
            assert {f: hashlib.sha256((snapshot / f).read_bytes()).hexdigest() for f in source} == source
            unit_env = env.copy(); unit_env['RULEMOOR_UNIT_OUTPUT'] = str(output / 'native.json')
            result = run([sys.executable, '-m', 'tools.unit'], timeout=90, env=unit_env, cwd=snapshot)
            host['stages'].append({'name': 'native-contracts', **{k: result[k] for k in ('exit_code', 'timed_out', 'seconds')}})
            (output / 'native.log').write_text(result['stdout'] + result['stderr'])
            assert result['passed'], 'Native contracts failed'
            native = json.loads((output / 'native.json').read_text())
            assert native['source'] == source
            unit_env['RULEMOOR_MUTATION_OUTPUT'] = str(output / 'mutations.json')
            mutation_result = run([sys.executable, '-m', 'tools.mutations'], timeout=90, env=unit_env, cwd=snapshot)
            host['stages'].append({'name': 'production-mutations', **{k: mutation_result[k] for k in ('exit_code', 'timed_out', 'seconds')}})
            assert mutation_result['passed'], 'Mutation checks failed'
            mutation_data = json.loads((output / 'mutations.json').read_text())
            assert mutation_data['source'] == source and mutation_data['run_id'] == rid
            host['production_mutations'] = mutation_data['rows']
            host['vm_initial_state'] = vm_state('vm-initial')
            assert host['vm_initial_state'] in ('Stopped', 'Absent'), 'Refuse to disturb an already running VM'
            started = True
            call('vm-start', [colima, 'start', a.profile, '--cpu', '4', '--memory', '6', '--disk', '30', '--vm-type', 'vz', '--runtime', 'docker', '--mount', 'none', '--activate=false', '--ssh-config=false', '--ssh-agent=false', '--vz-rosetta=false', '--binfmt=false'], timeout=240)
            call('image-build', [docker, 'build', '--load', '-t', 'rulemoor-validation:local', str(snapshot)], timeout=300)
        image = json.loads(call('image-inspect', [docker, 'image', 'inspect', 'rulemoor-validation:local'])['stdout'])[0]
        host['image'] = {k: image[k] for k in ('Id', 'Architecture', 'Os')}
        created = True
        call('container-create', [docker, 'create', '--name', name, '--init', '--env', 'RULEMOOR_RUN_ID=' + rid,
              '--network', 'none', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'SYS_ADMIN',
              '--security-opt', 'apparmor=unconfined', '--security-opt', 'no-new-privileges',
              '--cpus', '2', '--memory', '768m', '--pids-limit', '128', image['Id']])
        inspection = json.loads(call('container-inspect', [docker, 'inspect', name])['stdout'])[0]
        cfg = inspection['HostConfig']
        host['container'] = {k: cfg[k] for k in ('Privileged', 'NetworkMode', 'CapDrop', 'CapAdd', 'Memory', 'NanoCpus', 'PidsLimit', 'SecurityOpt', 'Init')}
        host['container']['mount_count'] = len(inspection['Mounts'])
        assert not inspection['Mounts'] and not cfg['Privileged'] and cfg['NetworkMode'] == 'none'
        result = call('linux-run', [docker, 'start', '-a', name], timeout=180, check=False)
        state = json.loads(call('container-state', [docker, 'inspect', name])['stdout'])[0]['State']
        host['container_exit'] = {k: state[k] for k in ('ExitCode', 'OOMKilled', 'Running', 'Error')}
        call('export', [docker, 'cp', name + ':/app/results/.', str(output)])
        linux = json.loads((output / 'linux.json').read_text())
        assert result['passed'] and state['ExitCode'] == 0 and not state['OOMKilled'] and not state['Running'] and not state['Error']
        assert linux['passed'], 'Linux validation failed'
        host['passed'] = True
    except BaseException as exc:
        host['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        try:
            if created:
                result = call('container-remove', [docker, 'rm', '-f', name], check=False)
                host['container_removed'] = result['passed']
            if started:
                call('vm-stop', [colima, 'stop', a.profile], timeout=120)
                host['vm_final_state'] = vm_state('vm-final')
        except BaseException as exc:
            host['cleanup_error'] = type(exc).__name__
        host['source_changed'] = manifest() != source
        host['passed'] = bool(host['passed'] and not host['source_changed'] and host.get('container_removed')
                              and host.get('vm_final_state') == 'Stopped' and 'cleanup_error' not in host)
        if host['passed']:
            try:
                verify(linux, native, host, source)
                # Prove the verifier rejects broken source/run IDs, omitted failures and cleanup.
                mutations = []
                for target, key, changed in [('linux', 'run_id', 'stale'), ('linux', 'passed', False),
                                             ('linux', 'source', {}), ('native', 'tests', 0),
                                             ('host', 'container_removed', False), ('host', 'stages', []),
                                             ('linux', 'cases', []), ('native', 'test_ids', []),
                                             ('host', 'production_mutations', []), ('linux', 'source_sha256', 'wrong')]:
                    l, n, h = copy.deepcopy((linux, native, host))
                    {'linux': l, 'native': n, 'host': h}[target][key] = changed
                    try:
                        verify(l, n, h, source)
                    except AssertionError:
                        mutations.append({'target': target, 'field': key, 'rejected': True})
                    else:
                        raise RuntimeError('Verifier accepted corrupted evidence')
                for name in ('fencing-retirement', 'fencing-identical-policies', 'recovery-omitted', 'timing-summary',
                             'fencing-missing-identity', 'fencing-empty-identity', 'fencing-missing-policy'):
                    l, n, h = copy.deepcopy((linux, native, host))
                    if name.startswith('fencing'):
                        f = l['cases'][2]['evidence'][2]['fencing']
                        if name == 'fencing-missing-identity':
                            del f['old_executor_identity']
                        elif name == 'fencing-empty-identity':
                            f['old_executor_identity'] = {}
                        elif name == 'fencing-missing-policy':
                            f['old_candidate'] = None
                        elif name == 'fencing-retirement':
                            f['old_executor_exited'] = False
                        else:
                            from rulemoor.policy import expected
                            f['new_candidate'] = f['old_candidate']
                            f['kernel_after_release'] = expected(f['old_candidate'])
                    elif name == 'recovery-omitted':
                        l['cases'][3]['evidence'] = {}
                    else:
                        l['cases'][-1]['evidence']['apply']['median_ms'] += 1
                    try:
                        verify(l, n, h, source)
                    except AssertionError:
                        mutations.append({'target': 'linux', 'field': name, 'rejected': True})
                    else:
                        raise RuntimeError('Verifier accepted corrupted ' + name)
                host['evidence_mutations'] = mutations
            except Exception as exc:
                host.update(passed=False, verification_error=type(exc).__name__ + ': ' + str(exc))
        save(output / 'host.json', host)
        combined = {'passed': host['passed'], 'cases': linux.get('cases', []) if linux else [],
                    'host': host, 'native': native, 'linux': linux}
        save(output / 'combined.json', combined)
        (output / 'report.html').write_text(render(combined))
        print(json.dumps({'passed': host['passed'], 'run_id': rid, 'error': host.get('error'),
                          'verification_error': host.get('verification_error'), 'source_sha256': fingerprint(source)}), flush=True)
    raise SystemExit(0 if host['passed'] else 1)


if __name__ == '__main__':
    main()
