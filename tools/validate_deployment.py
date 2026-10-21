"""One-command actual systemd/VM reboot validation; never a container substitute."""
import argparse
import copy
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import sys
import tarfile
import tempfile
import time
import fcntl
from .evidence import ROOT, manifest, fingerprint, save
from .process import run
from .deployment_report import verify, render, negative_controls


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--toolchain', default=str(ROOT / 'results/local/toolchain/bin'))
    p.add_argument('--colima-home', required=True, help='Dedicated existing Colima home; VM will be restarted three times')
    p.add_argument('--profile', default='relay')
    p.add_argument('--output', required=True)
    p.add_argument('--allow-vm-restarts', action='store_true', required=True)
    a = p.parse_args()
    out = Path(a.output).resolve(); out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()): p.error('Output must be new/empty')
    bins = Path(a.toolchain).resolve(); home = Path(a.colima_home).resolve()
    if not home.is_dir(): p.error('Dedicated existing Colima home required')
    source = manifest(); rid = secrets.token_hex(8)
    value = {'schema':1, 'run_id':rid, 'recorded_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'passed':False, 'source':source, 'source_sha256':fingerprint(source), 'source_changed':False,
             'scope':{'execution':'Actual systemd in Colima Linux VM; isolated test network namespace',
                      'reboot_method':'Orderly Colima VM stop/start; pending agent stopped using SIGKILL',
                      'power_loss_tested':False, 'native_macos_deployment_tested':False},
             'stages':[], 'cases':[]}
    env = dict(os.environ, COLIMA_HOME=str(home), PATH=str(bins)+os.pathsep+os.environ.get('PATH',''))
    env.pop('DOCKER_CONTEXT', None)
    colima = str(bins / 'colima')
    started = uploaded = cleanup_done = False
    lockfd = os.open(home / ('.rulemoor-' + a.profile + '.lock'), os.O_CREAT|os.O_RDWR, 0o600)
    fcntl.flock(lockfd, fcntl.LOCK_EX|fcntl.LOCK_NB)
    def persist():
        save(out / 'deployment.json', value); (out / 'report.html').write_text(render(value))
    def call(label, args, timeout=90, **kw):
        result = run(args, timeout=timeout, env=env, **kw)
        logs = out / 'private-logs'; logs.mkdir(exist_ok=True)
        (logs / (label + '.log')).write_text(result['stdout']+result['stderr'])
        value['stages'].append({'name':label, **{k:result[k] for k in ('exit_code','timed_out','seconds')}})
        persist()
        if not result['passed']: raise RuntimeError(label + ' failed or timed out')
        return result['stdout']
    def ssh(label, args, **kw):
        return call(label,[colima,'--profile',a.profile,'ssh','--',*args],**kw)
    def state(label):
        rows = [json.loads(x) for x in call(label,[colima,'list','--json']).splitlines()]
        matched = [r for r in rows if r['name']==a.profile]
        assert len(matched)==1, 'An existing dedicated stopped VM is required'
        return matched[0]['status']
    def start(label):
        return call(label,[colima,'start',a.profile,'--cpu','4','--memory','6','--disk','30','--vm-type','vz','--runtime','docker','--mount','none','--activate=false','--ssh-config=false','--ssh-agent=false','--vz-rosetta=false','--binfmt=false'],timeout=240)
    def phase(name, setup=False):
        row = {'name':name,'passed':False}; value['cases'].append(row); persist()
        try:
            if setup:
                args = ['sudo','sh','-c','cd /opt/rulemoor-validation && exec python3 -m tools.deployment_guest setup']
            else:
                args = ['sudo','/opt/rulemoor/venv/bin/python','/opt/rulemoor-validation/tools/deployment_guest.py',name]
            data = json.loads(ssh('guest-'+name,args,timeout=120).strip())
            row.update(evidence=data,passed=True); persist()
            return data
        except BaseException as exc:
            row['error']=type(exc).__name__; persist(); raise
    persist()
    for sig in (signal.SIGINT,signal.SIGTERM):
        signal.signal(sig,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        value['vm_initial_state']=state('vm-initial'); assert value['vm_initial_state']=='Stopped'
        started=True; start('vm-start')
        preflight = ssh('preflight',['sudo','sh','-c',
            'test ! -e /opt/rulemoor-validation && test ! -e /opt/rulemoor && test ! -e /var/lib/rulemoor && test ! -e /var/lib/rulemoor-validation && test ! -e /etc/rulemoor && test ! -e /etc/systemd/system/rulemoor.service && test -z "$(docker ps -q)" && test "$(cat /proc/1/comm)" = systemd'])
        ssh('guest-prerequisites',['sudo','sh','-c','DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv nftables iproute2 openssl'],timeout=180)
        with tempfile.TemporaryDirectory(prefix='rulemoor-deployment-') as tmp:
            snapshot=Path(tmp)
            for f in [*source,'LICENSE','THIRD_PARTY_NOTICES.md','README.md']:
                dest=snapshot/f; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(ROOT/f,dest)
            assert {f:hashlib.sha256((snapshot/f).read_bytes()).hexdigest() for f in source}==source
            call('wheel-build',[sys.executable,'-m','build','--wheel','--outdir',str(snapshot/'wheel')],timeout=120,cwd=snapshot)
            wheel=next((snapshot/'wheel').glob('*.whl')); shutil.copyfile(wheel,snapshot/wheel.name)
            value['wheel_sha256']=hashlib.sha256(wheel.read_bytes()).hexdigest()
            (snapshot/'fixture-run-id').write_text(rid)
            buffer=io.BytesIO()
            with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
                for f in [*source,'LICENSE','THIRD_PARTY_NOTICES.md','README.md',wheel.name,'fixture-run-id']:
                    archive.add(snapshot/f,arcname=f,recursive=False)
            import base64
            bootstrap="import base64,io,tarfile,sys,pathlib; p=pathlib.Path('/opt/rulemoor-validation');p.mkdir(mode=0o700);tarfile.open(fileobj=io.BytesIO(base64.b64decode(sys.stdin.read()))).extractall(p,filter='data')"
            transfer = snapshot / 'transfer.b64'
            transfer.write_text(base64.b64encode(buffer.getvalue()).decode())
            with transfer.open() as stream:
                ssh('snapshot-upload',['sudo','python3','-c',bootstrap],stdin=stream,timeout=60)
            uploaded=True
        phase('setup',setup=True)
        phase('management_diagnostics'); phase('dual_stack')
        phase('poisoned_journal'); phase('restart_limit')
        phase('crash'); phase('held_writer'); phase('prepare_pending_boot')
        began=time.monotonic_ns(); call('pending-vm-stop',[colima,'stop',a.profile],timeout=120); start('pending-vm-start')
        phase('after_pending_boot'); ended=time.monotonic_ns()
        value['pending_vm_restart_clock']={'clock':'monotonic_ns','started_ns':began,'finished_ns':ended}
        value['pending_vm_restart_control_seconds']=(ended-began)/1e9
        began=time.monotonic_ns(); call('committed-vm-stop',[colima,'stop',a.profile],timeout=120); start('committed-vm-start')
        phase('after_committed_boot'); ended=time.monotonic_ns()
        value['committed_vm_restart_clock']={'clock':'monotonic_ns','started_ns':began,'finished_ns':ended}
        value['committed_vm_restart_control_seconds']=(ended-began)/1e9
        phase('prepare_dual_boot')
        began=time.monotonic_ns();call('dual-pending-vm-stop',[colima,'stop',a.profile],timeout=120);start('dual-pending-vm-start')
        phase('after_dual_boot');ended=time.monotonic_ns()
        value['dual_pending_vm_restart_clock']={'clock':'monotonic_ns','started_ns':began,'finished_ns':ended}
        value['dual_pending_vm_restart_control_seconds']=(ended-began)/1e9
        phase('dual_held_executor'); phase('dual_management_diagnostics')
        phase('cleanup'); cleanup_done=True
        value['passed']=True
    except BaseException as exc:
        value['error']=type(exc).__name__+': '+str(exc).replace(str(ROOT),'<checkout>').replace(str(home),'<colima-home>')
    finally:
        for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,signal.SIG_IGN)
        if uploaded:
            try:
                if not cleanup_done:
                    # Only touch paths after checking this run's fixture ownership marker.
                    ssh('cleanup-retry',['sudo','sh','-c',
                        'test -f /var/lib/rulemoor-validation/ownership.json && cd /opt/rulemoor-validation && exec python3 -m tools.deployment_guest cleanup'],timeout=90)
                ssh('snapshot-remove',['sudo','python3','-c',
                    "import pathlib,shutil,sys;p=pathlib.Path('/opt/rulemoor-validation');assert (p/'fixture-run-id').read_text()==sys.argv[1];shutil.rmtree(p)",rid])
                value['source_snapshot_removed']=True
            except BaseException as exc:
                value['cleanup_error']=type(exc).__name__
        if started:
            try:
                call('vm-final-stop',[colima,'stop',a.profile],timeout=120)
                value['vm_final_state']=state('vm-final')
            except BaseException as exc:value['vm_cleanup_error']=type(exc).__name__
        value['source_changed']=manifest()!=source
        value['passed']=bool(value['passed'] and value.get('source_snapshot_removed') and value.get('vm_final_state')=='Stopped'
                             and not value['source_changed'] and 'cleanup_error' not in value and 'vm_cleanup_error' not in value)
        if value['passed']:
            try:
                verify(value,source)
                value['evidence_controls']=negative_controls(value,source)
            except BaseException as exc:value.update(passed=False,verification_error=type(exc).__name__)
        persist(); os.close(lockfd)
    print(json.dumps({k:value.get(k) for k in ('passed','run_id','error','cleanup_error','verification_error','vm_final_state')}))
    raise SystemExit(0 if value['passed'] else 1)


if __name__=='__main__':main()
