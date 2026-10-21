"""Isolated VM fixtures for installed dual-stack recovery; no alternate controller."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from . import deployment_guest as g
from rulemoor.backend import identity, boot_id, lock
from rulemoor.policy import expected

CLIENT = 'rm_recovery_client'
SERVER_DEV, CLIENT_DEV = 'rmrs', 'rmrc'
MARKER = 'dual-recovery-mode'


def policy(v4, v6):
    return {family:{'default':'drop','rules':[{'port':18443,'verdict':'accept'},
                                            {'port':port,'verdict':'drop'}]}
            for family,port in (('ipv4',v4),('ipv6',v6))}


INITIAL = policy(60000,60000)
BASELINE = policy(60001,60002)
PENDING = policy(60011,60012)
SUCCESSOR = policy(60021,60022)
LATE = policy(60031,60032)
FINAL = policy(60041,60042)


def families():
    result={}
    for family in ('ip','ip6'):
        p=g.cmd(['ip','netns','exec',g.NS,'nft','-j','-s','list','table',family,'rulemoor'],check=False)
        if p.returncode:
            assert 'No such file or directory' in p.stderr
            result[family]=None
        else:
            from rulemoor.policy import canonical
            result[family]=canonical(json.loads(p.stdout))
    return result


def kernel():
    rows=families()
    return sum((rows[f] or [] for f in ('ip','ip6')),[]) or None


def topology():
    """Called by the real boot dependency before the Agent starts."""
    assert g.load(MARKER)=={'mode':'dual-recovery-v1'}
    assert CLIENT not in [line.split()[0] for line in g.cmd(['ip','netns','list']).stdout.splitlines()]
    g.cmd(['ip','netns','add',CLIENT]);g.cmd(['ip','-n',CLIENT,'link','set','lo','up'])
    g.cmd(['ip','-n',g.NS,'link','add',SERVER_DEV,'type','veth','peer','name',CLIENT_DEV,'netns',CLIENT])
    for ns,dev,v4,v6 in ((g.NS,SERVER_DEV,'192.0.2.22/24','2001:db8:55::2/64'),
                          (CLIENT,CLIENT_DEV,'192.0.2.21/24','2001:db8:55::1/64')):
        g.cmd(['ip','-n',ns,'addr','add',v4,'dev',dev])
        g.cmd(['ip','-n',ns,'-6','addr','add',v6,'dev',dev,'nodad'])
        g.cmd(['ip','-n',ns,'link','set',dev,'up'])


COMMON='''import json,sys
from pathlib import Path
from rulemoor.cli import request
urls={'ipv4':'https://192.0.2.22:18443','ipv6':'https://[2001:db8:55::2]:18443'}
ca='/etc/rulemoor/server.pem';token=Path('/etc/rulemoor/token').read_text().strip()
def call(f,path='/status',payload=None):return request(urls[f],ca,token,path,payload,family=f)
def projection(s):return {k:s[k] for k in ('phase','generation','op','boot','current','baseline','candidate','confirmed_families') if k in s}
def payload(s):return {k:s[k] for k in ('op','generation','candidate_digest','challenge')}
'''


def peer(code,*args):
    return json.loads(g.cmd(['ip','netns','exec',CLIENT,g.PYTHON,'-I','-c',COMMON+code,*args],cwd='/',timeout=20).stdout)


def apply(op, p, window=60):
    s=g.request()
    return g.request('/apply',{'op':op,'generation':s['generation'],'policy':p,'window':window})


def confirm(s,family):
    return peer("s=json.loads(sys.argv[1]);print(json.dumps(call(sys.argv[2],'/confirm',payload(s))))",json.dumps(s),family)


def commit(op,p):
    s=apply(op,p);partial=confirm(s,'ipv4');committed=confirm(s,'ipv6')
    assert partial['phase']=='AWAITING_CONFIRM' and partial['confirmed_families']==['ipv4']
    assert committed['phase']=='COMMITTED' and committed['confirmed_families']==['ipv4','ipv6']
    return committed


def prepare():
    """Explicit fresh disposable fixture, followed by normal dual API transactions."""
    g.cmd(['systemctl','stop',g.UNIT]);assert g.props()['MainPID']=='0'
    shutil.copytree(g.STATE,g.FIXTURE/'legacy-before-dual-recovery');shutil.rmtree(g.STATE)
    for family in ('ip','ip6'):
        g.cmd(['ip','netns','exec',g.NS,'nft','delete','table',family,'rulemoor'],check=False)
    g.save(MARKER,{'mode':'dual-recovery-v1'});topology()
    g.cmd(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
           '-keyout',g.CONFIG/'server.key','-out',g.CONFIG/'server.pem','-subj','/CN=rulemoor-dual-recovery',
           '-addext','subjectAltName=IP:127.0.0.1,IP:::1,IP:192.0.2.22,IP:2001:db8:55::2'])
    (g.CONFIG/'server.key').chmod(0o600)
    g.save('dual-initial-policy',INITIAL)
    g.cmd(['ip','netns','exec',g.NS,'/opt/rulemoor/venv/bin/rulemoor-agent','--state',g.STATE,
           'init','--dual-stack','--policy',g.FIXTURE/'dual-initial-policy.json'])
    original=next(line for line in Path('/etc/systemd/system/rulemoor.service').read_text().splitlines() if line.startswith('ExecStart='))
    Path('/etc/systemd/system/rulemoor.service.d/40-dual-recovery.conf').write_text(
        '[Service]\nExecStart=\n'+original.replace('--listen 127.0.0.1','--listen 0.0.0.0')+' --dual-stack --listen6 ::\n')
    g.cmd(['systemctl','daemon-reload']);g.cmd(['systemctl','reset-failed',g.UNIT]);g.cmd(['systemctl','start',g.UNIT]);g.ready('COMMITTED')
    committed=commit('dual-recovery-baseline',BASELINE);baseline_kernel=kernel();assert baseline_kernel==expected(BASELINE)
    old=apply('dual-pending-before-boot',PENDING);partial=confirm(old,'ipv4')
    g.save('dual-reboot-private-receipt',old)  # challenge remains inside private fixture
    before_stop=g.journal_projection();candidate_kernel=kernel()
    assert before_stop==g.project(partial) and candidate_kernel==expected(PENDING)
    drop=Path('/etc/systemd/system/rulemoor.service.d/91-test-kill.conf')
    drop.write_text('[Service]\nKillSignal=SIGKILL\nRestart=no\n')
    try:
        g.cmd(['systemctl','daemon-reload']);g.cmd(['systemctl','stop',g.UNIT])
    finally:
        drop.unlink(missing_ok=True);g.cmd(['systemctl','daemon-reload'])
    after_stop=g.journal_projection();after_kernel=kernel();stopped=g.props()
    assert after_stop==before_stop and after_kernel==candidate_kernel and stopped['MainPID']=='0'
    row={'boot_id':boot_id(),'committed_baseline':g.project(committed),'baseline_kernel':baseline_kernel,
         'pending_before_stop':before_stop,'pending_after_stop':after_stop,'kernel_before_stop':candidate_kernel,
         'kernel_after_stop':after_kernel,'stop_method':'SIGKILL with Restart=no; no graceful rollback',
         'unit_after_stop':{k:stopped[k] for k in ('MainPID','ActiveState','KillMode')},
         'unit_enabled':g.cmd(['systemctl','is-enabled',g.UNIT]).stdout.strip()=='enabled'}
    g.save('dual-boot-before',row)
    return row


def stale_requests(old, paths):
    observations=[]
    for path in paths:
        before=g.journal_projection();before_kernel=kernel()
        s=peer('''old=json.loads(sys.argv[1]);path=sys.argv[2]
if path=='/confirm':p=payload(old)
elif path=='/cancel':p={'op':old['op'],'generation':old['generation']}
else:p={'op':'dual-stale-base','generation':old['generation'],'policy':json.loads(sys.argv[3]),'window':60}
try:call('ipv4',path,p)
except RuntimeError as e:
 assert str(e).startswith('409:');print(json.dumps({'status':409}))
else:raise AssertionError('Stale operation accepted')
''',json.dumps(old),path,json.dumps(LATE))
        after=g.journal_projection();after_kernel=kernel()
        assert before==after and before_kernel==after_kernel
        observations.append({'path':path,'status':s['status'],'before':before,'after':after,
                             'kernel_before':before_kernel,'kernel_after':after_kernel})
    return observations


def after_boot():
    before=g.load('dual-boot-before');pre=g.load('pre-agent-boot');old=g.load('dual-reboot-private-receipt')
    assert before['boot_id']!=boot_id() and pre['boot_id']==boot_id()
    assert pre['dual_tables']=={'ip':None,'ip6':None}
    assert pre['journal']==before['pending_after_stop']
    restored=g.project(g.ready('ROLLED_BACK'));restored_kernel=kernel()
    assert restored['boot']==boot_id() and restored['generation']>old['generation']
    assert restored_kernel==expected(BASELINE)
    fresh=peer("print(json.dumps({f:projection(call(f)) for f in urls}))")
    assert fresh['ipv4']==fresh['ipv6']==restored
    newer=apply('dual-after-boot-successor',SUCCESSOR)
    observations=stale_requests(old,('/confirm','/cancel','/apply'))
    assert kernel()==expected(SUCCESSOR)
    partial=confirm(newer,'ipv4');committed=confirm(newer,'ipv6')
    assert partial['phase']=='AWAITING_CONFIRM' and committed['phase']=='COMMITTED'
    committed_kernel=kernel();assert committed_kernel==expected(SUCCESSOR)
    return {'boot_id_before':before['boot_id'],'boot_id_after':boot_id(),
            'journal_before_agent':pre['journal'],'tables_before_agent':pre['dual_tables'],
            'restored':restored,'restored_kernel':restored_kernel,'fresh_tls':fresh,
            'successor_pending':g.project(newer),'stale_observations':observations,
            'successor_committed':g.project(committed),'committed_kernel':committed_kernel,'memory':g.memory()}


def writer_locked():
    try:fd=lock(g.STATE/'writer.lock')
    except RuntimeError as exc:
        assert isinstance(exc.__context__,BlockingIOError)
        return True
    os.close(fd);return False


def held_executor():
    """Force a real orphan outside systemd, then exercise production pidfd retirement."""
    baseline=g.project(g.request());assert baseline['phase']=='COMMITTED' and kernel()==expected(SUCCESSOR)
    g.cmd(['systemctl','stop',g.UNIT]);assert g.props()['MainPID']=='0'
    for name in ('executor-held.reached','executor-held.go'):(g.STATE/name).unlink(missing_ok=True)
    code='''import sys,json
from rulemoor.core import Controller
from rulemoor.backend import NftBackend
c=Controller('/var/lib/rulemoor',NftBackend(dual_stack=True))
c.start();c.apply('dual-held-orphan',c.s['generation'],json.loads(sys.argv[1]),60)
'''
    env=dict(os.environ,RULEMOOR_FAULT='executor-held');env.pop('PYTHONPATH',None);env.pop('PYTHONHOME',None)
    agent=subprocess.Popen(['ip','netns','exec',g.NS,g.PYTHON,'-I','-c',code,json.dumps(LATE)],
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True,env=env,cwd='/')
    old_identity=None
    try:
        g.wait(lambda:(g.STATE/'executor-held.reached').exists(),timeout=1.5)
        pending=g.journal_projection()
        from rulemoor.core import Store
        full=Store(g.STATE).load();token=full['executor_token']
        rec=json.loads((g.STATE/('executor-'+token+'.json')).read_text())
        old_identity={k:rec[k] for k in ('pid','start_ticks','boot')}
        assert identity(rec['pid'])==old_identity and pending['phase']=='APPLYING'
        agent_identity=identity(agent.pid);assert agent_identity is not None
        orphan_cgroup=Path('/proc',str(rec['pid']),'cgroup').read_text().splitlines()
        assert not any('/system.slice/rulemoor.service' in line for line in orphan_cgroup)
        os.kill(agent.pid,signal.SIGKILL);agent.communicate(timeout=3)
        survived=identity(rec['pid']);held_lock=writer_locked();pre_kernel=kernel()
        assert survived==old_identity and held_lock and pre_kernel==expected(SUCCESSOR)
        g.cmd(['systemctl','start',g.UNIT]);restored=g.project(g.ready('ROLLED_BACK'))
        retired_identity=identity(rec['pid']);free_lock=not writer_locked();restored_kernel=kernel()
        assert retired_identity!=old_identity and free_lock and restored_kernel==expected(SUCCESSOR)
        assert restored['generation']>pending['generation']
        new=apply('dual-after-orphan-new',FINAL)
        pending_observations=stale_requests(full,('/cancel','/apply'))
        partial=confirm(new,'ipv4');committed=confirm(new,'ipv6')
        assert partial['phase']=='AWAITING_CONFIRM' and committed['phase']=='COMMITTED'
        committed_observations=stale_requests(full,('/cancel','/apply'))
        before_release=g.journal_projection();kernel_before_release=kernel();identity_before_release=identity(rec['pid'])
        began=time.monotonic_ns();(g.STATE/'executor-held.go').touch();time.sleep(2.1);ended=time.monotonic_ns()
        after_release=g.journal_projection();kernel_after_release=kernel();identity_after_release=identity(rec['pid'])
        assert before_release==after_release==g.project(committed)
        assert kernel_before_release==kernel_after_release==expected(FINAL)
        assert identity_before_release!=old_identity and identity_after_release!=old_identity
        return {'baseline':baseline,'pending':pending,'held_agent_identity':agent_identity,
                'old_executor_identity':old_identity,'old_executor_cgroup':orphan_cgroup,
                'after_agent_kill_identity':survived,'writer_lock_held_before_recovery':held_lock,
                'kernel_before_recovery':pre_kernel,'restored':restored,'restored_kernel':restored_kernel,
                'identity_after_recovery':retired_identity,'writer_lock_free_after_recovery':free_lock,
                'successor_pending':g.project(new),'successor_committed':g.project(committed),
                'pending_stale_observations':pending_observations,'committed_stale_observations':committed_observations,
                'journal_before_release':before_release,'journal_after_release':after_release,
                'kernel_before_release':kernel_before_release,'kernel_after_release':kernel_after_release,
                'identity_before_release':identity_before_release,'identity_after_release':identity_after_release,
                'release_clock':{'clock':'monotonic_ns','started_ns':began,'finished_ns':ended},
                'release_observation_seconds':(ended-began)/1e9,'memory':g.memory(),
                'scope':'Fault-injected installed Controller/executor outside unit; recovery by installed systemd Agent/pidfd fencing; finite late-release observation'}
    finally:
        if agent.poll() is None:agent.kill()
        agent.communicate(timeout=3)
        if old_identity and identity(old_identity['pid'])==old_identity:
            os.kill(old_identity['pid'],signal.SIGKILL)
        (g.STATE/'executor-held.go').touch()


def cleanup():
    for pid in g.cmd(['ip','netns','pids',CLIENT],check=False).stdout.split():
        os.kill(int(pid),signal.SIGKILL)
    g.cmd(['ip','netns','delete',CLIENT],check=False)
    assert CLIENT not in [line.split()[0] for line in g.cmd(['ip','netns','list']).stdout.splitlines()]
    return {'dual_client_namespace_removed':True}
