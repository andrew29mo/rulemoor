"""Installed production Boot Guard tests in an isolated VM; no second gate."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
if __package__ in (None,''):sys.path.append(str(Path(__file__).resolve().parents[1]))
from tools import deployment_guest as g
from rulemoor.backend import boot_id, identity
from rulemoor.core import Store
from rulemoor.policy import expected, canonical, digest

UNIT='rulemoor-boot-guard.service'
PEER='rm_guard_peer'
DEV='rg0'
ROOT=g.FIXTURE/'guard-mvp'
PROFILE=g.CONFIG/'boot-guard.json'
SOURCE=g.SOURCE
MARKER=g.FIXTURE/'guard-mvp-mode.json'
BASE={f:{'default':'drop','rules':[{'port':18443,'verdict':'accept'},{'port':19001,'verdict':'accept'},
      {'port':port,'verdict':'drop'}]} for f,port in (('ipv4',59001),('ipv6',59002))}
NEW={f:{**p,'rules':p['rules']+[{'port':59011 if f=='ipv4' else 59012,'verdict':'drop'}]} for f,p in BASE.items()}
FINAL={f:{**p,'rules':p['rules']+[{'port':59021 if f=='ipv4' else 59022,'verdict':'drop'}]} for f,p in NEW.items()}
CANDIDATE={f:{'default':'accept','rules':[]} for f in ('ipv4','ipv6')}


def save(n,v):
    from rulemoor.backend import atomic_json
    atomic_json(ROOT/(n+'.json'),v)


def load(n):return json.loads((ROOT/(n+'.json')).read_text())
def ctl(*args,**kw):return g.cmd(['systemctl',*args],**kw)
def props(unit=UNIT):
    keys=('MainPID','ActiveState','SubState','Result','ExecMainStatus','InvocationID','MemoryCurrent','MemoryPeak')
    return dict(x.split('=',1) for x in ctl('show',unit,*['-p'+k for k in keys]).stdout.splitlines())
def link():
    r=json.loads(g.cmd(['ip','-n',g.NS,'-j','link','show','dev',DEV]).stdout)[0]
    return {'up':'UP' in r['flags'],'ifindex':r['ifindex'],'namespace_inode':Path('/run/netns',g.NS).stat().st_ino,'boot':boot_id()}
def families():
    result={}
    for f in ('ip','ip6'):
        p=g.cmd(['ip','netns','exec',g.NS,'nft','-j','-s','list','table',f,'rulemoor'],check=False)
        if p.returncode:
            assert 'No such file or directory' in p.stderr
            result[f]=None
        else:result[f]=canonical(json.loads(p.stdout))
    return result

def kernel():
    rows=families();return sum((rows[f] or [] for f in ('ip','ip6')),[]) or None

def receipt():return json.loads((g.STATE/'boot-guard.json').read_text())
def in_ns(code,*args,check=True,**kw):return g.cmd(['ip','netns','exec',g.NS,g.PYTHON,'-I','-c',code,*args],check=check,**kw)


def topology():
    """Production namespace boot prerequisite calls this before guard/Agent."""
    g.cmd(['ip','netns','add',PEER]);g.cmd(['ip','-n',PEER,'link','set','lo','up'])
    g.cmd(['ip','-n',g.NS,'link','add',DEV,'type','veth','peer','name','rc0','netns',PEER])
    for ns,dev,mac,v4,v6 in ((g.NS,DEV,'02:00:00:77:00:02','192.0.2.42/24','2001:db8:88::2/64'),
                             (PEER,'rc0','02:00:00:77:00:01','192.0.2.41/24','2001:db8:88::1/64')):
        g.cmd(['ip','-n',ns,'link','set',dev,'address',mac])
        g.cmd(['ip','-n',ns,'addr','add',v4,'dev',dev]);g.cmd(['ip','-n',ns,'-6','addr','add',v6,'dev',dev,'nodad'])
    g.cmd(['ip','-n',PEER,'link','set','rc0','up']);assert not link()['up']
    save('pre-guard',{'boot':boot_id(),'link':link(),'kernel':kernel(),'family_kernel':families(),'journal':g.project(Store(g.STATE).load())})


COMMON='''import json,sys
from pathlib import Path
from rulemoor.cli import request
urls={'ipv4':'https://192.0.2.42:18443','ipv6':'https://[2001:db8:88::2]:18443'}
def call(f,path='/status',payload=None):return request(urls[f],'/etc/rulemoor/server.pem',Path('/etc/rulemoor/token').read_text().strip(),path,payload,family=f)
def project(s):return {k:s[k] for k in ('phase','generation','op','boot','current','baseline','candidate','confirmed_families') if k in s}
def payload(s):return {k:s[k] for k in ('op','generation','candidate_digest','challenge')}
'''
def peer(code,*args,check=True):
    p=g.cmd(['ip','netns','exec',PEER,g.PYTHON,'-I','-c',COMMON+code,*args],check=check,timeout=15)
    return json.loads(p.stdout) if p.returncode==0 else None

def ready():
    try:return g.wait(lambda:peer("print(json.dumps({f:project(call(f)) for f in urls}))",check=False))
    except AssertionError:
        raise RuntimeError('TLS readiness failed: '+str(props(g.UNIT))+'\n'+g.cmd(['ip','-n',g.NS,'-j','addr']).stdout+'\n'+g.cmd(['journalctl','-u',g.UNIT,'--no-pager','-n','20']).stdout)
def commit(op,policy):
    return peer('''s0=call('ipv4');s=call('ipv4','/apply',{'op':sys.argv[1],'generation':s0['generation'],'policy':json.loads(sys.argv[2]),'window':30})
a=call('ipv4','/confirm',payload(s));b=call('ipv6','/confirm',payload(s))
assert a['phase']=='AWAITING_CONFIRM' and b['phase']=='COMMITTED'
print(json.dumps(project(b)))
''',op,json.dumps(policy))

def listeners():
    import socketserver,threading
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data=self.request.recv(64);self.request.sendall(data)
    class S4(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
    class S6(S4):
        address_family=socket.AF_INET6
        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);super().server_bind()
    for cls,host in ((S4,'0.0.0.0'),(S6,'::')):
        for port in (19001,19002):
            s=cls((host,port),Handler);threading.Thread(target=s.serve_forever,daemon=True).start()
    while True:time.sleep(1)

def data_plane():
    p=props('rulemoor-guard-listeners.service');pid=int(p['MainPID']);before=identity(pid);assert before
    rows=peer('''import socket
rows=[]
for f,af,host in (('ipv4',socket.AF_INET,'192.0.2.42'),('ipv6',socket.AF_INET6,'2001:db8:88::2')):
 for port in (19001,19002):
  s=socket.socket(af,socket.SOCK_STREAM);s.settimeout(.3);connected=False
  try:
   s.connect((host,port));connected=True;s.sendall((f+'-canary').encode());echo=s.recv(64).decode();r={'family':f,'port':port,'connected':True,'stage':'complete','echo':echo}
  except OSError as e:r={'family':f,'port':port,'connected':connected,'stage':'echo' if connected else 'connect','errno':e.errno}
  finally:s.close()
  if port==19001:assert r.get('echo')==f+'-canary'
  else:assert not r['connected'] and r['errno'] in (None,11,110)
  rows.append(r)
print(json.dumps(rows))
''')
    assert before==identity(pid) and props('rulemoor-guard-listeners.service')['MainPID']==str(pid)
    # Prove both denied sockets actually listen, excluding ECONNREFUSED/no server.
    sockets=g.cmd(['ip','netns','exec',g.NS,'ss','-H','-lnt']).stdout
    assert sockets.count(':19002')==2 and sockets.count(':19001')==2
    return {'rows':rows,'listener_identity_before':before,'listener_identity_after':identity(pid),'listening_socket_counts':{'19001':2,'19002':2}}


def start_guard():
    ctl('reset-failed',UNIT)
    p=ctl('start',UNIT,check=False)
    return {'exit_code':p.returncode,'unit':props(),'link':link(),'receipt':receipt() if (g.STATE/'boot-guard.json').exists() else None,'kernel':kernel(),'journal':g.project(Store(g.STATE).load())}

def stop():
    ctl('stop',g.UNIT);ctl('stop',UNIT);assert not link()['up']


def setup():
    ctl('disable','--now',g.UNIT)
    ROOT.mkdir(mode=0o700);save('ownership',{'kind':'guard-mvp-v1'})
    shutil.copytree(g.STATE,ROOT/'legacy-backup');shutil.rmtree(g.STATE)
    for f in ('ip','ip6'):g.cmd(['ip','netns','exec',g.NS,'nft','delete','table',f,'rulemoor'],check=False)
    g.STATE.mkdir(mode=0o700)
    in_ns('import json,sys;from rulemoor.core import Controller;from rulemoor.backend import NftBackend;c=Controller(sys.argv[1],NftBackend(dual_stack=True));c.initialize(json.loads(sys.argv[2]));c.close()',str(g.STATE),json.dumps(BASE))
    MARKER.write_text('{}');topology()
    PROFILE.write_text(json.dumps({'version':1,'interface':DEV,'mac':'02:00:00:77:00:02',
                                  'namespace':'/run/netns/'+g.NS,'activation_owner':'rulemoor-exclusive','ipv4':'192.0.2.42/24','ipv6':'2001:db8:88::2/64'}));PROFILE.chmod(0o600)
    g.cmd(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',g.CONFIG/'server.key','-out',g.CONFIG/'server.pem','-subj','/CN=rulemoor-guard',
           '-addext','subjectAltName=IP:127.0.0.1,IP:::1,IP:192.0.2.42,IP:2001:db8:88::2'])
    (g.CONFIG/'server.key').chmod(0o600)
    shutil.copyfile(SOURCE/'deploy/rulemoor-boot-guard.service','/etc/systemd/system/'+UNIT)
    drop=Path('/etc/systemd/system/'+UNIT+'.d');drop.mkdir()
    (drop/'10-namespace.conf').write_text('[Unit]\nRequires=rulemoor-test-namespace.service\nAfter=rulemoor-test-namespace.service\n[Service]\nNetworkNamespacePath=/run/netns/'+g.NS+'\nMemoryAccounting=yes\n')
    shutil.copyfile(SOURCE/'deploy/rulemoor-agent-guard.conf','/etc/systemd/system/rulemoor.service.d/50-guard.conf')
    original=next(x for x in Path('/etc/systemd/system/rulemoor.service').read_text().splitlines() if x.startswith('ExecStart='))
    Path('/etc/systemd/system/rulemoor.service.d/60-dual.conf').write_text('[Service]\nExecStart=\n'+original.replace('--listen 127.0.0.1','--listen 0.0.0.0')+' --dual-stack --listen6 ::\n')
    nsunit=Path('/etc/systemd/system/rulemoor-test-namespace.service')
    nsunit.write_text(nsunit.read_text().replace('[Unit]\n','[Unit]\nDefaultDependencies=no\nAfter=local-fs.target\nBefore='+UNIT+'\n'))
    Path('/etc/systemd/system/rulemoor-guard-listeners.service').write_text('[Unit]\nRequires=rulemoor-test-namespace.service\nAfter=rulemoor-test-namespace.service\n[Service]\nType=simple\nNetworkNamespacePath=/run/netns/'+g.NS+'\nExecStart='+g.PYTHON+' -I '+str(SOURCE/'tools/guard_guest.py')+' listeners\n[Install]\nWantedBy=multi-user.target\n')
    ctl('daemon-reload')
    g.cmd(['systemd-analyze','verify','/etc/systemd/system/'+UNIT,'/etc/systemd/system/rulemoor.service'])
    ctl('enable',UNIT,g.UNIT,'rulemoor-guard-listeners.service');ctl('start','rulemoor-guard-listeners.service')
    opened=start_guard()
    if opened['exit_code']!=0:raise RuntimeError('Guard startup failed: '+json.dumps(opened)+'\n'+g.cmd(['journalctl','-u',UNIT,'--no-pager','-n','50']).stdout)
    assert opened['receipt']['status']=='OPEN'
    ctl('start',g.UNIT);tls=ready();assert tls['ipv4']==tls['ipv6']
    return {'installed':g.installed_modules(),'production_unit_sha256':hashlib.sha256(Path('/etc/systemd/system/'+UNIT).read_bytes()).hexdigest(),
            'source_unit_sha256':hashlib.sha256((SOURCE/'deploy/rulemoor-boot-guard.service').read_bytes()).hexdigest(),
            'namespace_only_guard_override':True,'profile':json.loads(PROFILE.read_text()),'opened':opened,'tls':tls,'data':data_plane(),'agent_memory':g.memory()}


def portable():
    env=dict(os.environ,RULEMOOR_UNIT_OUTPUT=str(ROOT/'portable.json'))
    g.cmd([g.PYTHON,'-m','tools.unit'],cwd=SOURCE,env=env,timeout=60)
    return json.loads((ROOT/'portable.json').read_text())


def failures():
    stop()
    # Create a real pending policy with the installed Controller, then force the
    # real executor's nft invocation to fail, without replacing Guard/Backend.
    pending=json.loads(in_ns('''import json,sys
from rulemoor.core import Controller
from rulemoor.backend import NftBackend
c=Controller(sys.argv[1],NftBackend(dual_stack=True));c.start();s=c.apply('guard-write-fault',c.s['generation'],json.loads(sys.argv[2]),60)
print(json.dumps(s));c.close()
''',str(g.STATE),json.dumps(CANDIDATE)).stdout)
    saved=Store(g.STATE).load();candidate_kernel=kernel();assert candidate_kernel==expected(CANDIDATE)
    bins=ROOT/'fault-bin';bins.mkdir();trace=g.STATE/'test-nft-fault-trace'
    wrapper=bins/'nft';wrapper.write_text('#!/bin/sh\nif test "$1" = "-f"; then\n echo rejected-write >> '+str(trace)+'\n exec /usr/sbin/nft --rulemoor-injected-invalid-option\nfi\nexec /usr/sbin/nft "$@"\n');wrapper.chmod(0o700)
    drop=Path('/etc/systemd/system/'+UNIT+'.d/80-write-fault.conf')
    drop.write_text('[Service]\nEnvironment=PATH='+str(bins)+':/usr/sbin:/usr/bin:/sbin:/bin\n')
    ctl('daemon-reload');bad=start_guard()
    assert bad['exit_code']!=0 and not bad['link']['up'] and bad['receipt']['status']=='CLOSED'
    assert bad['journal']['phase']=='DEGRADED' and kernel()==candidate_kernel
    attempts=trace.read_text().splitlines();assert attempts==['rejected-write']
    drop.unlink();ctl('daemon-reload');ctl('reset-failed',UNIT)
    # Explicit operator fixture repair of DEGRADED, not automatic journal repair.
    Store(g.STATE).save(saved,'guard_fixture_local_repair')
    good=start_guard();assert good['exit_code']==0 and good['kernel']==expected(BASE)
    ctl('start',g.UNIT);ready()
    return {'pending':g.project(pending),'candidate_kernel':candidate_kernel,'failed':bad,'write_attempts':attempts,
            'fault_boundary':'PATH nft wrapper delegates reads, fails actual production executor write','repaired':good,'data':data_plane()}


def monitor():
    import struct
    marker=ROOT/'monitor-ready.json';stopfile=ROOT/'monitor-stop'
    s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024*1024);s.bind((0,1));s.settimeout(.05)
    started=time.monotonic_ns();save('monitor-ready',{'subscribed_ns':started,'namespace_inode':Path('/proc/self/ns/net').stat().st_ino})
    events=[]
    try:
        while not stopfile.exists():
            try:packet=s.recv(65536)
            except socket.timeout:continue
            while packet:
                length,kind,flags,seq,pid=struct.unpack_from('IHHII',packet)
                assert 16<=length<=len(packet)
                if kind==2:raise RuntimeError('Netlink error')
                if kind in (16,17):
                    family,pad,typ,index,linkflags,change=struct.unpack_from('BBHiII',packet,16)
                    events.append({'type':kind,'ifindex':index,'up':bool(linkflags&1),'observed_ns':time.monotonic_ns()})
                    assert len(events)<=256
                packet=packet[(length+3)&~3:]
        save('monitor-result',{'subscribed_ns':started,'finished_ns':time.monotonic_ns(),
                              'namespace_inode':Path('/proc/self/ns/net').stat().st_ino,'events':events})
    finally:s.close()


def delayed_agent():
    stop()
    key=g.CONFIG/'server.key';renamed=g.CONFIG/'server.key.saved';key.rename(renamed)
    early=start_guard();assert early['exit_code']==0
    no_tls=ctl('start',g.UNIT,check=False)
    failed_unit=g.wait(lambda:props(g.UNIT) if props(g.UNIT)['Result']=='exit-code' and props(g.UNIT)['ExecMainStatus']!='0' else False)
    assert peer("print(json.dumps({f:project(call(f)) for f in urls}))",check=False) is None
    ctl('stop',g.UNIT);during=data_plane()
    renamed.rename(key);ctl('reset-failed',g.UNIT)
    drop=Path('/etc/systemd/system/rulemoor.service.d/75-delay.conf');drop.write_text('[Service]\nExecStartPre=/usr/bin/sleep 2\n')
    ctl('daemon-reload');ctl('start','--no-block',g.UNIT);g.wait(lambda:props(g.UNIT)['SubState']=='start-pre')
    waiting={'agent':props(g.UNIT),'link':link(),'kernel':kernel(),'data':data_plane()}
    tls=ready();before=props(g.UNIT);guard_before=receipt()
    drop.unlink();ctl('daemon-reload')
    for name in ('monitor-ready.json','monitor-stop','monitor-result.json'):(ROOT/name).unlink(missing_ok=True)
    observer=subprocess.Popen(['ip','netns','exec',g.NS,g.PYTHON,'-I',str(SOURCE/'tools/guard_guest.py'),'monitor'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        g.wait(lambda:(ROOT/'monitor-ready.json').exists());subscribed=load('monitor-ready')
        ctl('restart',g.UNIT);after_tls=ready()
        (ROOT/'monitor-stop').touch();observer.wait(timeout=3);assert observer.returncode==0
        observed=load('monitor-result');assert observed['subscribed_ns']==subscribed['subscribed_ns']
        assert observed['namespace_inode']==link()['namespace_inode'] and not observed['events']
    finally:
        if observer.poll() is None:observer.kill();observer.wait()

    assert before['MainPID']!=props(g.UNIT)['MainPID'] and receipt()==guard_before
    return {'early_without_tls_key':early,'tls_start_exit':no_tls.returncode,'tls_failed_unit':failed_unit,'tls_unavailable_observed':True,'data_without_agent':during,
            'delayed':waiting,'tls_after_delay':tls,'tls_after_restart':after_tls,
            'guard_receipt_unchanged':receipt()==guard_before,'restart_link_monitor':observed,'data_after_restart':data_plane()}


def crashes():
    rows=[];stop()
    bins=ROOT/'ip-fault-bin';bins.mkdir()
    marker=g.STATE/'test-ip-held';wrapper=bins/'ip'
    drop=Path('/etc/systemd/system/'+UNIT+'.d/81-ip-fault.conf')
    for point in ('before-up','after-up'):
        marker.unlink(missing_ok=True)
        script='#!/bin/sh\nif test "$1" = link && test "$4" = rg0 && test "$5" = up; then\n'
        if point=='after-up':script+='/usr/sbin/ip "$@" || exit $?\n'
        script+='echo $$ > '+str(marker)+'\nwhile :; do /usr/bin/sleep 0.01; done\nfi\nexec /usr/sbin/ip "$@"\n'
        wrapper.write_text(script);wrapper.chmod(0o700)
        drop.write_text('[Service]\nEnvironment=PATH='+str(bins)+':/usr/sbin:/usr/bin:/sbin:/bin\n')
        ctl('daemon-reload');ctl('reset-failed',UNIT);ctl('start','--no-block',UNIT)
        g.wait(lambda:marker.exists(),timeout=1.5)
        running=props();main=identity(int(running['MainPID']));child=identity(int(marker.read_text()))
        before=link();assert main and child and running['ActiveState']=='activating'
        fields=dict(line.split(':',1) for line in Path(f"/proc/{main['pid']}/status").read_text().splitlines() if ':' in line)
        argv=Path(f"/proc/{main['pid']}/cmdline").read_bytes().decode().split('\0')
        assert '/opt/rulemoor/venv/bin/rulemoor-boot-guard' in argv and identity(main['pid'])==main
        process_memory={'identity':main,'rss_bytes':int(fields['VmRSS'].split()[0])*1024,'vmhwm_bytes':int(fields['VmHWM'].split()[0])*1024,
                        'entrypoint':'/opt/rulemoor/venv/bin/rulemoor-boot-guard','scope':'VM production gate held in actual ip subprocess call; process only, excludes children; not normal whole-run peak'}
        assert before['up']==(point=='after-up')
        ctl('kill','--kill-whom=main','--signal=SIGKILL',UNIT)
        g.wait(lambda:props()['ActiveState']=='failed')
        closed=receipt();after=link();unit=props()
        assert unit['Result']=='signal' and unit['ExecMainStatus']=='9' and unit['InvocationID']==running['InvocationID']
        assert closed['status']=='CLOSED' and not after['up'] and not closed['link']['up']
        assert identity(child['pid'])!=child and identity(main['pid'])!=main
        rows.append({'point':point,'unit_before':running,'main_identity':main,'child_identity':child,
                     'link_before':before,'process_memory':process_memory,'unit_after':unit,'receipt_after':closed,'link_after':after,
                     'child_retired':True})
        drop.unlink();ctl('daemon-reload')
    # Start normally, then reject the actual ip DOWN call in ExecStopPost.
    wrapper.write_text('#!/bin/sh\nif test "$1" = link && test "$4" = rg0 && test "$5" = down; then exit 77; fi\nexec /usr/sbin/ip "$@"\n')
    drop.write_text('[Service]\nEnvironment=PATH='+str(bins)+':/usr/sbin:/usr/bin:/sbin:/bin\n')
    ctl('daemon-reload');active=start_guard();assert active['exit_code']==0
    stopped=ctl('stop',UNIT,check=False);fault={'stop_exit':stopped.returncode,'unit':props(),'receipt':receipt(),'link':link()}
    assert fault['receipt']['status']=='FAULTED' and fault['link']['up'] and fault['unit']['ActiveState']=='failed'
    # Separate explicit local rescue, not an automatic-success claim.
    g.cmd(['ip','-n',g.NS,'link','set',DEV,'down']);fault['manual_rescue_link']=link();assert not link()['up']
    drop.unlink();ctl('daemon-reload')
    reopened=start_guard();assert reopened['exit_code']==0
    ctl('start',g.UNIT);ready()
    return {'kills':rows,'close_failure':fault,'reopened':reopened,'data':data_plane(),
            'injection':'PATH ip wrapper holds real subprocess call before/after actual UP; unit cgroup cleanup and formal ExecStopPost'}


def delayed_executor():
    stop();(g.STATE/'executor-held.reached').unlink(missing_ok=True);(g.STATE/'executor-held.go').unlink(missing_ok=True)
    script='''import json,sys
from rulemoor.core import Controller
from rulemoor.backend import NftBackend
c=Controller(sys.argv[1],NftBackend(dual_stack=True));c.start();c.apply('guard-old-writer',c.s['generation'],json.loads(sys.argv[2]),60)
'''
    env=dict(os.environ,RULEMOOR_FAULT='executor-held')
    parent=subprocess.Popen(['ip','netns','exec',g.NS,g.PYTHON,'-I','-c',script,str(g.STATE),json.dumps(CANDIDATE)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        g.wait(lambda:(g.STATE/'executor-held.reached').exists(),timeout=1.5)
        state=Store(g.STATE).load();old=json.loads((g.STATE/('executor-'+state['executor_token']+'.json')).read_text())
        old_identity={k:old[k] for k in ('pid','start_ticks','boot')};assert identity(old['pid'])==old_identity
        parent.kill();parent.wait(timeout=2);assert identity(old['pid'])==old_identity
        opened=start_guard();assert opened['exit_code']==0 and identity(old['pid'])!=old_identity
        retired_at=time.monotonic_ns();ctl('start',g.UNIT);ready();new=commit('guard-new-after-orphan',NEW)
        before=kernel();assert before==expected(NEW)
        (g.STATE/'executor-held.go').touch();released=time.monotonic_ns();time.sleep(2.1)
        after=kernel();assert before==after and Store(g.STATE).load()['generation']==new['generation']
        return {'old_identity':old_identity,'old_phase':state['phase'],'parent_returncode':parent.returncode,
                'orphan_observed_alive':True,'retired_before_open_return':True,'retired_at_ns':retired_at,
                'opened':opened,'successor':new,'release_ns':released,'observed_ns':time.monotonic_ns(),
                'kernel_before_release':before,'kernel_after_release':after,'data':data_plane()}
    finally:
        if parent.poll() is None:parent.kill();parent.wait()


def prepare_pending():
    partial=peer('''s0=call('ipv4');s=call('ipv4','/apply',{'op':'guard-partial-boot','generation':s0['generation'],'policy':json.loads(sys.argv[1]),'window':60})
Path('/var/lib/rulemoor-validation/guard-mvp/old-private-receipt.json').write_text(json.dumps(s))
p=call('ipv4','/confirm',payload(s));assert p['confirmed_families']==['ipv4'] and p['phase']=='AWAITING_CONFIRM'
print(json.dumps(project(p)))
''',json.dumps(CANDIDATE))
    before=g.project(Store(g.STATE).load());assert before==partial
    drop=Path('/etc/systemd/system/rulemoor.service.d/91-kill.conf');drop.write_text('[Service]\nKillSignal=SIGKILL\nRestart=no\n')
    ctl('daemon-reload');ctl('stop',g.UNIT);drop.unlink();ctl('daemon-reload')
    ctl('stop',UNIT)
    assert g.project(Store(g.STATE).load())==before and kernel()==expected(CANDIDATE) and not link()['up']
    row={'boot':boot_id(),'journal_before_stop':partial,'journal_after_stop':g.project(Store(g.STATE).load()),
         'kernel_after_stop':kernel(),'link':link(),'agent_stopped':props(g.UNIT)['MainPID']=='0'}
    save('pending-before-boot',row);return row


def after_boot(kind):
    before=load(kind+'-before-boot');pre=load('pre-guard');tls=ready();current=g.project(Store(g.STATE).load());r=receipt()
    assert before['boot']!=boot_id() and pre['boot']==boot_id() and not pre['link']['up'] and pre['kernel'] is None
    assert pre['family_kernel']=={'ip':None,'ip6':None}
    assert pre['journal']==before['journal_after_stop']
    target=NEW if kind=='pending' else FINAL
    assert current['current']==target and kernel()==expected(target) and r['kernel']==expected(target)
    assert r['status']=='OPEN' and current['generation']>before['journal_after_stop']['generation']
    assert current['phase']==('ROLLED_BACK' if kind=='pending' else 'COMMITTED')
    assert tls['ipv4']==tls['ipv6']==current
    row={'before':before,'pre_guard':pre,'guard':r,'journal':current,'tls':tls,'data':data_plane(),'agent_memory':g.memory(),'power_loss_tested':False}
    if kind=='pending':
        committed=commit('guard-final-before-boot',FINAL)
        stop();assert g.project(Store(g.STATE).load())==committed
        save('committed-before-boot',{'boot':boot_id(),'journal_after_stop':committed,'kernel_after_stop':kernel(),'link':link()})
        row['next_committed']=committed
    else:
        before_stale=g.project(Store(g.STATE).load());before_kernel=kernel()
        status=peer('''old=json.loads(Path('/var/lib/rulemoor-validation/guard-mvp/old-private-receipt.json').read_text());rows=[]
for f in urls:
 try:call(f,'/confirm',payload(old))
 except RuntimeError as e:assert str(e).startswith('409:');rows.append({'family':f,'status':409})
 else:raise AssertionError('Old confirm accepted')
print(json.dumps(rows))
''')
        assert before_stale==g.project(Store(g.STATE).load()) and before_kernel==kernel()
        row['stale_confirmations']={'rows':status,'before':before_stale,'after':g.project(Store(g.STATE).load()),'kernel_before':before_kernel,'kernel_after':kernel()}
    return row


def cleanup():
    assert load('ownership')=={'kind':'guard-mvp-v1'}
    ctl('disable','--now',g.UNIT,UNIT,'rulemoor-guard-listeners.service')
    for ns in (PEER,):
        for pid in g.cmd(['ip','netns','pids',ns],check=False).stdout.split():os.kill(int(pid),signal.SIGKILL)
        g.cmd(['ip','netns','delete',ns],check=False)
    for path in ('/etc/systemd/system/'+UNIT,'/etc/systemd/system/rulemoor-guard-listeners.service'):
        Path(path).unlink(missing_ok=True)
    shutil.rmtree('/etc/systemd/system/'+UNIT+'.d',ignore_errors=True)
    MARKER.unlink(missing_ok=True);ctl('daemon-reload');ctl('reset-failed',UNIT,'rulemoor-guard-listeners.service',check=False)
    assert props()['MainPID']=='0' and PEER not in g.cmd(['ip','netns','list']).stdout
    return {'guard_removed':True,'peer_removed':True,'root_firewall_unchanged':g.root_rules_digest()==g.load('root-rules-before')['sha256']}


if __name__=='__main__':
    action=sys.argv[1]
    if action=='listeners':listeners()
    elif action=='after_pending':print(json.dumps(after_boot('pending')))
    elif action=='after_committed':print(json.dumps(after_boot('committed')))
    else:print(json.dumps(globals()[action]()))
