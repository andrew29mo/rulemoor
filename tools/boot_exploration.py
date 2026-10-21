"""Experimental VM fixtures, NOT an installed or supported Boot Guard feature.

Controller/NftBackend are the installed production wheel. Gate orchestration is a
prototype whose limitations are part of the experiment, not production claims.
"""
import json
import os
from pathlib import Path
import signal
import sys
import time

if __package__ in (None, ''):
    sys.path.append(str(Path(__file__).resolve().parents[1]))
from tools import deployment_guest as g
from rulemoor.backend import NftBackend, boot_id, identity, lock, atomic_json
from rulemoor.core import Controller, Store, TERMINAL
from rulemoor.policy import expected, digest, compile_policy

NS = 'rm_boot_probe'
DEV = 'rmbs'
PEER = 'rmbp'
ROOT = g.FIXTURE / 'boot-probe'
STATE = ROOT / 'state'
UNITDIR = Path('/etc/systemd/system')
PREFIX = 'rulemoor-boot-probe-'
SCRIPT = '/opt/rulemoor-validation/tools/boot_exploration.py'
POLICY = {f:{'default':'drop','rules':[{'port':18443,'verdict':'accept'},
                                      {'port':59998 if f=='ipv4' else 59999,'verdict':'drop'}]}
          for f in ('ipv4','ipv6')}
CANDIDATE = {f:{'default':'accept','rules':[]} for f in ('ipv4','ipv6')}


def save(name, value):
    atomic_json(ROOT / (name + '.json'), value)


def load(name):
    return json.loads((ROOT / (name + '.json')).read_text())


def name(short):
    return PREFIX + short + '.service'


def ctl(*args, **kw):
    return g.cmd(['systemctl', *args], **kw)


def properties(short):
    keys = ('ActiveState','SubState','Result','ExecMainStatus','MainPID','InvocationID')
    return dict(x.split('=',1) for x in ctl('show',name(short),*['-p'+k for k in keys]).stdout.splitlines())


def link():
    row = json.loads(g.cmd(['ip','-n',NS,'-j','link','show','dev',DEV]).stdout)[0]
    return {'ifindex':row['ifindex'],'up':'UP' in row['flags'],
            'namespace_inode':Path('/run/netns',NS).stat().st_ino,'boot':boot_id()}


def down():
    g.cmd(['ip','-n',NS,'link','set',DEV,'down'])
    assert not link()['up']


def topology():
    g.cmd(['ip','netns','add',NS])
    g.cmd(['ip','-n',NS,'link','set','lo','up'])
    g.cmd(['ip','-n',NS,'link','add',DEV,'type','veth','peer','name',PEER])
    for dev,v4,v6 in ((DEV,'192.0.2.32/24','2001:db8:77::2/64'),(PEER,'192.0.2.31/24','2001:db8:77::1/64')):
        g.cmd(['ip','-n',NS,'addr','add',v4,'dev',dev])
        g.cmd(['ip','-n',NS,'-6','addr','add',v6,'dev',dev,'nodad'])
    assert not link()['up']
    save('pre-restore',{'link':link(),'journal':g.project(Store(STATE).load()) if Store(STATE).path.exists() else None,
                        'kernel':json.loads(g.cmd(['ip','netns','exec',NS,'nft','-j','list','ruleset']).stdout)})


def in_ns(code, *args, check=True):
    return g.cmd(['ip','netns','exec',NS,g.PYTHON,'-I','-c',code,*args],check=check,cwd='/')


def initialize():
    result = in_ns('''import json,sys
from rulemoor.core import Controller
from rulemoor.backend import NftBackend
c=Controller(sys.argv[1],NftBackend(dual_stack=True))
try: print(json.dumps(c.initialize(json.loads(sys.argv[2]))))
finally:c.close()
''',str(STATE),json.dumps(POLICY))
    assert json.loads(result.stdout)['phase']=='COMMITTED'


def kernel():
    return json.loads(in_ns('import json;from rulemoor.backend import NftBackend;print(json.dumps(NftBackend(dual_stack=True).read()))').stdout)


def unit(short, service, unit='', install=False):
    (UNITDIR/name(short)).write_text('[Unit]\n'+unit+'\n[Service]\n'+service+('\n[Install]\nWantedBy=multi-user.target\n' if install else '\n'))


def gate(mode):
    """Exclusive controller + writer ownership spans final readback through link UP.

    ExecStopPost covers this unit's process death, not kernel stalls/power loss.
    The durable receipt is diagnostic; it is never used as permission to open.
    """
    started = time.monotonic_ns()
    c = Controller(STATE,NftBackend(dual_stack=True))
    fd = None
    try:
        status = c.start()
        assert status['phase'] in TERMINAL and not c.storage_failed, 'Recovery not ready'
        fd=lock(STATE/'writer.lock')
        live=Store(STATE).load()
        assert live==c.s and c.backend.read()==expected(live['current']), 'Live policy mismatch'
        receipt={**link(),'generation':live['generation'],'policy_digest':digest(expected(live['current'])),
                 'phase':live['phase'],'clock':'monotonic_ns','verified_ns':time.monotonic_ns()}
        assert not receipt['up'], 'Interface already open'
        save('verified',receipt)
        if mode=='hold-before':
            save('hold',{'point':'before-up','pid':os.getpid()})
            while True:time.sleep(.05)
        g.cmd(['ip','-n',NS,'link','set',DEV,'up'])
        opened=link();assert opened['up']
        save('opened',{**receipt,'link_after':opened,'opened_ns':time.monotonic_ns()})
        if mode=='hold-after':
            save('hold',{'point':'after-up','pid':os.getpid()})
            while True:time.sleep(.05)
        if mode=='fail-after':raise RuntimeError('Injected post-UP failure')
        save('gate-result',{'status':'OPEN','receipt':receipt,'link':opened,'kernel':c.backend.read(),
                            'started_ns':started,'opened_ns':load('opened')['opened_ns'],'finished_ns':time.monotonic_ns()})
    finally:
        if fd is not None:os.close(fd)
        c.close()


def close_gate():
    try:
        if (ROOT/'deny-close').exists():raise RuntimeError('Injected cleanup command failure; not a kernel fault')
        down();save('closed',{'status':'CLOSED','link':link()})
    except BaseException:
        save('closed',{'status':'FAULTED','boot':boot_id()})
        raise


def configure_gate(mode='normal', timeout=5, condition=False):
    unit('gate',f'''Type=oneshot
NetworkNamespacePath=/run/netns/{NS}
ExecStart={g.PYTHON} -I {SCRIPT} gate {mode}
ExecStopPost={g.PYTHON} -I {SCRIPT} close
TimeoutStartSec={timeout}
RemainAfterExit=yes
KillMode=control-group
''',unit=f'Requires={name("topology")}\nAfter={name("topology")}\n'+('ConditionPathExists=/run/rulemoor-deliberately-absent\n' if condition else ''))
    # A deliberately unsafe consumer demonstrates Requires+After does not catch
    # skipped Condition*=. The safe candidate always rechecks live policy/identity.
    unit('unsafe-consumer',f'Type=oneshot\nExecStart=/usr/sbin/ip -n {NS} link set {DEV} up\n',
         unit=f'Requires={name("gate")}\nAfter={name("gate")}\n')
    ctl('daemon-reload');ctl('reset-failed',name('gate'),name('unsafe-consumer'),check=False)


def stop_gate():
    ctl('stop',name('unsafe-consumer'),name('gate'),check=False)
    down()
    for f in ('hold','closed','opened','gate-result'):(ROOT/(f+'.json')).unlink(missing_ok=True)


def start_gate(mode='normal', timeout=5, consumer=False):
    stop_gate();configure_gate(mode,timeout)
    began=time.monotonic_ns()
    p=ctl('start',name('unsafe-consumer' if consumer else 'gate'),check=False)
    return {'exit_code':p.returncode,'unit':properties('gate'),'link':link(),
            'started_ns':began,'finished_ns':time.monotonic_ns(),
            'cleanup':load('closed') if (ROOT/'closed.json').exists() else None}


def setup():
    assert not ROOT.exists() and NS not in g.cmd(['ip','netns','list']).stdout
    assert not list(UNITDIR.glob(PREFIX+'*')), 'Refuse to overwrite leftover probe units'
    ROOT.mkdir(mode=0o700)
    save('ownership',{'kind':'rulemoor-boot-spikes-v1'})
    unit('topology',f'Type=oneshot\nExecStart={g.PYTHON} -I {SCRIPT} topology\nRemainAfterExit=yes\n',install=True)
    ctl('daemon-reload');ctl('enable','--now',name('topology'))
    initialize()
    configure_gate()
    return {'installed_modules':g.installed_modules(),'boot':boot_id(),'initial_link':link(),
            'systemd':ctl('--version').stdout.splitlines()[0]}


def failures():
    rows=[]
    # Real journal corruption -> formal Controller.start returns DEGRADED;
    # prototype must convert that diagnostic into a failed systemd prerequisite.
    store=Store(STATE);valid=store.load()
    import sqlite3
    with sqlite3.connect(store.path) as db:
        # Use exact production schema, corrupt only persisted JSON.
        table=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='snapshot'").fetchone()
        assert table is not None
        db.execute("UPDATE snapshot SET value=?",('{"phase":"bad"}',))
    try:
        bad=start_gate(consumer=True);assert bad['exit_code']!=0 and not bad['link']['up'];rows.append({'fault':'journal',**bad})
    finally:store.save(valid,'probe_repair')
    # Real nft syntax failure in the prerequisite, not a fake successful command.
    stop_gate();configure_gate()
    p=UNITDIR/name('gate');text=p.read_text();p.write_text(text.replace(f'ExecStart={g.PYTHON} -I {SCRIPT} gate normal','ExecStart=/usr/sbin/nft -f /var/lib/rulemoor-validation/boot-probe/invalid.nft'))
    (ROOT/'invalid.nft').write_text('this is not nft syntax\n');ctl('daemon-reload')
    r=ctl('start',name('unsafe-consumer'),check=False)
    assert r.returncode!=0 and not link()['up'];rows.append({'fault':'nft','exit_code':r.returncode,'unit':properties('gate'),'link':link(),'cleanup':load('closed')})
    timed=start_gate('hold-before',timeout=1,consumer=True)
    assert timed['exit_code']!=0 and timed['unit']['Result']=='timeout' and not timed['link']['up'];rows.append({'fault':'timeout',**timed})
    # IPv4 intact cannot clear IPv6 drift in the live production readback.
    stop_gate();before_drift=kernel()
    g.cmd(['ip','netns','exec',NS,'nft','add','rule','ip6','rulemoor','input','tcp','dport','59997','drop'])
    drift_kernel=kernel();assert drift_kernel!=before_drift
    family_drift=start_gate(consumer=True)
    assert family_drift['exit_code']!=0 and not family_drift['link']['up']
    assert kernel()==drift_kernel  # no speculative repair of unknown policy
    rows.append({'fault':'ipv6-drift',**family_drift,'kernel_before':before_drift,'kernel_drift':drift_kernel,'kernel_after':kernel()})
    # Explicit local fixture repair, never part of the tested gate admission.
    store.save(valid,'probe_local_drift_repair')
    g.cmd(['ip','netns','exec',NS,'nft','-f','-'],input=compile_policy(POLICY))
    stop_gate();configure_gate()
    invalid=ROOT/'invalid-ipv6-batch.nft'
    invalid.write_text(compile_policy(CANDIDATE)+'add rule ip6 rulemoor missing_chain tcp dport 1 drop\n')
    p=UNITDIR/name('gate');p.write_text(p.read_text().replace(f'ExecStart={g.PYTHON} -I {SCRIPT} gate normal',f'ExecStart=/usr/sbin/nft -f {invalid}'))
    ctl('daemon-reload');before_batch=kernel();r=ctl('start',name('unsafe-consumer'),check=False)
    assert r.returncode!=0 and not link()['up'] and kernel()==before_batch
    rows.append({'fault':'ipv6-batch','exit_code':r.returncode,'unit':properties('gate'),'link':link(),
                 'cleanup':load('closed'),'kernel_before':before_batch,'kernel_after':kernel()})
    # A skipped unit is not failed: demonstrate and retain the counterexample.
    stop_gate();configure_gate(condition=True)
    p=ctl('start',name('unsafe-consumer'),check=False)
    assert p.returncode==0 and link()['up']
    counter={'exit_code':p.returncode,'unit':properties('gate'),'link':link()}
    stop_gate();configure_gate()
    good=start_gate();assert good['exit_code']==0 and good['link']['up']
    good['receipt']=load('gate-result');stop_gate()
    return {'failures':rows,'condition_skip_counterexample':counter,'repaired':good}


def ownership():
    """Run a second *real* networkd in its own network and mount namespaces."""
    stop_gate();configure_gate()
    conf=ROOT/'network';conf.mkdir(exist_ok=True)
    (conf/'10-probe.network').write_text(f'[Match]\nName={DEV}\n[Link]\nActivationPolicy=manual\nRequiredForOnline=no\n[Network]\nDHCP=no\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n')
    unit('networkd',f'''Type=notify
NetworkNamespacePath=/run/netns/{NS}
PrivateMounts=yes
BindReadOnlyPaths={conf}:/etc/systemd/network
TemporaryFileSystem=/run/systemd/netif /run/systemd/network /usr/lib/systemd/network
Environment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/rulemoor-no-system-bus
ExecStart=/usr/lib/systemd/systemd-networkd
TimeoutStartSec=10
''')
    ctl('daemon-reload');ctl('start',name('networkd'))
    observations=[]
    def observe(label):
        row={'action':label,'link':link(),'networkd':properties('networkd')}
        observations.append(row);return row
    assert not observe('manual-start')['link']['up']
    # Unrelated networkd restart cannot enable this manual interface.
    ctl('restart',name('networkd'));assert not observe('manual-restart-closed')['link']['up']
    opened=start_gate();assert opened['exit_code']==0 and opened['link']['up']
    # Gate closes intentionally; manual does NOT force DOWN if someone else opens.
    ctl('restart',name('networkd'));assert observe('manual-restart-open')['link']['up']
    # Actual RTNL reconfigure: restart forces reload of this .network profile.
    down();ctl('restart',name('networkd'));assert not observe('manual-reconfigure-closed')['link']['up']
    # Negative control: allow another manager to own activation; it opens the link.
    ctl('stop',name('networkd'));down()
    p=conf/'10-probe.network';p.write_text(p.read_text().replace('ActivationPolicy=manual','ActivationPolicy=up'))
    ctl('start',name('networkd'))
    g.wait(lambda:link()['up'])
    assert observe('competing-up-counterexample')['link']['up']
    ctl('stop',name('networkd'))
    assert observe('networkd-stop-leaves-open')['link']['up']
    down();p.write_text(p.read_text().replace('ActivationPolicy=up','ActivationPolicy=manual'))
    ctl('start',name('networkd'));assert not link()['up']
    # Same-policy namespace, installed formal Agent, delayed before ExecStart.
    opened=start_gate();assert opened['exit_code']==0
    baseline=kernel();assert baseline==expected(POLICY)
    unit('agent',f"""Type=simple
NetworkNamespacePath=/run/netns/{NS}
ExecStartPre=/usr/bin/sleep 3
ExecStart=/opt/rulemoor/venv/bin/rulemoor-agent --state {STATE} serve --listen 127.0.0.1 --port 18443 --cert /etc/rulemoor/server.pem --key /etc/rulemoor/server.key --token-file /etc/rulemoor/token --dual-stack --listen6 ::1
TimeoutStartSec=10
""")
    ctl('daemon-reload');began=time.monotonic_ns();ctl('start','--no-block',name('agent'))
    g.wait(lambda:properties('agent')['SubState']=='start-pre')
    during={'link':link(),'kernel':kernel(),'agent':properties('agent')}
    assert during['agent']['MainPID']=='0' and during['kernel']==baseline and during['link']['up']
    def ready():
        p=in_ns("import json;from pathlib import Path;from rulemoor.cli import request;print(json.dumps(request('https://127.0.0.1:18443','/etc/rulemoor/server.pem',Path('/etc/rulemoor/token').read_text().strip(),'/status')))",check=False)
        return json.loads(p.stdout) if p.returncode==0 else False
    status=g.wait(ready);assert status['phase']=='COMMITTED'
    pid=int(properties('agent')['MainPID']);origin=Path(f'/proc/{pid}/ns/net').stat().st_ino
    assert origin==link()['namespace_inode']
    after={'link':link(),'kernel':kernel(),'agent':properties('agent'),'agent_namespace_inode':origin}
    assert after['kernel']==baseline and after['link']['up'] and int(after['agent']['MainPID'])>0
    ctl('restart',name('agent'));g.wait(ready)
    restarted={'link':link(),'kernel':kernel(),'agent':properties('agent')}
    assert restarted['link']['up'] and restarted['kernel']==baseline
    assert restarted['agent']['MainPID']!=after['agent']['MainPID']
    ctl('stop',name('agent'));ctl('stop',name('networkd'))
    return {'observations':observations,'delay':{'started_ns':began,'finished_ns':time.monotonic_ns(),
                                                'during':during,'after':after,'restarted':restarted,
                                                'scope':'installed formal Agent and policy/link in same namespace; endpoint observations'}}


def crashes():
    rows=[]
    for mode,point in (('hold-before','before-up'),('hold-after','after-up')):
        stop_gate();configure_gate(mode)
        ctl('start','--no-block',name('gate'))
        g.wait(lambda:(ROOT/'hold.json').exists())
        held=load('hold');assert held['point']==point
        running=properties('gate');process=identity(int(running['MainPID']))
        assert running['ActiveState']=='activating' and int(running['MainPID'])==held['pid']
        assert process is not None and process['boot']==boot_id()
        process_namespace=Path(f"/proc/{held['pid']}/ns/net").stat().st_ino
        before=link();assert before['up']==(point=='after-up')
        assert process_namespace==before['namespace_inode']
        # Challenge each real lock independently. Only the exact ownership
        # rejection counts; syntax/import failures cannot masquerade as fencing.
        contender=in_ns('''import sys
import json
from rulemoor.core import Controller
from rulemoor.backend import NftBackend
try:c=Controller(sys.argv[1],NftBackend(dual_stack=True))
except RuntimeError as e:
 assert str(e)=='Another owner/writer is active'
 print(json.dumps({'blocked':True}));raise SystemExit(7)
c.close();print(json.dumps({'blocked':False}))
''',str(STATE),check=False)
        writer=in_ns('''import sys,os,json
from rulemoor.backend import lock
from pathlib import Path
try:fd=lock(Path(sys.argv[1])/'writer.lock')
except RuntimeError as e:
 assert str(e)=='Another owner/writer is active'
 print(json.dumps({'blocked':True}));raise SystemExit(7)
os.close(fd);print(json.dumps({'blocked':False}))
''',str(STATE),check=False)
        assert contender.returncode==writer.returncode==7
        owner_result=json.loads(contender.stdout);writer_result=json.loads(writer.stdout)
        assert owner_result==writer_result=={'blocked':True}
        killed_at=time.monotonic_ns()
        ctl('kill','--kill-whom=main','--signal=SIGKILL',name('gate'))
        g.wait(lambda:properties('gate')['ActiveState']=='failed')
        closed=load('closed');assert closed['status']=='CLOSED' and not closed['link']['up'] and not link()['up']
        stopped=properties('gate')
        assert stopped['Result']=='signal' and stopped['ExecMainStatus']=='9'
        assert stopped['InvocationID']==running['InvocationID'] and identity(held['pid'])!=process
        row={'point':point,'held':held,'link_before':before,'contending_controller_exit':contender.returncode,
             'owner_lock_contender':{'exit_code':contender.returncode,**owner_result},
             'writer_lock_contender':{'exit_code':writer.returncode,**writer_result},
             'unit_before':running,'process_before':process,'process_namespace_inode':process_namespace,
             'signal_clock':{'clock':'monotonic_ns','sent_ns':killed_at,'observed_closed_ns':time.monotonic_ns()},
             'unit':stopped,'cleanup':closed,'link_after':link()}
        reopened=start_gate();assert reopened['exit_code']==0 and reopened['link']['up'];row['reopened']=reopened
        rows.append(row)
    after=start_gate('fail-after');assert after['exit_code']!=0 and not after['link']['up']
    # A failed close is FAULTED, never a false CLOSED/pass. The file injects
    # a command-level failure; it does not emulate uninterruptible kernel I/O.
    stop_gate();configure_gate('fail-after');(ROOT/'deny-close').touch()
    try:
        p=ctl('start',name('gate'),check=False)
        faulted={'exit_code':p.returncode,'unit':properties('gate'),'cleanup':load('closed'),'link':link()}
        assert p.returncode!=0 and faulted['cleanup']['status']=='FAULTED' and faulted['link']['up']
    finally:(ROOT/'deny-close').unlink(missing_ok=True)
    down();faulted['manual_rescue_link']=link()
    stop_gate()
    return {'kills':rows,'post_up_exception':after,'close_failure':faulted,'scope':'observed post-UP window exists; ExecStopPost cleanup, not zero exposure'}


def handoff():
    # Genuine Controller ownership handoff: immediate second owner starts and
    # writes a distinct pending policy, then normal startup restores baseline.
    stop_gate();opened=start_gate();assert opened['exit_code']==0
    previous=load('gate-result')['receipt']
    result=json.loads(in_ns('''import json,sys
from rulemoor.core import Controller
from rulemoor.backend import NftBackend
c=Controller(sys.argv[1],NftBackend(dual_stack=True))
try:
 s=c.start();p=c.apply('boot-probe-pending',s['generation'],json.loads(sys.argv[2]),60)
 print(json.dumps({k:p[k] for k in ('phase','generation','op','boot','current','baseline','candidate','confirmed_families')}))
finally:c.close()
''',str(STATE),json.dumps(CANDIDATE)).stdout)
    assert result['phase']=='AWAITING_CONFIRM'
    # Persist pending journal, then stop fixture gate without calling Controller
    # shutdown (ExecStopPost only closes interface). No pre-reboot rollback.
    ctl('stop',name('gate'));assert not link()['up']
    before=g.project(Store(STATE).load());assert before==result
    before_kernel=kernel();assert before_kernel==expected(CANDIDATE)
    save('before-reboot',{'boot':boot_id(),'journal':before,'kernel':before_kernel,'old_receipt':previous,'link':link()})
    # Boot starts topology first and the experimental gate next, using real
    # installed Controller.start and both kernel policies before opening.
    configure_gate()
    p=UNITDIR/name('gate');p.write_text(p.read_text()+'\n[Install]\nWantedBy=multi-user.target\n')
    ctl('daemon-reload');ctl('enable',name('gate'))
    return load('before-reboot')


def after_boot():
    before=load('before-reboot');pre=load('pre-restore')
    g.wait(lambda:(ROOT/'gate-result.json').exists() and properties('gate')['ActiveState']=='active')
    after=load('gate-result');current=g.project(Store(STATE).load())
    assert boot_id()!=before['boot'] and pre['link']['boot']==boot_id() and not pre['link']['up']
    assert pre['journal']==before['journal']
    # Ruleset metainfo version is not a policy. No tables/rules are allowed.
    assert all(set(row)=={'metainfo'} for row in pre['kernel']['nftables'])
    assert current['phase']=='ROLLED_BACK' and current['current']==POLICY
    assert current['generation']>before['journal']['generation'] and current['boot']==boot_id()
    assert after['kernel']==expected(POLICY) and kernel()==expected(POLICY)
    assert after['receipt']['verified_ns']<=after['opened_ns']<=after['finished_ns']
    assert after['link']['up'] and link()['up']
    # Old boot receipt must never authorize a new open; gate ignores receipts
    # entirely and reconciles live journal. Corrupt it and repeat actual gate.
    stop_gate();save('verified',before['old_receipt'])
    supplied=load('verified');assert supplied==before['old_receipt']
    restored=start_gate();assert restored['exit_code']==0
    revalidation=load('gate-result');receipt=revalidation['receipt']
    assert receipt['boot']==boot_id() and receipt['boot']!=before['old_receipt']['boot']
    assert receipt['generation']==current['generation'] and receipt['policy_digest']==digest(expected(current['current']))
    # Pin the old namespace while creating its successor, making inode reuse
    # impossible during the identity check. Missing-policy rejection is still
    # not an isolated proof of stale-interface admission handling.
    stop_gate();old_inode=link()['namespace_inode']
    ctl('stop',name('networkd'),check=False)
    pinned=os.open(Path('/run/netns',NS),os.O_RDONLY)
    try:
        assert os.fstat(pinned).st_ino==old_inode
        g.cmd(['ip','netns','delete',NS]);topology()
        assert link()['namespace_inode']!=old_inode
        # Same-boot missing-table production reconciliation MUST NOT open.
        rejected=start_gate();assert rejected['exit_code']!=0 and not rejected['link']['up']
        recreated={'old_inode':old_inode,'old_namespace_pinned':True,'new_link':link(),'rejected':rejected}
    finally:os.close(pinned)
    return {'before':before,'pre_agent':pre,'after':after,'journal_after':current,
            'stale_receipt_supplied':supplied,'stale_receipt_revalidated':receipt,
            'stale_receipt_revalidation':revalidation,'same_boot_namespace_recreation':recreated,
            'power_loss_tested':False}


def cleanup():
    assert load('ownership')=={'kind':'rulemoor-boot-spikes-v1'}
    units=[p.name for p in UNITDIR.glob(PREFIX+'*.service')]
    for u in units:
        ctl('disable','--now',u,check=False)
        assert ctl('show',u,'-pMainPID','--value').stdout.strip()=='0'
    p=g.cmd(['ip','netns','pids',NS],check=False)
    for pid in p.stdout.split():os.kill(int(pid),signal.SIGKILL)
    g.cmd(['ip','netns','delete',NS],check=False)
    for u in units:(UNITDIR/u).unlink()
    ctl('daemon-reload')
    if units:ctl('reset-failed',*units,check=False)
    assert NS not in g.cmd(['ip','netns','list']).stdout and not list(UNITDIR.glob(PREFIX+'*.service'))
    return {'namespace_removed':True,'units_removed':True,'root_firewall_unchanged':g.root_rules_digest()==g.load('root-rules-before')['sha256']}


if __name__=='__main__':
    assert os.geteuid()==0
    action=sys.argv[1]
    if action=='gate':gate(sys.argv[2])
    elif action=='close':close_gate()
    elif action=='topology':topology()
    else:print(json.dumps(globals()[action]()),flush=True)
