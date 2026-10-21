"""Installed dual systemd service: configured admission and read-only foreign rules."""
import copy
import json
import signal
import subprocess
import time
from pathlib import Path
from . import deployment_guest as g
from . import dual_recovery as d
from rulemoor.backend import identity, boot_id
from rulemoor.policy import canonical, expected

PORT=59999
PATHS=[{'name':name+suffix,'family':family,'port':port}
       for family,suffix in (('ipv4','4'),('ipv6','6')) for name,port in (('api',18443),('probe',PORT))]
OPEN=copy.deepcopy(d.FINAL)
for family in ('ipv4','ipv6'):OPEN[family]['rules'].insert(1,{'port':PORT,'verdict':'accept'})


def run():
    assert d.kernel()==expected(d.FINAL) and g.request()['phase']=='COMMITTED'
    config=g.CONFIG/'dual-management-paths.json';config.write_text(json.dumps({'paths':PATHS}))
    drop=Path('/etc/systemd/system/rulemoor.service.d/50-dual-management.conf')
    original=next(line for line in Path('/etc/systemd/system/rulemoor.service.d/40-dual-recovery.conf').read_text().splitlines() if line.startswith('ExecStart=') and len(line)>10)
    drop.write_text('[Service]\nExecStart=\n'+original+' --management-paths /etc/rulemoor/dual-management-paths.json\n')
    def restart():
        g.cmd(['systemctl','daemon-reload']);g.cmd(['systemctl','reset-failed',g.UNIT]);g.cmd(['systemctl','restart',g.UNIT]);g.ready()
    restart()
    listener=subprocess.Popen(['ip','netns','exec',g.NS,g.PYTHON,'-I','-c',
        '''import selectors,socket
sel=selectors.DefaultSelector()
for af,host in ((socket.AF_INET,'192.0.2.22'),(socket.AF_INET6,'2001:db8:55::2')):
 s=socket.socket(af,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if af==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((host,59999));s.listen();sel.register(s,selectors.EVENT_READ)
while True:
 for key,_ in sel.select():
  c,_=key.fileobj.accept();c.close()
'''],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,cwd='/')
    listener_id=identity(listener.pid);assert listener_id
    table='rm_dual_preflight'
    active_family=None
    cleanup={}
    def observe_listener():
        result={'poll':listener.poll(),'identity':identity(listener.pid)}
        assert result=={'poll':None,'identity':listener_id}
        return result
    def probes():
        before=observe_listener()
        result=d.peer('''import socket
out={}
for f,af,host in (('ipv4',socket.AF_INET,'192.0.2.22'),('ipv6',socket.AF_INET6,'2001:db8:55::2')):
 s=socket.socket(af,socket.SOCK_STREAM);s.settimeout(.25);e=s.connect_ex((host,59999));s.close();out[f]={'connected':e==0,'errno':e}
print(json.dumps(out))
''')
        return {'families':result,'listener_before':before,'listener_after':observe_listener()}
    def foreign():
        return canonical(json.loads(g.cmd(['ip','netns','exec',g.NS,'nft','-j','-s','list','table',active_family,table]).stdout))
    def remove():
        nonlocal active_family
        if active_family:g.cmd(['ip','netns','exec',g.NS,'nft','delete','table',active_family,table]);active_family=None
    def install(family,priority,rule):
        nonlocal active_family
        assert active_family is None
        g.cmd(['ip','netns','exec',g.NS,'nft','-f','-'],input=f'table {family} {table} {{\n chain input {{\n type filter hook input priority {priority}; policy accept;\n {rule}\n }}\n}}\n');active_family=family
    def plan(p):return g.request('/plan',{'policy':p})['diagnostics']
    try:
        baseline=g.project(g.request());before_kernel=d.kernel()
        blocked=copy.deepcopy(OPEN);blocked['ipv6']={'default':'drop','rules':[]}
        denied=plan(blocked);assert denied['family_statuses']['ipv4']['own_policy']=='allowed' and denied['family_statuses']['ipv6']['own_policy']=='blocked'
        before=g.journal_projection();g.request('/apply',{'op':'dual-preflight-denied','generation':before['generation'],'policy':blocked,'window':30},rejected=True)
        after=g.journal_projection();after_kernel=d.kernel();assert before==after and before_kernel==after_kernel
        admitted=d.commit('dual-preflight-open',OPEN)
        g.wait(lambda:all(p['connected'] for p in probes()['families'].values()))
        cases=[]
        for family,priority,rule in (('ip6',-100,'tcp dport 59999 drop'),('ip6',10,'tcp dport 59999 drop'),('inet',-100,'meta nfproto ipv6 tcp dport 59999 drop')):
            before_probe=probes();assert all(p['connected'] for p in before_probe['families'].values())
            install(family,priority,rule);raw=foreign();blocked_probe=probes()
            assert blocked_probe['families']['ipv4']=={'connected':True,'errno':0}
            assert blocked_probe['families']['ipv6']['errno'] in (11,110)
            began=time.monotonic_ns();diagnostics=plan(OPEN);ended=time.monotonic_ns()
            assert diagnostics['family_statuses']['ipv4']['external']=='no_observed_input_conflict' and diagnostics['family_statuses']['ipv6']['external']=='blocked'
            after_plan=foreign();assert after_plan==raw
            new=d.apply('dual-foreign-'+family+str(priority).replace('-','m'),OPEN)
            partial=d.confirm(new,'ipv4');assert partial['phase']=='AWAITING_CONFIRM'
            g.request('/cancel',{'op':new['op'],'generation':new['generation']});g.ready('ROLLED_BACK')
            after_operations=foreign();assert after_operations==raw and d.kernel()==expected(OPEN)
            remove();recovered_probe=probes();assert all(p['connected'] for p in recovered_probe['families'].values())
            cases.append({'family':family,'priority':priority,'diagnostics':diagnostics,'foreign_before':raw,'foreign_after_plan':after_plan,
                          'foreign_after_operations':after_operations,'before':before_probe,'blocked':blocked_probe,'recovered':recovered_probe,
                          'partial':g.project(partial),'plan_clock':{'clock':'monotonic_ns','started_ns':began,'finished_ns':ended},'plan_observed_ms':(ended-began)/1e6})
        install('ip6',10,'ip6 saddr 2001:db8:55::1 tcp dport 59999 drop')
        unknown_raw=foreign();unknown=plan(OPEN)
        assert unknown['family_statuses']['ipv4']['external']=='no_observed_input_conflict' and unknown['family_statuses']['ipv6']['external']=='risk'
        unknown_probe=probes();assert unknown_probe['families']['ipv6']['errno'] in (11,110)
        new=d.apply('dual-unknown',OPEN);unknown_receipt=new['diagnostics'];unknown_partial=d.confirm(new,'ipv4')
        g.request('/cancel',{'op':new['op'],'generation':new['generation']});g.ready('ROLLED_BACK')
        unknown_after=foreign();assert unknown_raw==unknown_after;remove();unknown_recovered=probes()
        assert all(p['connected'] for p in unknown_recovered['families'].values())
        # With the guard configured, old connections still cannot confirm either family.
        confirmation=d.peer('''import http.client,ssl
old={}
for f,host in (('ipv4','192.0.2.22'),('ipv6','2001:db8:55::2')):
 c=http.client.HTTPSConnection(host,18443,context=ssl.create_default_context(cafile=ca),timeout=2)
 c.request('GET','/status',headers={'Authorization':'Bearer '+token});r=c.getresponse();assert r.status==200;r.read();old[f]=c
s0=call('ipv4');s=call('ipv4','/apply',{'op':'dual-guard-fresh','generation':s0['generation'],'policy':json.loads(sys.argv[1]),'window':10})
statuses={}
for f,c in old.items():
 c.request('POST','/confirm',json.dumps(payload(s)),{'Authorization':'Bearer '+token,'Content-Type':'application/json'})
 r=c.getresponse();statuses[f]=r.status;r.read();c.close();assert statuses[f]==409
partial=call('ipv4','/confirm',payload(s));assert partial['phase']=='AWAITING_CONFIRM'
committed=call('ipv6','/confirm',payload(s));assert committed['phase']=='COMMITTED'
print(json.dumps({'old_status':statuses,'partial':projection(partial),'committed':projection(committed)}))
''',json.dumps(OPEN))
        # Restore a baseline that the currently configured probe guard would reject.
        drop.unlink();restart();d.commit('dual-unguarded-baseline',d.FINAL)
        drop.write_text('[Service]\nExecStart=\n'+original+' --management-paths /etc/rulemoor/dual-management-paths.json\n');restart()
        recovery=[]
        for mode in ('cancel','deadline','restart'):
            rejected_baseline=plan(d.FINAL);assert rejected_baseline['own_policy']['status']=='blocked'
            s=d.apply('dual-guard-restore-'+mode,OPEN,3 if mode=='deadline' else 30);partial=d.confirm(s,'ipv4')
            kernel_pending=d.kernel();assert kernel_pending==expected(OPEN)
            if mode=='cancel':g.request('/cancel',{'op':s['op'],'generation':s['generation']})
            elif mode=='restart':g.cmd(['systemctl','kill','--kill-whom=main','--signal=SIGKILL',g.UNIT])
            restored=g.project(g.ready('ROLLED_BACK'));kernel_restored=d.kernel()
            assert kernel_restored==expected(d.FINAL) and restored['current']==d.FINAL
            fresh=d.peer("print(json.dumps({f:projection(call(f)) for f in urls}))")
            assert fresh['ipv4']==fresh['ipv6']==restored
            recovery.append({'mode':mode,'baseline_plan':rejected_baseline,'partial':g.project(partial),'kernel_pending':kernel_pending,
                             'restored':restored,'kernel_restored':kernel_restored,'fresh_tls':fresh})
        sample=g.memory();assert sample['process_identity']['boot']==boot_id()
        return {'boot':boot_id(),'baseline':baseline,'paths':PATHS,'own_denied':denied,'journal_before_denial':before,'journal_after_denial':after,
                'kernel_before_denial':before_kernel,'kernel_after_denial':after_kernel,'admitted':g.project(admitted),'foreign_cases':cases,
                'unknown':{'diagnostics':unknown,'apply_diagnostics':unknown_receipt,'foreign_before':unknown_raw,'foreign_after':unknown_after,
                           'probe':unknown_probe,'recovered_probe':unknown_recovered,'partial':g.project(unknown_partial)},
                'confirmations':confirmation,'recoveries':recovery,'listener_identity':listener_id,'memory':sample,'cleanup':cleanup}
    finally:
        remove()
        if listener.poll() is None:listener.send_signal(signal.SIGTERM)
        listener.wait(timeout=3);cleanup['listener_reaped']=listener.poll() is not None
        drop.unlink(missing_ok=True);config.unlink(missing_ok=True)
        g.cmd(['systemctl','daemon-reload']);g.cmd(['systemctl','reset-failed',g.UNIT]);g.cmd(['systemctl','restart',g.UNIT]);g.ready()
        cleanup['configuration_removed']=not drop.exists() and not config.exists()
        cleanup['foreign_tables_absent']=all(g.cmd(['ip','netns','exec',g.NS,'nft','list','table',f,table],check=False).returncode!=0 for f in ('ip6','inet'))
