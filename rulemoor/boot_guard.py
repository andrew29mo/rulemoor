"""Opt-in interface startup gate; policy decisions belong to Controller.

This MVP supports a named, separately managed veth namespace only. Receipts are
observations, never authority to open a link. No assertion controls safety.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
from .backend import NftBackend, atomic_json, boot_id, lock
from .core import Controller, Store, TERMINAL
from .policy import expected, digest


def require(value, reason):
    if not value:raise RuntimeError(reason)


def load_profile(path):
    path=Path(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        require(st.st_uid==os.geteuid() and not st.st_mode & 0o077,'Profile must be private and owned by service user')
        raw=os.read(fd,4097)
    finally:os.close(fd)
    require(len(raw)<=4096,'Profile exceeds 4 KiB')
    p=json.loads(raw)
    require(isinstance(p,dict) and set(p)=={'version','interface','mac','namespace','activation_owner','ipv4','ipv6'},'Invalid profile fields')
    require(type(p['version']) is int and p['version']==1,'Unsupported profile version')
    require(isinstance(p['interface'],str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,15}',p['interface']),'Invalid interface')
    require(isinstance(p['mac'],str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',p['mac']),'Invalid MAC')
    require(isinstance(p['namespace'],str) and re.fullmatch(r'/run/netns/[a-zA-Z0-9_-]{1,48}',p['namespace']),'Named namespace required')
    require(p['activation_owner']=='rulemoor-exclusive','Explicit exclusive activation profile required')
    for key,version in (('ipv4',4),('ipv6',6)):
        require(isinstance(p[key],str),'Static dual-stack addresses required')
        addr=ipaddress.ip_interface(p[key])
        require(addr.version==version and str(addr)==p[key] and not (addr.ip.is_multicast or addr.ip.is_unspecified or addr.ip.is_loopback or addr.ip.is_link_local),'Invalid static address')
    return p


class Interface:
    def __init__(self,profile):self.profile=profile

    def run(self,*args):
        p=subprocess.run(['ip',*args],capture_output=True,text=True,timeout=2)
        require(p.returncode==0,'Interface operation failed')
        return p.stdout

    def read(self):
        p=self.profile
        current=Path('/proc/self/ns/net').stat().st_ino
        require(current==Path(p['namespace']).stat().st_ino,'Wrong network namespace')
        # The bounded root setup step snapshots PID 1's namespace before the
        # main service runs with reduced capabilities. Plain root CLI use can
        # inspect PID 1 directly; restricted service use verifies a fresh anchor.
        try:host=Path('/proc/1/ns/net').stat().st_ino
        except PermissionError:
            fd=os.open('/run/rulemoor-boot-guard/host.json',os.O_RDONLY|os.O_NOFOLLOW)
            try:
                st=os.fstat(fd);raw=os.read(fd,1025)
            finally:os.close(fd)
            require(st.st_uid==0 and not st.st_mode & 0o077 and len(raw)<=1024,'Invalid namespace anchor')
            anchor=json.loads(raw)
            require(set(anchor)=={'boot','namespace_inode'} and anchor['boot']==boot_id(),'Stale namespace anchor')
            host=anchor['namespace_inode']
            require(type(host) is int and host>0,'Invalid namespace anchor identity')
        require(current!=host,'Root namespace is unsupported')
        rows=json.loads(self.run('-j','-d','link','show','dev',p['interface']))
        require(len(rows)==1,'Ambiguous interface')
        r=rows[0]
        require(r.get('ifname')==p['interface'] and r.get('address')==p['mac'],'Interface identity changed')
        require(r.get('linkinfo',{}).get('info_kind')=='veth','Only isolated veth profiles are supported')
        return {'boot':boot_id(),'namespace_inode':current,'host_namespace_inode':host,'ifindex':r['ifindex'],
                'interface':p['interface'],'mac':p['mac'],'kind':'veth','up':'UP' in r['flags']}

    def set_up(self,value):
        before=self.read()
        self.run('link','set','dev',self.profile['interface'],'up' if value else 'down')
        after=self.read()
        require({k:v for k,v in before.items() if k!='up'}=={k:v for k,v in after.items() if k!='up'},'Interface replaced during activation')
        require(after['up'] is value,'Interface state readback failed')
        return after

    def addresses(self):
        rows=json.loads(self.run('-j','addr','show','dev',self.profile['interface']))
        return sorted(str(ipaddress.ip_interface(a['local']+'/'+str(a['prefixlen'])))
                      for row in rows for a in row['addr_info'] if a['scope']=='global')

    def prepare(self):
        require(not self.read()['up'],'Addresses must be prepared while DOWN')
        wanted=sorted(self.profile[f] for f in ('ipv4','ipv6'))
        actual=self.addresses()
        require(set(actual).issubset(wanted),'Foreign global addresses on controlled interface')
        # Linux may discard even static IPv6 addresses on DOWN. Restore only
        # explicitly owned profile addresses before opening, never flush extras.
        for key,flag in (('ipv4','-4'),('ipv6','-6')):
            if self.profile[key] not in actual:
                self.run(flag,'addr','add',self.profile[key],'dev',self.profile['interface'],*(['nodad'] if key=='ipv6' else []))
        require(self.addresses()==wanted,'Static address readback failed')
        return wanted


class Guard:
    def __init__(self,root,profile,interface=None,backend=None):
        self.root=Path(root);self.profile=profile
        require(self.root.is_dir() and not self.root.is_symlink() and not self.root.stat().st_mode & 0o077,'Existing private state directory required')
        self.interface=interface or Interface(profile)
        self.backend=backend or NftBackend(dual_stack=True)
        self.receipt=self.root/'boot-guard.json'

    def record(self,status,**kw):
        value={'schema':1,'status':status,'profile_digest':digest(self.profile),'clock':'monotonic_ns',
               'observed_ns':time.monotonic_ns(),**kw}
        atomic_json(self.receipt,value)
        return value

    def close_locked(self):
        receipt_error=None
        try:
            before=self.interface.read()
            # Observations must never be a prerequisite for closing the link.
            # Preserve a failed write as a service failure even if DOWN succeeds.
            try:self.record('CLOSING',link=before)
            except Exception as exc:receipt_error=exc
            after=self.interface.set_up(False)
        except Exception:
            try:self.record('FAULTED',reason='Cannot verify interface DOWN; local recovery required')
            except Exception:pass  # Keep the actual interface failure, not a logging error.
            raise
        closed=self.record('CLOSED',link=after)
        if receipt_error is not None:raise receipt_error
        return closed

    def close(self):
        fd=lock(self.root/'guard.lock')
        try:return self.close_locked()
        finally:os.close(fd)

    def open(self):
        began=time.monotonic_ns();guard_fd=lock(self.root/'guard.lock');controller=None;writer=None
        try:
            initial=self.interface.read()
            require(not initial['up'],'Explicit close required before opening')
            self.record('RESTORING',link=initial)
            controller=Controller(self.root,self.backend)
            status=controller.start()
            require(status['phase'] in TERMINAL and not controller.storage_failed,'Recovery not ready')
            writer=lock(self.root/'writer.lock')
            live=Store(self.root).load()
            require(live==controller.s and self.backend.read()==expected(live['current']),'Live journal/policy mismatch')
            addresses=self.interface.prepare()
            now=self.interface.read()
            require(now==initial,'Interface changed during restoration')
            self.record('POLICY_READY',link=now,generation=live['generation'],policy_digest=digest(expected(live['current'])))
            verified=time.monotonic_ns()
            self.record('OPENING',link=now,generation=live['generation'])
            opened=self.interface.set_up(True)
            opened_at=time.monotonic_ns()
            require(self.backend.read()==expected(live['current']) and Store(self.root).load()==live,'Policy changed during activation')
            require(self.interface.addresses()==addresses,'Static addresses changed during activation')
            return self.record('OPEN',link=opened,verified_link=now,boot=live['boot'],
                               generation=live['generation'],phase=live['phase'],
                               policy=live['current'],policy_digest=digest(expected(live['current'])),
                               kernel=self.backend.read(),addresses=addresses,started_ns=began,verified_ns=verified,opened_ns=opened_at)
        except Exception:
            self.close_locked()
            raise
        finally:
            if writer is not None:os.close(writer)
            if controller is not None:controller.close()
            os.close(guard_fd)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--state',required=True);p.add_argument('--profile',required=True)
    p.add_argument('action',choices=('open','close','anchor'))
    a=p.parse_args()
    require(os.geteuid()==0,'Boot Guard requires root in the isolated namespace')
    os.umask(0o077)
    profile=load_profile(a.profile)
    if a.action=='anchor':
        directory=Path('/run/rulemoor-boot-guard')
        st=directory.stat()
        require(not directory.is_symlink() and st.st_uid==0 and not st.st_mode & 0o077,'Private runtime directory required')
        atomic_json(directory/'host.json',{'boot':boot_id(),'namespace_inode':Path('/proc/1/ns/net').stat().st_ino})
        return
    g=Guard(a.state,profile)
    print(json.dumps(g.open() if a.action=='open' else g.close()))


if __name__=='__main__':main()
