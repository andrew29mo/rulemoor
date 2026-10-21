"""Production Guard decisions; real kernel/installed-unit evidence is separate."""
import json
from pathlib import Path
import tempfile
import unittest
from rulemoor.boot_guard import Guard, load_profile
from rulemoor.core import Controller, Store
from rulemoor.backend import lock
from test_core import MemoryBackend

PROFILE={'version':1,'interface':'rg0','mac':'02:00:00:77:00:02',
         'namespace':'/run/netns/test','activation_owner':'rulemoor-exclusive','ipv4':'192.0.2.42/24','ipv6':'2001:db8:88::2/64'}
BASE={f:{'default':'drop','rules':[{'port':18443,'verdict':'accept'}]} for f in ('ipv4','ipv6')}
NEXT={f:{'default':'accept','rules':[]} for f in ('ipv4','ipv6')}


class Link:
    def __init__(self):self.up=False;self.fail_close=False;self.fail_open=False;self.on_open=lambda:None
    def read(self):return {'up':self.up,'boot':'test-boot','namespace_inode':123,'ifindex':2}
    def addresses(self):return sorted(PROFILE[f] for f in ('ipv4','ipv6'))
    def prepare(self):
        if self.up:raise RuntimeError('Must prepare while DOWN')
        return self.addresses()
    def set_up(self,value):
        if not value and self.fail_close:raise RuntimeError('close failed')
        if value:
            self.on_open()
            self.up=True
            if self.fail_open:raise RuntimeError('after UP')
        else:self.up=False
        return self.read()


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.b=MemoryBackend();c=Controller(self.root,self.b);c.initialize(BASE);c.close()
        self.link=Link();self.g=Guard(self.root,PROFILE,self.link,self.b)
    def tearDown(self):self.tmp.cleanup()
    def receipt(self):return json.loads(self.g.receipt.read_text())
    def pending(self):
        c=Controller(self.root,self.b);c.start();c.apply('guard-pending',c.s['generation'],NEXT,60);c.close()
    def test_open_and_close_hold_real_ownership_through_up(self):
        def challenge():
            for name in ('agent.lock','writer.lock','guard.lock'):
                with self.assertRaises(RuntimeError):lock(self.root/name)
        self.link.on_open=challenge
        s=self.g.open();self.assertEqual(s['status'],'OPEN');self.assertTrue(self.link.up)
        self.assertLessEqual(s['verified_ns'],s['opened_ns'])
        self.assertEqual(self.g.close()['status'],'CLOSED');self.assertFalse(self.link.up)
    def test_pending_recovery_uses_production_controller(self):
        self.pending();s=self.g.open()
        self.assertEqual(s['phase'],'ROLLED_BACK');self.assertEqual(s['policy'],BASE)
    def test_corrupt_journal_does_not_open(self):
        with Store(self.root).connect() as db:db.execute("UPDATE snapshot SET value='{}'")
        with self.assertRaises(RuntimeError):self.g.open()
        self.assertFalse(self.link.up);self.assertEqual(self.receipt()['status'],'CLOSED')
    def test_backend_recovery_failure_does_not_open(self):
        self.pending()
        def fail(*args):raise RuntimeError('write failed')
        self.b.execute=fail
        with self.assertRaises(RuntimeError):self.g.open()
        self.assertFalse(self.link.up);self.assertEqual(Store(self.root).load()['phase'],'DEGRADED')
    def test_post_up_failure_closes(self):
        self.link.fail_open=True
        with self.assertRaises(RuntimeError):self.g.open()
        self.assertFalse(self.link.up);self.assertEqual(self.receipt()['status'],'CLOSED')
    def test_failed_close_is_faulted(self):
        self.g.open();self.link.fail_close=True
        with self.assertRaises(RuntimeError):self.g.close()
        self.assertTrue(self.link.up);self.assertEqual(self.receipt()['status'],'FAULTED')
    def test_stale_receipt_never_authorizes_open(self):
        self.g.receipt.write_text('{"status":"OPEN","generation":999,"boot":"old"}')
        self.b.value=None
        with self.assertRaises(RuntimeError):self.g.open()
        self.assertFalse(self.link.up)
    def test_profile_is_private_bounded_and_explicit(self):
        path=self.root/'profile.json';path.write_text(json.dumps(PROFILE));path.chmod(0o600)
        self.assertEqual(load_profile(path),PROFILE)
        for key,value in (('version',True),('interface','../eth0'),('namespace','/proc/self/ns/net'),('activation_owner','auto')):
            path.write_text(json.dumps({**PROFILE,key:value}))
            with self.assertRaises(RuntimeError):load_profile(path)
        path.write_text(json.dumps(PROFILE));path.chmod(0o644)
        with self.assertRaises(RuntimeError):load_profile(path)
