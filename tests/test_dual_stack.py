"""Formal dual-policy/state/API tests; actual nft effects are a separate VM case."""
import copy
import http.client
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from rulemoor.backend import NftBackend
from rulemoor.cli import request
from rulemoor.core import Controller, Conflict, Store, validate_snapshot
from rulemoor.policy import validate, compile_policy, expected
from rulemoor.service import Server, Server6
from tests.test_core import MemoryBackend, BASE, NEXT

BASE_DUAL={'ipv4':BASE,'ipv6':BASE}
NEXT_DUAL={'ipv4':NEXT,'ipv6':{'default':'drop','rules':[]}}


def confirm(c,s,family):
    return c.confirm(**{k:s[k] for k in ('op','generation','candidate_digest','challenge')},
                     connected_at=c.backend.clock()+.001,transport_family=family)


class DualCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.b=MemoryBackend()
        self.c=Controller(self.temp.name,self.b);self.c.initialize(BASE_DUAL)
    def tearDown(self):self.c.close();self.temp.cleanup()
    def apply(self):return self.c.apply('dual',0,NEXT_DUAL,10)

    def test_dual_policy_schema_and_single_batch(self):
        p=validate(BASE_DUAL);p['ipv6']['rules'].clear();self.assertEqual(len(BASE_DUAL['ipv6']['rules']),1)
        text=compile_policy(NEXT_DUAL)
        self.assertIn('delete table ip rulemoor',text);self.assertIn('delete table ip6 rulemoor',text)
        self.assertIn('meta l4proto ipv6-icmp accept',text)
        rows=expected(NEXT_DUAL)
        self.assertEqual([r['chain']['policy'] for r in rows if 'chain' in r],['drop','drop'])
        self.assertEqual({next(iter(r.values()))['family'] for r in rows},{'ip','ip6'})
        for bad in ({'ipv4':BASE}, {'ipv4':BASE,'ipv6':BASE,'default':'drop'}, {'ipv4':BASE_DUAL,'ipv6':BASE}, {'ipv4':BASE,'ipv6':{'default':'drop','rules':[{'port':True,'verdict':'accept'}]}}):
            with self.subTest(bad=bad),self.assertRaises(ValueError):validate(bad)

    def test_ipv4_repetition_cannot_commit_or_extend_deadline(self):
        s=self.apply();deadline=s['deadline']
        with self.assertRaises(Conflict):confirm(self.c,s,None)
        for _ in range(2):
            partial=confirm(self.c,s,'ipv4')
            self.assertEqual(partial['phase'],'AWAITING_CONFIRM')
            self.assertEqual(partial['confirmed_families'],['ipv4']);self.assertEqual(partial['deadline'],deadline)
            self.assertEqual(self.c.store.load()['phase'],'AWAITING_CONFIRM')
        self.b.t=deadline;self.c.tick()
        self.assertEqual(self.c.status()['phase'],'ROLLED_BACK')
        self.assertEqual(self.b.read(),expected(BASE_DUAL))
        with self.assertRaises(Conflict):confirm(self.c,s,'ipv6')

    def test_two_families_commit_in_either_order(self):
        s=self.apply();confirm(self.c,s,'ipv6');committed=confirm(self.c,s,'ipv4')
        self.assertEqual(committed['phase'],'COMMITTED');self.assertEqual(committed['confirmed_families'],['ipv4','ipv6'])
        self.assertEqual(committed['current'],NEXT_DUAL)
        self.c.close();self.c=Controller(self.temp.name,self.b)
        self.assertEqual(self.c.start()['phase'],'COMMITTED')
        self.assertEqual(self.b.read(),expected(NEXT_DUAL))

    def test_partial_confirmation_failure_is_not_persisted_in_memory(self):
        s=self.apply()
        with patch.object(self.c.store,'save',side_effect=OSError('injected full disk')):
            with self.assertRaises(OSError):confirm(self.c,s,'ipv4')
        self.assertEqual(self.c.status()['confirmed_families'],[])
        confirm(self.c,s,'ipv4')
        with patch.object(self.c.store,'save',side_effect=OSError('injected full disk')):
            with self.assertRaises(OSError):confirm(self.c,s,'ipv6')
        self.assertEqual(self.c.status()['phase'],'AWAITING_CONFIRM')
        self.assertEqual(self.c.status()['confirmed_families'],['ipv4'])

    def test_partial_confirmation_restart_and_reboot_restore_both(self):
        for reboot in (False,True):
            with self.subTest(reboot=reboot),tempfile.TemporaryDirectory() as root:
                b=MemoryBackend();c=Controller(root,b);c.initialize(BASE_DUAL)
                s=c.apply('pending',0,NEXT_DUAL,10);confirm(c,s,'ipv4');c.close()
                if reboot:b.boot_value='new-boot';b.value=None
                c=Controller(root,b)
                try:
                    restored=c.start();self.assertEqual(restored['phase'],'ROLLED_BACK')
                    self.assertEqual(b.read(),expected(BASE_DUAL));self.assertGreater(restored['generation'],s['generation'])
                    newer=c.apply('newer',restored['generation'],BASE_DUAL,10)
                    with self.assertRaises(Conflict):confirm(c,s,'ipv6')
                    self.assertEqual(c.status(),newer)
                finally:c.close()

    def test_journal_rejects_missing_duplicate_or_full_pending_confirmations(self):
        s=self.apply()
        for value in (None,['ipv4','ipv4'],['ipv4','ipv6'],['ipv7'],['ipv6','ipv4']):
            bad=copy.deepcopy(s);bad['confirmed_families']=value
            with self.subTest(value=value),self.assertRaises(ValueError):validate_snapshot(bad)
        bad=copy.deepcopy(s);del bad['confirmed_families']
        with self.assertRaises(ValueError):validate_snapshot(bad)
        with self.assertRaises(Conflict):self.c.cancel('old',0)

    def test_policy_mode_cannot_switch_or_adopt_legacy(self):
        with self.assertRaises(Conflict):self.c.apply('switch',0,BASE,10)
        with self.assertRaises(Conflict):self.c.plan(BASE)
        b=NftBackend(dual_stack=True)
        with patch('rulemoor.backend.subprocess.run') as run:
            with self.assertRaises(RuntimeError):b.check(BASE)
            run.assert_not_called()

    def test_partial_table_read_is_not_absence_and_mode_check_precedes_writes(self):
        b=NftBackend(dual_stack=True)
        def run(args,**kwargs):
            if args[-2]=='ip':return SimpleNamespace(returncode=0,stdout=json.dumps({'nftables':expected(BASE)}),stderr='')
            return SimpleNamespace(returncode=1,stdout='',stderr='No such file or directory')
        with patch('rulemoor.backend.subprocess.run',side_effect=run):
            self.assertEqual(b.read(),expected(BASE));self.assertIsNotNone(b.read())
        s=self.apply();self.c.close()
        b=NftBackend()
        self.c=Controller(self.temp.name,b)
        with patch.object(b,'read',side_effect=AssertionError('mode mismatch must stop before kernel access')):
            self.assertEqual(self.c.start()['phase'],'DEGRADED')


class DualAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.path=Path(cls.temp.name)
        import subprocess
        config=cls.path/'cert.cnf';config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=localhost\n[v3]\nsubjectAltName=IP:127.0.0.1,IP:::1\n')
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(cls.path/'key'),'-out',str(cls.path/'cert'),'-config',str(config)],check=True,capture_output=True,timeout=10)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def setUp(self):
        self.state=tempfile.TemporaryDirectory();b=MemoryBackend();b.clock=time.monotonic
        self.c=Controller(self.state.name,b);self.c.initialize(BASE_DUAL)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.path/'cert',self.path/'key')
        self.servers=[Server(('127.0.0.1',0),self.c,'x'*64,context),Server6(('::1',0),self.c,'x'*64,context)]
        self.threads=[threading.Thread(target=s.serve_forever,kwargs={'poll_interval':.01}) for s in self.servers]
        for t in self.threads:t.start()
        self.connections=[]
    def tearDown(self):
        for c in self.connections:c.close()
        for s,t in zip(self.servers,self.threads):s.shutdown();t.join(2);s.server_close()
        self.c.close();self.state.cleanup()
    def conn(self,family):
        i=0 if family=='ipv4' else 1
        c=http.client.HTTPSConnection('127.0.0.1' if i==0 else '::1',self.servers[i].server_port,context=ssl.create_default_context(cafile=str(self.path/'cert')),timeout=2)
        self.connections.append(c);return c
    def call(self,c,path,payload=None):
        c.request('GET' if payload is None else 'POST',path,json.dumps(payload) if payload is not None else None,{'Authorization':'Bearer '+'x'*64,'Content-Type':'application/json'})
        r=c.getresponse();return r.status,json.loads(r.read())
    def test_real_transports_old_connections_and_body_spoof(self):
        old4=self.conn('ipv4');old6=self.conn('ipv6')
        self.assertEqual(self.call(old4,'/status')[0],200);self.assertEqual(self.call(old6,'/status')[0],200)
        code,s=self.call(self.conn('ipv4'),'/apply',{'op':'dual-api','generation':0,'policy':NEXT_DUAL,'window':5})
        self.assertEqual(code,200);payload={k:s[k] for k in ('op','generation','candidate_digest','challenge')}
        self.assertEqual(self.call(old4,'/confirm',payload)[0],409);self.assertEqual(self.call(old6,'/confirm',payload)[0],409)
        self.assertEqual(self.call(self.conn('ipv4'),'/confirm',{**payload,'transport_family':'ipv6'})[0],400)
        for _ in range(2):
            code,partial=self.call(self.conn('ipv4'),'/confirm',payload)
            self.assertEqual(code,200);self.assertEqual(partial['phase'],'AWAITING_CONFIRM');self.assertEqual(partial['confirmed_families'],['ipv4'])
        code,committed=self.call(self.conn('ipv6'),'/confirm',payload)
        self.assertEqual(code,200);self.assertEqual(committed['phase'],'COMMITTED');self.assertEqual(committed['confirmed_families'],['ipv4','ipv6'])
        self.assertEqual(self.servers[1].socket.getsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY),1)
    def test_cli_family_is_literal_and_cannot_fallback(self):
        for family,url in (('ipv6','https://127.0.0.1'),('ipv4','https://[::1]'),('ipv6','https://localhost')):
            with self.subTest(family=family,url=url),self.assertRaises(ValueError):request(url,str(self.path/'cert'),'x'*64,'/status',family=family)
        for family,i,host in (('ipv4',0,'127.0.0.1'),('ipv6',1,'[::1]')):
            result=request('https://'+host+':'+str(self.servers[i].server_port),str(self.path/'cert'),'x'*64,'/status',family=family)
            self.assertEqual(result['current'],BASE_DUAL)

    def test_ipv6_backlog_snapshot_uses_tcp6_word_order_and_peer_pair(self):
        server=self.servers[1];port=server.server_port
        address='20010db8000000000000000000000001'
        raw=bytes.fromhex(address);proc_hex=b''.join(raw[i:i+4][::-1] for i in range(0,16,4)).hex().upper()
        row=f'0: {"0"*32}:{port:04X} {proc_hex}:3039 01 0:0 00:0 0 0 0 0\n'
        def read(path,*args,**kwargs):
            self.assertEqual(str(path),'/proc/net/tcp6');return 'header\n'+row
        with patch.object(Path,'read_text',read):server.snapshot_connections()
        self.assertEqual(server.blocked_peers,{('2001:db8::1',12345)})
