"""Real local TLS/API tests; memory backend makes these portable, not nft tests."""
import http.client
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from rulemoor.service import Handler
from rulemoor.core import Controller
from rulemoor.service import Server, secret_file
from tests.test_core import MemoryBackend, BASE, NEXT


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.temp.name)
        config = cls.path / 'cert.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=localhost\n[v3]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(cls.path / 'key'), '-out', str(cls.path / 'cert'), '-config', str(config)],
                       check=True, capture_output=True, timeout=10)
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()
    def setUp(self):
        self.state = tempfile.TemporaryDirectory()
        b = MemoryBackend(); b.clock = time.monotonic
        self.c = Controller(self.state.name, b); self.c.initialize(BASE)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.path / 'cert', self.path / 'key')
        self.server = Server(('127.0.0.1', 0), self.c, 'x' * 64, context)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01})
        self.thread.start(); self.connections = []
    def tearDown(self):
        for c in self.connections: c.close()
        self.server.shutdown(); self.thread.join(2); self.server.server_close()
        self.c.close(); self.state.cleanup()
    def conn(self):
        c = http.client.HTTPSConnection('localhost', self.server.server_port,
                 context=ssl.create_default_context(cafile=str(self.path / 'cert')), timeout=2)
        self.connections.append(c); return c
    def call(self, path, payload=None, conn=None, token=None, headers=None):
        c = conn or self.conn()
        h = {'Authorization': 'Bearer ' + (token or 'x' * 64), 'Content-Type': 'application/json'}
        h.update(headers or {})
        c.request('GET' if payload is None else 'POST', path, json.dumps(payload) if payload is not None else None, h)
        r = c.getresponse(); return r.status, json.loads(r.read())
    def test_authentication(self):
        self.assertEqual(self.call('/status', token='wrong')[0], 401)
        self.assertEqual(self.call('/status')[0], 200)
    def test_full_api_and_keepalive_freshness(self):
        old = self.conn(); self.call('/status', conn=old)
        self.assertEqual(self.call('/plan', {'policy': NEXT})[0], 200)
        code, s = self.call('/apply', {'op': 'api-change', 'generation': 0, 'policy': NEXT, 'window': 5})
        self.assertEqual(code, 200)
        payload = {k: s[k] for k in ('op', 'generation', 'candidate_digest', 'challenge')}
        self.assertEqual(self.call('/confirm', payload, conn=old)[0], 409)
        self.assertEqual(self.call('/confirm', payload)[0], 200)
        self.assertEqual(self.c.s['phase'], 'COMMITTED')
        self.assertGreater(len(self.call('/history')[1]['events']), 0)
    def test_bad_request_does_not_apply(self):
        self.assertEqual(self.call('/apply', {'arbitrary': 1})[0], 400)
        self.assertEqual(self.c.s['generation'], 0)
    def test_content_type_and_transfer_encoding(self):
        self.assertEqual(self.call('/plan', {'policy': NEXT}, headers={'Content-Type': 'text/plain'})[0], 400)
        self.assertEqual(self.call('/plan', {'policy': NEXT}, headers={'Transfer-Encoding': 'chunked'})[0], 400)
    def test_backlog_peer_rejected(self):
        code, s = self.call('/apply', {'op': 'backlog', 'generation': 0, 'policy': NEXT, 'window': 5})
        c = self.conn(); c.connect()
        self.server.blocked_peers.add(c.sock.getsockname())
        payload = {k: s[k] for k in ('op', 'generation', 'candidate_digest', 'challenge')}
        self.assertEqual(self.call('/confirm', payload, conn=c)[0], 409)
    def test_certificate_verification_enforced(self):
        c = http.client.HTTPSConnection('localhost', self.server.server_port, timeout=2)
        self.connections.append(c)
        with self.assertRaises(ssl.SSLCertVerificationError): c.request('GET', '/status')
    def test_cli_reads_max_policy_bounded_history(self):
        from rulemoor.cli import request
        full_policy = {'default': 'accept', 'rules': [{'port': 10000 + i, 'verdict': 'drop'} for i in range(32)]}
        for i in range(20):
            s = self.c.apply('large-' + str(i), self.c.s['generation'], full_policy, 5)
            self.c.cancel(s['op'], s['generation'])
        history = self.c.store.history()
        self.assertGreater(len(json.dumps({'events': history})), 65537)
        response = request('https://localhost:' + str(self.server.server_port), str(self.path / 'cert'), 'x' * 64, '/history')
        self.assertEqual(response['events'], history)
    def test_private_token_file(self):
        f = Path(self.state.name, 'token'); f.write_text('x' * 64); f.chmod(0o644)
        with self.assertRaises(ValueError): secret_file(f)
        f.chmod(0o600); self.assertEqual(secret_file(f), 'x' * 64)

    def test_absolute_lifetime_expires_dripping_unauthenticated_connections(self):
        sockets = []
        with patch('rulemoor.service.MAX_CONNECTION_SECONDS', .3, create=True):
            for _ in range(2):
                c = self.conn(); c.connect(); sockets.append(c.sock)
                c.sock.sendall(b'GET /status HTTP/1.1\r\nX-Slow: ')
            end = time.monotonic() + .7
            while time.monotonic() < end:
                for sock in sockets:
                    try: sock.sendall(b'x')
                    except OSError: pass
                time.sleep(.04)
            with self.server.accepted_lock:
                remaining = len(self.server.accepted)
        self.assertEqual(remaining, 0, 'Header trickle retained slots beyond absolute deadline')
        self.assertEqual(self.call('/status')[0], 200)

    def test_history_network_output_does_not_hold_controller_lock(self):
        entered, release = threading.Event(), threading.Event()
        original = Handler.answer
        def delayed_answer(handler, code, value):
            if handler.path == '/history':
                entered.set(); release.wait(2)
            return original(handler, code, value)
        errors = []
        def reader():
            try: self.call('/history')
            except Exception as exc: errors.append(type(exc).__name__)
        with patch.object(Handler, 'answer', delayed_answer):
            worker = threading.Thread(target=reader); worker.start()
            self.assertTrue(entered.wait(1))
            acquired = self.c.mutex.acquire(timeout=.05)
            if acquired: self.c.mutex.release()
            release.set(); worker.join(2)
        self.assertTrue(acquired, 'A blocked HTTP write stalled controller decisions')
        self.assertFalse(errors)

    def test_configured_management_guard_is_production_api_admission(self):
        self.c.management_paths=[{'name':'api','port':self.server.server_port}]
        before=self.c.status();kernel=self.c.backend.value
        policy={'default':'drop','rules':[]}
        code,plan=self.call('/plan',{'policy':policy})
        self.assertEqual(code,200);self.assertEqual(plan['diagnostics']['own_policy']['status'],'blocked')
        code,response=self.call('/apply',{'op':'guarded','generation':0,'policy':policy,'window':5})
        self.assertEqual(code,409);self.assertEqual(response['diagnostics']['own_policy']['status'],'blocked')
        self.assertEqual(self.c.status(),before);self.assertEqual(self.c.backend.value,kernel)

    def test_configured_guard_preserves_fresh_confirmation_requirement(self):
        self.c.management_paths=[{'name':'api','port':self.server.server_port}]
        old=self.conn();self.call('/status',conn=old)
        policy={'default':'drop','rules':[{'port':self.server.server_port,'verdict':'accept'}]}
        code,s=self.call('/apply',{'op':'guarded-allow','generation':0,'policy':policy,'window':5})
        self.assertEqual(code,200)
        payload={k:s[k] for k in ('op','generation','candidate_digest','challenge')}
        self.assertEqual(self.call('/confirm',payload,conn=old)[0],409)
        self.assertEqual(self.call('/confirm',payload)[0],200)
