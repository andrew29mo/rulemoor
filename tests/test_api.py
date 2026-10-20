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
    def test_private_token_file(self):
        f = Path(self.state.name, 'token'); f.write_text('x' * 64); f.chmod(0o644)
        with self.assertRaises(ValueError): secret_file(f)
        f.chmod(0o600); self.assertEqual(secret_file(f), 'x' * 64)
