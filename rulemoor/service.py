"""Bounded TLS management API; credentials and certificates are provisioned externally."""
import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import ssl
import threading
import time
import socket
from .backend import NftBackend
from .core import Controller, Conflict, PreflightRejected
from .diagnostics import load_paths

MAX_BODY = 16384
MAX_CONNECTION_SECONDS = 5.0


def secret_file(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise ValueError('Secret file must be private and not a symlink')
    value = path.read_text().strip()
    if len(value) < 32 or len(value) > 256 or not value.isascii() or any(c.isspace() for c in value):
        raise ValueError('Token must contain 32–256 non-whitespace ASCII characters')
    return value


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, controller, token, context):
        self.controller, self.token, self.context = controller, token, context
        self.slots = threading.BoundedSemaphore(16)
        self.accepted = {}
        self.deadlines = {}
        self.blocked_peers = set()
        self.accepted_lock = threading.Lock()
        super().__init__(address, Handler)

    def snapshot_connections(self):
        # TCP may already be established in the listen backlog before accept().
        # Record those peers after apply, so an old queued connection cannot be
        # misclassified as fresh merely because userspace accepted it later.
        peers = set()
        port = self.server_address[1]
        for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
            fields = line.split()
            local, remote, state = fields[1:4]
            if int(local.split(':')[1], 16) == port and state != '0A':
                addr, remote_port = remote.split(':')
                peers.add((socket.inet_ntoa(bytes.fromhex(addr)[::-1]), int(remote_port, 16)))
        self.blocked_peers = peers

    def handle_error(self, request, client_address):
        # Deliberately avoid default traceback logging of operator addresses.
        pass

    @staticmethod
    def expire_connection(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        # The handler owns close/releasing the slot. Keeping its fd valid until
        # shutdown_request also prevents an expired socket from deleting a reused fd.

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(2)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Timestamp TCP acceptance, before TLS handshake or any HTTP request.
        at = self.controller.backend.clock()
        if not self.slots.acquire(False):
            sock.close()
            raise OSError('Connection capacity reached')
        try:
            sock = self.context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
            with self.accepted_lock:
                self.accepted[sock.fileno()] = at
                timer = threading.Timer(MAX_CONNECTION_SECONDS, self.expire_connection, args=(sock,))
                timer.daemon = True
                self.deadlines[sock.fileno()] = timer
            timer.start()
            return sock, addr
        except BaseException:
            self.slots.release()
            sock.close()
            raise

    def shutdown_request(self, request):
        with self.accepted_lock:
            self.accepted.pop(request.fileno(), None)
            timer = self.deadlines.pop(request.fileno(), None)
            if timer:
                timer.cancel()
        try:
            super().shutdown_request(request)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'Rulemoor'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connected_at = self.server.accepted[self.connection.fileno()]
        self.connection.do_handshake()

    def log_message(self, *args):
        pass  # No credentials, request bodies, paths or operator addresses in default logs.

    def answer(self, code, value):
        data = json.dumps(value).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def dispatch(self):
        if not hmac.compare_digest(self.headers.get('Authorization', '').encode(), ('Bearer ' + self.server.token).encode()):
            self.close_connection = True
            return self.answer(401, {'error': 'Unauthorized'})
        try:
            c = self.server.controller
            if self.command == 'GET':
                if self.path == '/status':
                    return self.answer(200, c.status())
                if self.path == '/history':
                    with c.mutex:
                        events = c.store.history()
                    return self.answer(200, {'events': events})
                return self.answer(404, {'error': 'Not found'})
            if self.headers.get('Transfer-Encoding') is not None:
                raise ValueError('Chunked bodies are not supported')
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not lengths[0].isdigit():
                raise ValueError('Exactly one Content-Length required')
            length = int(lengths[0])
            if not 0 < length <= MAX_BODY:
                raise ValueError('Body length outside budget')
            if self.headers.get_content_type() != 'application/json':
                raise ValueError('Expected application/json')
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('Incomplete body')
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError('Expected JSON object')
            routes = {'/plan': ({'policy'}, lambda: c.plan(data['policy'])),
                      '/apply': ({'op', 'generation', 'policy', 'window'}, lambda: c.apply(**data)),
                      '/confirm': ({'op', 'generation', 'candidate_digest', 'challenge'},
                                   lambda: c.confirm(**data, connected_at=self.connected_at)),
                      '/cancel': ({'op', 'generation'}, lambda: c.cancel(**data))}
            if self.path not in routes:
                return self.answer(404, {'error': 'Not found'})
            if self.path == '/confirm' and self.client_address in self.server.blocked_peers:
                raise Conflict('Connection existed before the post-apply connection snapshot')
            keys, action = routes[self.path]
            if set(data) != keys:
                raise ValueError('Unexpected or missing request fields')
            self.answer(200, action())
        except PreflightRejected as exc:
            self.answer(409, {'error': str(exc), 'diagnostics':exc.diagnostics})
        except Conflict as exc:
            self.answer(409, {'error': str(exc)})
        except (ValueError, TypeError, KeyError) as exc:
            self.close_connection = True
            self.answer(400, {'error': str(exc)})
        except Exception:
            self.close_connection = True
            self.answer(503, {'error': 'Operation unavailable; inspect status and local state'})


def main():
    p = argparse.ArgumentParser(description='Rulemoor Linux agent (requires nftables privileges)')
    p.add_argument('--state', required=True)
    sub = p.add_subparsers(dest='action', required=True)
    init = sub.add_parser('init')
    init.add_argument('--policy', required=True)
    serve = sub.add_parser('serve')
    serve.add_argument('--listen', default='127.0.0.1')
    serve.add_argument('--port', type=int, default=18443)
    serve.add_argument('--cert', required=True)
    serve.add_argument('--key', required=True)
    serve.add_argument('--token-file', required=True)
    serve.add_argument('--management-paths', help='Optional bounded JSON configuration of protected local IPv4 TCP ports')
    a = p.parse_args()
    if os.name != 'posix' or not hasattr(time, 'CLOCK_BOOTTIME') or not hasattr(os, 'pidfd_open'):
        p.error('The agent requires Linux CLOCK_BOOTTIME and pidfd support')
    os.umask(0o077)
    c = Controller(a.state, NftBackend())
    server = None
    try:
        if a.action == 'init':
            print(json.dumps(c.initialize(json.loads(Path(a.policy).read_text()))))
            return
        token = secret_file(a.token_file)
        secret_file_check = Path(a.key)
        if secret_file_check.is_symlink() or secret_file_check.stat().st_mode & 0o077:
            raise ValueError('TLS private key must be private and not a symlink')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(a.cert, a.key)
        # Recover known durable state before optional admission configuration.
        # Invalid configuration still prevents the API from accepting new work.
        c.start()
        c.management_paths = load_paths(a.management_paths) if a.management_paths else None
        server = Server((a.listen, a.port), c, token, context)
        def hook(point):
            if point == 'awaiting-confirm':
                server.snapshot_connections()
            if os.environ.get('RULEMOOR_FAULT') == point:
                (c.root / (point + '.reached')).touch()
                while not (c.root / (point + '.go')).exists():
                    time.sleep(.005)
        c.hook = hook
        server.timeout = .05
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())
        while not stop.is_set():
            server.handle_request()
            try:
                c.tick()
            except Exception:
                with c.mutex:
                    c._degrade('Automatic recovery failed; local operator required')
        # Stop accepting and join serialized operations before attempting rollback.
        with c.mutex:
            c.shutdown()
    finally:
        if server:
            server.server_close()
        c.close()


if __name__ == '__main__':
    main()
