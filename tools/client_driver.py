"""Isolated network client using the production CLI transport, plus keepalive adversarial probe."""
import argparse
import http.client
import json
from pathlib import Path
import ssl
import time
from rulemoor.cli import request


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['request', 'persistent', 'queued', 'slow-headers'])
    p.add_argument('root')
    p.add_argument('--path', default='/status')
    p.add_argument('--payload')
    p.add_argument('--wrong-token', action='store_true')
    a = p.parse_args()
    root = Path(a.root)
    token = 'incorrect' if a.wrong_token else (root / 'token').read_text().strip()
    try:
        if a.mode == 'slow-headers':
            from rulemoor.core import Store
            context = ssl.create_default_context(cafile=str(root / 'cert.pem'))
            connections = []
            expired = set()
            observed_rollback = False
            began = time.monotonic()
            try:
                for _ in range(16):
                    c = http.client.HTTPSConnection('192.0.2.2', 18443, context=context, timeout=1)
                    c.connect(); connections.append(c)
                    c.sock.sendall(b'GET /status HTTP/1.1\r\nX-Slow: ')
                end = time.monotonic() + 6
                while time.monotonic() < end:
                    for i, c in enumerate(connections):
                        if i not in expired:
                            try: c.sock.sendall(b'x')
                            except OSError: expired.add(i)
                    if len(expired) == 0 and Store(root).load()['phase'] == 'ROLLED_BACK':
                        observed_rollback = True
                    time.sleep(.1)
            finally:
                for c in connections: c.close()
            value = request('https://192.0.2.2:18443', str(root / 'cert.pem'), token, '/status')
            print(json.dumps({'ok': True, 'connections': len(connections),
                              'expired_connections': len(expired), 'rollback_while_all_slots_occupied': observed_rollback,
                              'final_phase': value['phase'], 'seconds': time.monotonic() - began}), flush=True)
            return
        if a.mode == 'request':
            value = request('https://192.0.2.2:18443', str(root / 'cert.pem'), token,
                            a.path, json.loads(a.payload) if a.payload else None)
            print(json.dumps({'ok': True, 'value': value}), flush=True)
            return
        queued_socket = None
        if a.mode == 'queued':
            import socket
            queued_socket = socket.create_connection(('192.0.2.2', 18443), timeout=2)
            (root / 'queued.ready').touch()
            end = time.monotonic() + 5
            while not (root / 'queued.go').exists() and time.monotonic() < end:
                time.sleep(.005)
        conn = http.client.HTTPSConnection('192.0.2.2', 18443,
                 context=ssl.create_default_context(cafile=str(root / 'cert.pem')), timeout=1)
        if queued_socket is not None:
            conn.sock = ssl.create_default_context(cafile=str(root / 'cert.pem')).wrap_socket(queued_socket, server_hostname='192.0.2.2')
        headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
        def call(path, payload=None):
            conn.request('POST' if payload else 'GET', path, json.dumps(payload) if payload else None, headers)
            r = conn.getresponse(); return {'status': r.status, 'body': json.loads(r.read())}
        first = call('/status')
        (root / 'persistent.ready').touch()
        if a.mode == 'queued':
            s = first['body']
            denied = call('/confirm', {k: s[k] for k in ('op', 'generation', 'candidate_digest', 'challenge')})
            print(json.dumps({'ok': True, 'confirm_status': denied['status'], 'reason': denied['body'].get('error')}), flush=True)
            conn.close()
            return
        end = time.monotonic() + 4
        while not (root / 'persistent.go').exists() and time.monotonic() < end:
            time.sleep(.005)
        old = call('/status'); s = old['body']
        denied = call('/confirm', {k: s[k] for k in ('op', 'generation', 'candidate_digest', 'challenge')})
        conn.close()
        print(json.dumps({'ok': True, 'first': first['status'], 'old_status': old['status'],
                          'old_confirm': denied['status']}), flush=True)
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': type(exc).__name__}), flush=True)


if __name__ == '__main__':
    main()
