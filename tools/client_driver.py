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
    p.add_argument('mode', choices=['request', 'persistent', 'queued'])
    p.add_argument('root')
    p.add_argument('--path', default='/status')
    p.add_argument('--payload')
    p.add_argument('--wrong-token', action='store_true')
    a = p.parse_args()
    root = Path(a.root)
    token = 'incorrect' if a.wrong_token else (root / 'token').read_text().strip()
    try:
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
