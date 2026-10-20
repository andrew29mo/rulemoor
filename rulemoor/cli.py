"""TLS-only operator CLI. Every invocation creates a new management connection."""
import argparse
import http.client
import json
from pathlib import Path
import ssl
from urllib.parse import urlsplit
from .service import secret_file


def request(url, ca, token, path, payload=None):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.username:
        raise ValueError('Use an HTTPS origin without path, credentials or query')
    context = ssl.create_default_context(cafile=ca)
    conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=context, timeout=5)
    try:
        headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
        conn.request('POST' if payload is not None else 'GET', path,
                     body=json.dumps(payload) if payload is not None else None, headers=headers)
        response = conn.getresponse()
        value = json.loads(response.read(65537))
        if response.status != 200:
            raise RuntimeError(str(response.status) + ': ' + value.get('error', 'Request failed'))
        return value
    finally:
        conn.close()


def main():
    p = argparse.ArgumentParser(description='Confirmed network changes with Rulemoor')
    p.add_argument('--url', required=True)
    p.add_argument('--ca', required=True)
    p.add_argument('--token-file', required=True)
    sub = p.add_subparsers(dest='action', required=True)
    sub.add_parser('status')
    sub.add_parser('history')
    plan = sub.add_parser('plan')
    plan.add_argument('policy')
    apply = sub.add_parser('apply')
    apply.add_argument('policy')
    apply.add_argument('--op', required=True)
    apply.add_argument('--generation', required=True, type=int)
    apply.add_argument('--window', type=float, default=30)
    confirm = sub.add_parser('confirm')
    confirm.add_argument('--op', required=True)
    confirm.add_argument('--generation', required=True, type=int)
    cancel = sub.add_parser('cancel')
    cancel.add_argument('--op', required=True)
    cancel.add_argument('--generation', required=True, type=int)
    a = p.parse_args()
    token = secret_file(a.token_file)
    def call(path, payload=None):
        return request(a.url, a.ca, token, path, payload)
    try:
        if a.action in ('status', 'history'):
            value = call('/' + a.action)
        elif a.action in ('plan', 'apply'):
            payload = {'policy': json.loads(Path(a.policy).read_text())}
            if a.action == 'apply':
                payload.update(op=a.op, generation=a.generation, window=a.window)
            value = call('/' + a.action, payload)
        else:
            payload = {'op': a.op, 'generation': a.generation}
            if a.action == 'confirm':
                state = call('/status')
                if (state['op'], state['generation']) != (a.op, a.generation):
                    raise RuntimeError('Status does not match requested operation')
                payload.update(candidate_digest=state['candidate_digest'], challenge=state['challenge'])
            value = call('/' + a.action, payload)
        print(json.dumps(value, indent=2))
    except (RuntimeError, ValueError, OSError) as exc:
        p.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()
