"""Strict schema, safe text compiler and independently constructed expected JSON."""
import difflib
import hashlib
import json

TABLE = 'rulemoor'
MAX_RULES = 32


def validate(value):
    if not isinstance(value, dict) or set(value) != {'default', 'rules'}:
        raise ValueError('Policy requires exactly default and rules')
    if value['default'] not in ('accept', 'drop'):
        raise ValueError('default must be accept or drop')
    rules = value['rules']
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ValueError('rules must be a list of at most 32 TCP port rules')
    out = []
    for row in rules:
        if not isinstance(row, dict) or set(row) != {'port', 'verdict'}:
            raise ValueError('Each rule requires exactly port and verdict')
        if type(row['port']) is not int or not 1 <= row['port'] <= 65535:
            raise ValueError('Invalid TCP port')
        if row['verdict'] not in ('accept', 'drop'):
            raise ValueError('Invalid verdict')
        out.append(dict(row))
    return {'default': value['default'], 'rules': out}


def compile_policy(value, replace=True):
    p = validate(value)
    rules = ['ct state established,related accept']
    rules += [f"tcp dport {r['port']} {r['verdict']}" for r in p['rules']]
    prefix = f'delete table ip {TABLE}\n' if replace else ''
    return prefix + f'table ip {TABLE} {{\n chain input {{\n  type filter hook input priority 0; policy {p["default"]};\n  ' + '\n  '.join(rules) + '\n }\n}\n'


def expected(value):
    p = validate(value)
    base = {'family': 'ip', 'table': TABLE, 'chain': 'input'}
    rows = [{'table': {'family': 'ip', 'name': TABLE}},
            {'chain': {'family': 'ip', 'table': TABLE, 'name': 'input',
                       'type': 'filter', 'hook': 'input', 'prio': 0, 'policy': p['default']}},
            {'rule': {**base, 'expr': [{'match': {'op': 'in', 'left': {'ct': {'key': 'state'}},
                                      'right': ['established', 'related']}}, {'accept': None}]}}]
    for r in p['rules']:
        rows.append({'rule': {**base, 'expr': [{'match': {'op': '==', 'left': {'payload': {
            'protocol': 'tcp', 'field': 'dport'}}, 'right': r['port']}}, {r['verdict']: None}]}})
    return rows


def canonical(raw):
    def clean(x):
        if isinstance(x, dict):
            return {k: clean(v) for k, v in x.items() if k != 'handle'}
        if isinstance(x, list):
            return [clean(v) for v in x]
        return x
    return [clean(row) for row in raw['nftables'] if 'metainfo' not in row]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def diff(before, after):
    return ''.join(difflib.unified_diff(compile_policy(before).splitlines(True),
                                      compile_policy(after).splitlines(True), 'current', 'candidate'))
