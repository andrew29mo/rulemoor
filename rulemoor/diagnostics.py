"""Conservative, read-only diagnostics for declared local IPv4 TCP ingress ports."""
import hashlib
import json
from pathlib import Path
import re
from .policy import TABLE, validate

MAX_PATH_BYTES = 4096
MAX_PATHS = 8
MAX_ENTRIES = 4096
MAX_CHAINS = 64
SCOPE = 'NEW and ESTABLISHED IPv4 TCP input traffic to explicitly configured local destination ports; not an end-to-end route proof'


def validate_paths(paths):
    if paths is None:
        return None
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_PATHS:
        raise ValueError('Configure 1–8 management paths')
    out = []
    for item in paths:
        if (not isinstance(item, dict) or set(item) != {'name', 'port'}
                or not isinstance(item['name'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', item['name'])
                or type(item['port']) is not int or not 1 <= item['port'] <= 65535):
            raise ValueError('Each path requires a short name and TCP destination port')
        if any(row['name'] == item['name'] or row['port'] == item['port'] for row in out):
            raise ValueError('Management path names and ports must be unique')
        out.append(dict(item))
    return out


def load_paths(path):
    p = Path(path)
    if p.is_symlink():
        raise ValueError('Management path configuration must not be a symlink')
    with p.open('rb') as stream:
        raw = stream.read(MAX_PATH_BYTES + 1)
    if not 0 < len(raw) <= MAX_PATH_BYTES:
        raise ValueError('Management path configuration exceeds 4 KiB')
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {'paths'} or value['paths'] is None:
        raise ValueError('Management path configuration requires exactly paths')
    return validate_paths(value['paths'])


def own_paths(policy, paths):
    p = validate(policy)
    out = []
    for path in paths:
        hit = next(((i, r['verdict']) for i, r in enumerate(p['rules']) if r['port'] == path['port']), None)
        out.append({**path, 'decision': hit[1] if hit else p['default'],
                    'source': 'rule' if hit else 'default', 'rule_index': hit[0] if hit else None})
    return {'status': 'blocked' if any(p['decision'] == 'drop' for p in out) else 'allowed', 'paths': out}


def match_value(expr, port, state):
    """True/False/unknown for a small documented IPv4 TCP state model."""
    if not isinstance(expr, dict) or set(expr) != {'op', 'left', 'right'}:
        return None
    left, right, op = expr['left'], expr['right'], expr['op']
    if left == {'payload': {'protocol': 'tcp', 'field': 'dport'}} and type(right) is int and op in ('==', '!='):
        return (port == right) if op == '==' else (port != right)
    if left == {'meta': {'key': 'l4proto'}} and isinstance(right, str) and right in ('tcp', 'udp') and op in ('==', '!='):
        return (right == 'tcp') if op == '==' else (right != 'tcp')
    if left == {'meta': {'key': 'nfproto'}} and isinstance(right, str) and right in ('ipv4', 'ipv6') and op in ('==', '!='):
        return (right == 'ipv4') if op == '==' else (right != 'ipv4')
    if left == {'ct': {'key': 'state'}}:
        states = right.get('set') if isinstance(right, dict) and set(right) == {'set'} else right
        if isinstance(states, str):
            states = [states]
        if isinstance(states, list) and all(isinstance(s, str) and s in ('new','established','related','invalid','untracked') for s in states):
            if op in ('in', '=='):
                return state in states
            if op == '!=':
                return state not in states
    return None


def state_decision(chain, rules, port, state):
    outcomes = set()
    reachable = True
    for rule in rules:
        expressions = rule.get('expr')
        if not isinstance(expressions, list):
            outcomes.add('unknown'); continue
        matched, verdict, unsupported = True, None, False
        for expression in expressions:
            if not isinstance(expression, dict) or len(expression) != 1:
                unsupported = True; continue
            kind, value = next(iter(expression.items()))
            if kind == 'match':
                result = match_value(value, port, state)
                if result is False: matched = False
                elif result is None and matched is not False: matched = None
            elif kind in ('accept', 'drop') and value is None and verdict is None:
                verdict = kind
            elif kind == 'reject' and isinstance(value, (dict, type(None))) and verdict is None:
                verdict = 'drop'
            elif kind not in ('counter', 'log', 'comment'):
                unsupported = True
        if unsupported:
            outcomes.add('unknown')
            continue  # Unknown actions may rewrite headers before later conditions.
        if matched is False:
            continue
        if verdict is not None:
            outcomes.add(verdict)
            if matched is True:
                reachable = False; break
    if reachable:
        outcomes.add(chain.get('policy') if chain.get('policy') in ('accept', 'drop') else 'unknown')
    if outcomes == {'drop'}:
        return 'blocked'
    if outcomes == {'accept'}:
        return 'no_observed_input_conflict'
    return 'risk'


def chain_decision(chain, rules, port):
    # A fresh TCP/TLS session needs both initial and subsequent ingress packets.
    # Accepting only NEW packets cannot justify a conflict-free session model.
    outcomes = {state_decision(chain, rules, port, state) for state in ('new','established')}
    if 'blocked' in outcomes:
        return 'blocked'
    if outcomes == {'no_observed_input_conflict'}:
        return 'no_observed_input_conflict'
    return 'risk'


def external_paths(raw, paths):
    if not isinstance(raw, dict) or set(raw) != {'nftables'} or not isinstance(raw['nftables'], list) or len(raw['nftables']) > MAX_ENTRIES:
        raise ValueError('Unsupported or oversized ruleset shape')
    chains, rules, other_hooks = [], {}, []
    unassessed_objects = 0
    for item in raw['nftables']:
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError('Unsupported ruleset entry')
        kind, value = next(iter(item.items()))
        if kind == 'metainfo': continue
        if not isinstance(value, dict): raise ValueError('Unsupported ruleset object')
        family, table = value.get('family'), value.get('table')
        if family == 'ip' and table == TABLE: continue
        if family not in ('ip', 'inet', 'netdev', 'bridge'): continue
        if kind in ('chain','rule') and (not isinstance(table,str) or not isinstance(value.get('name') if kind=='chain' else value.get('chain'),str)):
            raise ValueError('Incomplete chain/rule identity')
        if kind not in ('table','chain','rule','set','map','element','counter','quota','limit','ct helper','ct expectation'):
            unassessed_objects += 1
        if kind == 'chain' and 'hook' in value:
            if value['hook'] == 'input' and family in ('ip', 'inet'):
                chains.append(value)
            else:
                other_hooks.append({'family':family,'table':table,'chain':value.get('name'),'hook':value['hook']})
        elif kind == 'rule':
            rules.setdefault((family, table, value.get('chain')), []).append(value)
    results = []
    for chain in chains[:MAX_CHAINS]:
        key = (chain['family'], chain['table'], chain['name'])
        results.append({'family':key[0],'table':key[1],'chain':key[2], 'hook':'input', 'priority':chain.get('prio'),
                        'paths':[{**p,'status':chain_decision(chain,rules.get(key,[]),p['port'])} for p in paths]})
    statuses = [p['status'] for c in results for p in c['paths']]
    truncated = len(chains) > MAX_CHAINS or len(other_hooks) > MAX_CHAINS
    status = ('risk' if 'risk' in statuses or other_hooks or truncated or unassessed_objects
              else 'blocked' if 'blocked' in statuses else 'no_observed_input_conflict')
    return {'status':status, 'input_chains':results, 'unassessed_hooks':other_hooks[:MAX_CHAINS], 'truncated':truncated,
            'unassessed_object_count':unassessed_objects,
            'snapshot_sha256':hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'limitations':['Point-in-time read; no exclusion against other writers',
                           'Other hooks, NAT, routes, bridges, legacy iptables, eBPF and external devices are not evaluated',
                           'Unsupported expressions and jumps are uncertain; no observed input conflict is not proof of reachability']}


def diagnose(policy, paths, backend):
    result = {'schema':1,'scope':SCOPE,'configuration':'configured' if paths else 'not_configured',
              'fresh_connection_confirmation_required':True,'reachability_verified':False}
    if not paths:
        return {**result,'own_policy':{'status':'not_configured','paths':[]},'external':{'status':'not_configured'}}
    result['own_policy'] = own_paths(policy, paths)
    try:
        result['external'] = external_paths(backend.inspect_ruleset(), paths)
    except (AttributeError, OSError, RuntimeError, ValueError, TypeError, KeyError, RecursionError) as exc:
        codes={"Ruleset inspection timed out":"inspection_timeout",
               "Ruleset inspection exceeded 1 MiB":"inspection_output_limit",
               "Ruleset inspection failed":"inspection_failed"}
        code=codes.get(str(exc),"inspection_unavailable")
        result['external'] = {'status':'unavailable','reason_code':code,'reason':'Ruleset could not be safely inspected; no clear result is inferred'}
    return result
