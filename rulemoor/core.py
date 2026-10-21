"""Serialized durable decisions shared by CLI service and real-kernel fault tests."""
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import threading
from contextlib import contextmanager
from .backend import atomic_json, lock
from .policy import validate, expected, digest, diff

TERMINAL = ('COMMITTED', 'ROLLED_BACK')
MAX_HISTORY = 64
MAX_DISK = 4 * 1024 * 1024
MIN_FREE = 8 * 1024 * 1024


class Conflict(RuntimeError):
    pass

MAX_SNAPSHOT_BYTES = 65536


def validate_snapshot(s):
    """Reject unusable persisted state before fencing processes or changing rules."""
    phases = {'INITIALIZING','PREPARED','APPLYING','AWAITING_CONFIRM','ROLLING_BACK','ROLLED_BACK','COMMITTED','DEGRADED'}
    allowed = {'phase','generation','op','current','baseline','candidate','executor_token','boot','reason',
               'request_hash','candidate_digest','deadline','applied_at','challenge','confirmed_at',
               'rollback_started_at','rollback_completed_at'}
    if not isinstance(s, dict) or not set(s).issubset(allowed) or s.get('phase') not in phases:
        raise ValueError('Invalid journal state shape')
    degraded = s['phase'] == 'DEGRADED'
    if not (type(s.get('generation')) is int and 0 <= s['generation'] < 2**63):
        if not degraded or s.get('generation') is not None: raise ValueError('Invalid generation')
    if not (isinstance(s.get('op'), str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', s['op'])):
        if not degraded or s.get('op') is not None: raise ValueError('Invalid operation')
    if not (isinstance(s.get('boot'), str) and 0 < len(s['boot']) <= 128):
        if not degraded: raise ValueError('Invalid boot identity')
    if 'current' in s: validate(s['current'])
    elif not degraded: raise ValueError('Missing current policy')
    for k in ('baseline','candidate'):
        if s.get(k) is not None: validate(s[k])
    for k in ('request_hash','candidate_digest','challenge'):
        if k in s and (not isinstance(s[k], str) or re.fullmatch(r'[0-9a-f]{64}',s[k]) is None):
            raise ValueError('Invalid digest/challenge')
    token=s.get('executor_token')
    if token is not None and (not isinstance(token,str) or re.fullmatch(r'[0-9a-f]{32}',token) is None):
        raise ValueError('Invalid executor token')
    for k in ('deadline','applied_at','confirmed_at','rollback_started_at','rollback_completed_at'):
        if k in s:
            try:
                valid = type(s[k]) in (int,float) and math.isfinite(s[k]) and s[k] >= 0
            except OverflowError:
                valid = False
            if not valid: raise ValueError('Invalid journal clock')
    if s.get('reason') is not None and (not isinstance(s['reason'],str) or len(s['reason'])>2048):
        raise ValueError('Invalid diagnostic')
    if not degraded and not {'phase','generation','op','current','candidate','executor_token','boot','reason'}.issubset(s):
        raise ValueError('Incomplete common state')
    if not degraded and s['op']=='initial' and (s['phase'] not in {'INITIALIZING','COMMITTED'} or s['candidate'] is not None):
        raise ValueError('Invalid initialization state')
    if not degraded and s['op']!='initial':
        required={'baseline','candidate','candidate_digest','request_hash','deadline'}
        if not required.issubset(s) or s['baseline'] is None or s['candidate'] is None:
            raise ValueError('Incomplete pending/rollback state')
        if s['candidate_digest'] != digest(expected(s['candidate'])):
            raise ValueError('Candidate digest mismatch')
    if (s['phase']=='AWAITING_CONFIRM' or (s['phase']=='COMMITTED' and s['op']!='initial')) and not {'applied_at','challenge'}.issubset(s):
        raise ValueError('Incomplete confirmation state')
    if s['phase']=='ROLLED_BACK' and s['current']!=s['baseline']:
        raise ValueError('Rollback policy mismatch')
    if s['phase']=='COMMITTED' and s.get('candidate') is not None and s['current']!=s['candidate']:
        raise ValueError('Committed policy mismatch')
    return s



class Store:
    def __init__(self, root):
        self.path = Path(root) / 'state.sqlite'
        self.checkpoint_warning = None

    @contextmanager
    def connect(self):
        c = sqlite3.connect(self.path, timeout=2)
        try:
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('PRAGMA synchronous=FULL')
            with c:
                yield c
        finally:
            c.close()

    def create(self, state):
        with self.connect() as c:
            c.executescript('CREATE TABLE snapshot(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);'
                            'CREATE TABLE events(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL);'
                            'CREATE TABLE operations(op TEXT PRIMARY KEY, payload TEXT NOT NULL, value TEXT NOT NULL);')
            c.execute('INSERT INTO snapshot VALUES(1,?)', (json.dumps(state),))

    def load(self):
        with self.connect() as c:
            size = c.execute('SELECT length(CAST(value AS BLOB)) FROM snapshot WHERE id=1').fetchone()
            if size is None or type(size[0]) is not int or not 0 < size[0] <= MAX_SNAPSHOT_BYTES:
                raise ValueError('Missing or oversized journal snapshot')
            raw = c.execute('SELECT value FROM snapshot WHERE id=1').fetchone()[0]
            def invalid_constant(value): raise ValueError('Nonfinite JSON constant')
            try:
                return validate_snapshot(json.loads(raw, parse_constant=invalid_constant))
            except RecursionError:
                raise ValueError('Journal nesting exceeds parser limit') from None

    def save(self, state, kind):
        data = json.dumps(state)
        with self.connect() as c:
            c.execute('UPDATE snapshot SET value=? WHERE id=1', (data,))
            c.execute('INSERT INTO events(kind,value) VALUES(?,?)', (kind, data))
            if state.get('request_hash'):
                c.execute('INSERT OR REPLACE INTO operations VALUES(?,?,?)',
                          (state['op'], state['request_hash'], data))
            c.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)', (MAX_HISTORY,))
            # IDs are deduplicated for the retained bounded history only.
            c.execute('DELETE FROM operations WHERE rowid NOT IN (SELECT rowid FROM operations ORDER BY rowid DESC LIMIT ?)', (MAX_HISTORY,))
        # The transaction is already committed. Maintenance failure must not be
        # reported as a failed state transition (notably for confirmation).
        try:
            with self.connect() as c:
                result = c.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
            self.checkpoint_warning = ('Journal checkpoint busy; transaction committed' if result[0] else None)
        except (sqlite3.Error, OSError):
            self.checkpoint_warning = 'Journal checkpoint failed; transaction committed'

    def prior(self, op):
        with self.connect() as c:
            row = c.execute('SELECT payload,value FROM operations WHERE op=?', (op,)).fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def history(self):
        with self.connect() as c:
            return [{'kind': k, 'state': json.loads(v)} for k, v in
                    c.execute('SELECT kind,value FROM events ORDER BY id DESC LIMIT ?', (MAX_HISTORY,))]


class Controller:
    def __init__(self, root, backend, hook=None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink() or self.root.stat().st_mode & 0o077:
            raise ValueError('State directory must be private (0700) and not a symlink')
        self.owner_fd = lock(self.root / 'agent.lock')
        self.backend = backend
        self.store = Store(self.root)
        self.mutex = threading.RLock()
        self.hook = hook or (lambda point: None)
        self.s = None
        self.storage_failed = False
        self.closing = False

    def close(self):
        if self.owner_fd is not None:
            os.close(self.owner_fd)
            self.owner_fd = None

    def _save(self, kind):
        self.store.save(self.s, kind)

    def _space(self):
        usage = sum(p.stat().st_size for p in self.root.iterdir() if p.is_file())
        if usage >= MAX_DISK or shutil.disk_usage(self.root).free < MIN_FREE:
            raise Conflict('State storage budget or minimum free disk reached')

    def initialize(self, policy):
        with self.mutex:
            p = validate(policy)
            if self.store.path.exists() or self.backend.read() is not None:
                raise Conflict('Refuse to adopt or replace existing table/state')
            self._space()
            self.s = {'phase': 'INITIALIZING', 'generation': 0, 'op': 'initial',
                      'current': p, 'candidate': None, 'executor_token': None,
                      'boot': self.backend.boot(), 'reason': None}
            self.store.create(self.s)
            # Interrupted first-time provisioning is fail-closed; never silently adopted.
            self.backend.initialize(p)
            if self.backend.read() != expected(p):
                raise RuntimeError('Initialization readback mismatch')
            self.s['phase'] = 'COMMITTED'
            self._save('initialized')
            return self.status()

    def start(self):
        with self.mutex:
            try:
                self.s = self.store.load()
            except (sqlite3.Error, ValueError, TypeError, OSError):
                self.storage_failed = True
                self.s = {'phase': 'DEGRADED', 'generation': None, 'op': None,
                          'reason': 'Unreadable journal; local operator recovery required'}
                return self.status()
            if self.s['phase'] in ('INITIALIZING', 'DEGRADED'):
                self._degrade('Provisioning interrupted or prior degraded state; local recovery required')
                return self.status()
            try:
                if self.s['phase'] not in TERMINAL:
                    self.backend.retire(self.root, self.s)
                fd = lock(self.root / 'writer.lock')
                try:
                    rebooted = self.s['boot'] != self.backend.boot()
                    # Kernel tables are volatile. Recreate only an absent owned table
                    # after a verified boot change, never a same-boot deletion or drift.
                    if rebooted and self.backend.read() is None:
                        policy = self.s['current'] if self.s['phase'] in TERMINAL else self.s['baseline']
                        self._save('boot_restore_intent')
                        self.backend.initialize(policy)
                    if self.s['phase'] in TERMINAL:
                        if self.backend.read() != expected(self.s['current']):
                            self._degrade('Committed policy drift')
                        elif rebooted:
                            self.s['generation'] += 1
                            self.s['boot'] = self.backend.boot()
                            self._save('boot_restored')
                    else:
                        self.s['generation'] += 1
                        self._rollback(fd, 'reboot' if rebooted else 'restart')
                        if rebooted and self.s['phase'] == 'ROLLED_BACK':
                            self.s['boot'] = self.backend.boot()
                            self._save('boot_recovery_complete')
                finally:
                    os.close(fd)
            except (RuntimeError, OSError, sqlite3.Error) as exc:
                self._degrade(str(exc))
            return self.status()

    def _degrade(self, reason):
        self.s.update(phase='DEGRADED', reason=reason)
        try:
            self._save('degraded')
        except (sqlite3.Error, OSError):
            self.storage_failed = True

    def status(self):
        with self.mutex:
            result = json.loads(json.dumps(self.s))
            if self.store.checkpoint_warning:
                result['journal_maintenance_warning'] = self.store.checkpoint_warning
            return result

    def plan(self, policy):
        p = validate(policy)
        with self.mutex:
            if self.s['phase'] not in TERMINAL or self.storage_failed:
                raise Conflict('Agent is not ready')
            if self.backend.read() != expected(self.s['current']):
                self._degrade('Policy drift before planning')
                raise Conflict('Policy drift')
            self.backend.check(p)
            return {'generation': self.s['generation'], 'candidate_digest': digest(expected(p)),
                    'diff': diff(self.s['current'], p)}

    def apply(self, op, generation, policy, window):
        if not isinstance(op, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', op):
            raise ValueError('Invalid operation ID')
        if type(generation) is not int or type(window) not in (int, float) or not 1 <= window <= 300:
            raise ValueError('generation must be integer; confirmation window is 1–300 seconds')
        p = validate(policy)
        payload = digest({'generation': generation, 'policy': p, 'window': window})
        with self.mutex:
            if self.storage_failed or self.closing:
                raise Conflict('Journal unavailable or agent shutting down')
            prior = self.store.prior(op)
            if prior:
                if prior[0] != payload:
                    raise Conflict('Operation ID reused with different request')
                return prior[1]
            if self.s['phase'] not in TERMINAL or self.s['generation'] != generation:
                raise Conflict('Unfinished operation or stale base generation')
            self._space()
            self.backend.check(p)
            baseline = self.backend.read()
            if baseline != expected(self.s['current']):
                self._degrade('Policy drift before apply')
                raise Conflict('Policy drift')
            fd = lock(self.root / 'writer.lock')
            try:
                self._prune()
                self.s = {'phase': 'PREPARED', 'generation': generation + 1,
                          'op': op, 'request_hash': payload, 'current': self.s['current'],
                          'baseline': self.s['current'], 'candidate': p,
                          'candidate_digest': digest(expected(p)), 'boot': self.backend.boot(),
                          'deadline': self.backend.clock() + window, 'executor_token': None,
                          'reason': None}
                # Independent rescue record precedes kernel side effects; never contains credentials.
                atomic_json(self.root / 'rescue.json', self.s)
                reserve = os.open(self.root / 'reserve', os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
                with os.fdopen(reserve, 'wb') as stream:
                    stream.write(bytes(256 * 1024))
                    stream.flush()
                    os.fsync(stream.fileno())
                self._save('prepared')
                self.hook('prepared')
                self.s['phase'] = 'APPLYING'
                self._save('applying')
                self.backend.execute(self.root, self.s, p, fd, self._save, self.hook)
                self.hook('kernel-applied')
                if self.backend.read() != expected(p):
                    self._degrade('Candidate readback differs from expected policy')
                else:
                    self.s.update(phase='AWAITING_CONFIRM', applied_at=self.backend.clock(),
                                  challenge=secrets.token_hex(32))
                    self._save('awaiting_confirm')
                    self.hook('awaiting-confirm')
                    if self.backend.clock() >= self.s['deadline']:
                        self._rollback(fd, 'apply exceeded confirmation deadline')
            except Exception as exc:
                # Release reserve before recovery so persistence failure cannot skip kernel rollback.
                (self.root / 'reserve').unlink(missing_ok=True)
                try:
                    self._rollback(fd, 'apply failed: ' + type(exc).__name__)
                except Exception:
                    self._degrade('Apply/recovery failure; local operator required')
                raise
            finally:
                os.close(fd)
            return self.status()

    def confirm(self, op, generation, candidate_digest, challenge, connected_at):
        with self.mutex:
            s = self.s
            if (self.closing or s['phase'] != 'AWAITING_CONFIRM' or s['op'] != op or s['generation'] != generation
                    or s['boot'] != self.backend.boot() or self.backend.clock() >= s['deadline']
                    or connected_at <= s['applied_at'] or candidate_digest != s['candidate_digest']
                    or not isinstance(challenge, str) or not secrets.compare_digest(challenge, s['challenge'])):
                raise Conflict('Confirmation is stale, expired, or not from a fresh connection')
            if self.backend.read() != expected(s['candidate']):
                self._degrade('Policy drift before confirmation')
                raise Conflict('Policy drift')
            if self.backend.clock() >= s['deadline']:
                raise Conflict('Confirmation expired during readback')
            # A disk failure must not expose an unpersisted COMMITTED in-memory decision.
            before = json.loads(json.dumps(self.s))
            self.s.update(phase='COMMITTED', current=s['candidate'], confirmed_at=self.backend.clock())
            try:
                self._save('confirmed')
            except Exception:
                self.s = before
                raise
            self.hook('confirm-committed')
            return self.status()

    def cancel(self, op, generation):
        with self.mutex:
            if self.s['phase'] != 'AWAITING_CONFIRM' or (op, generation) != (self.s['op'], self.s['generation']):
                raise Conflict('No matching cancellable operation')
            fd = lock(self.root / 'writer.lock')
            try:
                self._rollback(fd, 'cancelled')
            finally:
                os.close(fd)
            return self.status()

    def tick(self):
        with self.mutex:
            if self.s and self.s['phase'] == 'AWAITING_CONFIRM' and (
                    self.s['boot'] != self.backend.boot() or self.backend.clock() >= self.s['deadline']):
                fd = lock(self.root / 'writer.lock')
                try:
                    self._rollback(fd, 'deadline')
                finally:
                    os.close(fd)

    def _rollback(self, fd, reason):
        actual = self.backend.read()
        if actual not in (expected(self.s['baseline']), expected(self.s['candidate'])):
            self._degrade('Unknown policy before rollback; no blind overwrite')
            return
        self.s.update(phase='ROLLING_BACK', rollback_started_at=self.backend.clock(), reason=reason)
        (self.root / 'reserve').unlink(missing_ok=True)
        try:
            self._save('rollback_started')
        except (sqlite3.Error, OSError):
            self.storage_failed = True
        if actual != expected(self.s['baseline']):
            # Persist executor intent if possible, but do not abandon restoring known rules on ENOSPC.
            def persist(kind):
                try:
                    self._save(kind)
                except (sqlite3.Error, OSError):
                    self.storage_failed = True
            self.backend.execute(self.root, self.s, self.s['baseline'], fd, persist, self.hook)
        if self.backend.read() != expected(self.s['baseline']):
            self._degrade('Rollback readback mismatch')
            return
        self.hook('rollback-applied')
        self.s.update(phase='ROLLED_BACK', current=self.s['baseline'],
                      rollback_completed_at=self.backend.clock())
        try:
            self._save('rollback_complete')
        except (sqlite3.Error, OSError):
            self._degrade('Rules restored, journal unavailable; writes blocked')

    def _prune(self):
        for pattern in ('executor-*.json', 'batch-*.nft'):
            for path in self.root.glob(pattern):
                path.unlink()

    def shutdown(self):
        with self.mutex:
            self.closing = True
            if self.s and self.s['phase'] == 'AWAITING_CONFIRM':
                self.cancel(self.s['op'], self.s['generation'])
