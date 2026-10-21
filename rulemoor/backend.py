"""Real Linux backend. Never flushes a ruleset or accepts arbitrary nft text from clients."""
import fcntl
import json
import os
from pathlib import Path
import secrets
import selectors
import re
import signal
import subprocess
import sys
import time
from .policy import TABLE, canonical, compile_policy, dual


def clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def identity(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        if fields[0] == 'Z':
            return None
        return {'pid': pid, 'start_ticks': int(fields[19]), 'boot': boot_id()}
    except (OSError, ValueError):
        return None


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + '.' + secrets.token_hex(6))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        temp.unlink(missing_ok=True)


def lock(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise RuntimeError('Another owner/writer is active')


class NftBackend:
    clock = staticmethod(clock)
    boot = staticmethod(boot_id)

    def __init__(self, dual_stack=False):
        self.dual_stack = dual_stack

    def assert_policy(self, policy):
        if dual(policy) != self.dual_stack:
            raise RuntimeError('Policy and backend mode differ; no automatic migration')

    def read(self):
        rows = []
        for family in (('ip','ip6') if self.dual_stack else ('ip',)):
            r = subprocess.run(['nft', '-j', '-s', 'list', 'table', family, TABLE],
                               capture_output=True, text=True, timeout=2)
            if r.returncode:
                if 'No such file or directory' in r.stderr:
                    continue
                raise RuntimeError('Cannot read nft table')
            rows.extend(canonical(json.loads(r.stdout)))
        return rows or None

    def inspect_ruleset(self):
        # Never collect an unbounded host ruleset in memory or write it to reports.
        p = subprocess.Popen(['nft', '-j', '-s', 'list', 'ruleset'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        data=bytearray(); end=time.monotonic()+2
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(p.stdout,selectors.EVENT_READ)
                while True:
                    if time.monotonic()>=end: raise RuntimeError('Ruleset inspection timed out')
                    if not selector.select(min(.05,max(0,end-time.monotonic()))): continue
                    chunk=os.read(p.stdout.fileno(),16384)
                    if not chunk: break
                    data.extend(chunk)
                    if len(data)>1024*1024: raise RuntimeError('Ruleset inspection exceeded 1 MiB')
            p.wait(timeout=max(.001,end-time.monotonic()))
            if p.returncode: raise RuntimeError('Ruleset inspection failed')
            return json.loads(data)
        except subprocess.TimeoutExpired:
            raise RuntimeError('Ruleset inspection timed out') from None
        finally:
            if p.poll() is None: p.kill()
            p.wait(timeout=2);p.stdout.close()

    def check(self, policy, replace=True):
        self.assert_policy(policy)
        self._direct(compile_policy(policy, replace), True)

    def _direct(self, script, check=False):
        r = subprocess.run(['nft', *(['-c'] if check else []), '-f', '-'],
                           input=script, capture_output=True, text=True, timeout=2)
        if r.returncode:
            raise RuntimeError('nft rejected transaction: ' + r.stderr[:300])

    def initialize(self, policy):
        self.check(policy, False)
        self._direct(compile_policy(policy, False))

    def execute(self, root, state, policy, writer_fd, persist, hook):
        self.assert_policy(policy)
        token = secrets.token_hex(16)
        state['executor_token'] = token
        persist('executor_intent')
        script = Path(root) / ('batch-' + token + '.nft')
        script.write_text(compile_policy(policy))
        hook('executor-intent')
        cmd = [sys.executable, '-m', 'rulemoor.executor', str(root), token,
               str(writer_fd), str(script)]
        p = subprocess.Popen(cmd, pass_fds=(writer_fd,), stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        try:
            out, err = p.communicate(timeout=2)
            if p.returncode:
                raise RuntimeError('nft executor failed: ' + err[:300])
        except BaseException:
            p.kill()
            p.wait(timeout=2)
            raise

    def retire(self, root, state):
        token = state.get('executor_token')
        if not token:
            return
        if not isinstance(token, str) or re.fullmatch(r'[0-9a-f]{32}', token) is None:
            raise RuntimeError('Invalid executor token; local operator recovery required')
        path = Path(root) / ('executor-' + token + '.json')
        end = clock() + 2
        while not path.exists() and clock() < end:
            time.sleep(.01)
        if not path.exists():
            # An executor inherits the writer lock from birth. If it is free after
            # the previous agent exited, no delayed executor can still write.
            fd = lock(Path(root) / 'writer.lock')
            os.close(fd)
            return
        try:
            with path.open('rb') as stream:
                raw = stream.read(4097)
            if len(raw) > 4096:
                raise ValueError('Oversized identity record')
            rec = json.loads(raw)
            if not isinstance(rec, dict) or set(rec) != {'pid', 'start_ticks', 'boot', 'token'}:
                raise ValueError('Invalid identity fields')
            if type(rec['pid']) is not int or rec['pid'] <= 1:
                raise ValueError('Invalid executor PID')
            if type(rec['start_ticks']) is not int or rec['start_ticks'] < 0:
                raise ValueError('Invalid process start time')
            if not isinstance(rec['boot'], str) or not 0 < len(rec['boot']) <= 128 or rec['token'] != token:
                raise ValueError('Invalid boot/token identity')
        except (ValueError, TypeError):
            raise RuntimeError('Invalid executor identity record; local operator recovery required') from None
        expected = {k: rec[k] for k in ('pid', 'start_ticks', 'boot')}
        if identity(rec['pid']) != expected:
            return
        try:
            fd = os.pidfd_open(rec['pid'])
        except ProcessLookupError:
            return  # Natural exit after identity check; caller still verifies writer.lock.
        try:
            if identity(rec['pid']) == expected:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    return  # The identified process exited before signaling.
        finally:
            os.close(fd)
        end = clock() + 2
        while identity(rec['pid']) == expected and clock() < end:
            time.sleep(.01)
        if identity(rec['pid']) == expected:
            raise RuntimeError('Old executor still active')
