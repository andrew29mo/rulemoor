"""Real Linux backend. Never flushes a ruleset or accepts arbitrary nft text from clients."""
import fcntl
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time
from .policy import TABLE, canonical, compile_policy


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

    def read(self):
        r = subprocess.run(['nft', '-j', '-s', 'list', 'table', 'ip', TABLE],
                           capture_output=True, text=True, timeout=2)
        if r.returncode:
            if 'No such file or directory' in r.stderr:
                return None
            raise RuntimeError('Cannot read nft table')
        return canonical(json.loads(r.stdout))

    def check(self, policy, replace=True):
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
        rec = json.loads(path.read_text())
        expected = {k: rec[k] for k in ('pid', 'start_ticks', 'boot')}
        if rec['token'] != token:
            raise RuntimeError('Executor identity token mismatch')
        if identity(rec['pid']) != expected:
            return
        fd = os.pidfd_open(rec['pid'])
        try:
            if identity(rec['pid']) == expected:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
        finally:
            os.close(fd)
        end = clock() + 2
        while identity(rec['pid']) == expected and clock() < end:
            time.sleep(.01)
        if identity(rec['pid']) == expected:
            raise RuntimeError('Old executor still active')
