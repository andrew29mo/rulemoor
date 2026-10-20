"""Bounded subprocess groups. Nonzero, timeout and cleanup failure are never successes."""
import os
import signal
import subprocess
import time


def run(args, timeout=60, **kwargs):
    began = time.monotonic()
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         start_new_session=True, **kwargs)
    timed_out = False
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(p.pid, signal.SIGKILL)
        out, err = p.communicate(timeout=5)
    except BaseException:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.communicate(timeout=5)
        raise
    finally:
        # Also reap descendants left after their direct parent returned.
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return {'exit_code': p.returncode, 'timed_out': timed_out,
            'seconds': time.monotonic() - began, 'stdout': out, 'stderr': err,
            'passed': p.returncode == 0 and not timed_out}
