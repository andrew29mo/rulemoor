"""One PID from launcher through nft exec; writer fd remains inherited."""
import os
from pathlib import Path
import sys
from .backend import atomic_json, identity


def main():
    root, token, fd, script = sys.argv[1:]
    os.set_inheritable(int(fd), True)
    atomic_json(Path(root) / ('executor-' + token + '.json'),
                {**identity(os.getpid()), 'token': token})
    # Internal fault-test hook; deployment unit clears this environment variable.
    if os.environ.get('RULEMOOR_FAULT') == 'executor-held':
        import time
        Path(root, 'executor-held.reached').touch()
        while not Path(root, 'executor-held.go').exists():
            time.sleep(.01)
    os.execvp('nft', ['nft', '-f', script])


if __name__ == '__main__':
    main()
