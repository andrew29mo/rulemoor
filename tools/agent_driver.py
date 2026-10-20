"""Fault harness around the production Controller/NftBackend; not another implementation."""
import argparse
import json
import os
from pathlib import Path
import signal
import time
from rulemoor.backend import NftBackend, atomic_json
from rulemoor.core import Controller


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['apply', 'recover', 'confirm'])
    p.add_argument('state')
    p.add_argument('--hold')
    a = p.parse_args()
    def hook(point):
        if a.hold == point:
            atomic_json(Path(a.state) / (point + '.reached'), {'point': point})
            while not Path(a.state, point + '.go').exists():
                time.sleep(.005)
    c = Controller(a.state, NftBackend(), hook=hook)
    try:
        c.start()
        if a.action == 'apply':
            c.apply('fault-change', c.s['generation'], {'default': 'accept', 'rules': [{'port': 59992, 'verdict': 'drop'}]}, 1)
            while c.s['phase'] == 'AWAITING_CONFIRM':
                c.tick(); time.sleep(.01)
        elif a.action == 'confirm':
            # This process cannot own a second active agent; used only after offline recovery.
            raise RuntimeError('Confirmation tests must use the live production TLS service')
        print(json.dumps(c.status()), flush=True)
        if c.s['phase'] == 'DEGRADED':
            raise SystemExit(2)
    finally:
        c.close()


if __name__ == '__main__':
    main()
