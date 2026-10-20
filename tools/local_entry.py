"""One-command wrapper: pinned tool installation or explicit existing toolchain overrides."""
import os
from pathlib import Path
import subprocess
import sys
import time
from .install_colima import install


def main():
    names = ['RULEMOOR_TOOLCHAIN', 'RULEMOOR_COLIMA_HOME', 'RULEMOOR_DOCKER_CONFIG']
    overrides = [os.environ.get(n) for n in names]
    if any(overrides) and not all(overrides):
        raise SystemExit('Supply all three RULEMOOR toolchain overrides, or none')
    if all(overrides):
        bins, home, config = overrides
    else:
        bins, env = install()
        home, config = env['COLIMA_HOME'], env['DOCKER_CONFIG']
    args = [sys.executable, '-m', 'tools.validate_local', '--toolchain', str(bins),
            '--colima-home', str(home), '--docker-config', str(config), *sys.argv[1:]]
    if '--output' not in sys.argv[1:]:
        args += ['--output', 'results/run-' + str(time.time_ns())]
    os.execv(sys.executable, args)


if __name__ == '__main__':
    main()
