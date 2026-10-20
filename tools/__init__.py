"""Executable validation requires assertions; never silently run it optimized."""
import sys

if sys.flags.optimize:
    raise RuntimeError('Validation requires assertions enabled; remove -O and PYTHONOPTIMIZE')
