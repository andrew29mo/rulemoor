"""Stable implementation/test snapshot. Docs/results are separate from executable inputs."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def manifest():
    files = [p for directory in ('rulemoor', 'tests', 'tools') for p in (ROOT / directory).rglob('*.py')]
    files += [ROOT / name for name in ('pyproject.toml', 'Dockerfile', 'deploy/rulemoor.service', 'tools/validate-local', 'tools/validate-deployment', 'tools/colima-lock.json')]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def fingerprint(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
