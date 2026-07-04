"""Minimal, stdlib-only `.env` reader.

Lives in its own module so import-light callers (notably pulse.py, which runs at
atexit and must not drag in requests/numpy — the 0.3.1 import-safety lesson) can
read the project `.env` without importing cli.py and its heavy dependency graph.
cli.py re-exports load_env_file from here for backward compatibility.
"""
import os


def load_env_file():
    """Extract KEY=value bindings from ./.env, falling back to ../.env. Returns a
    dict (empty if no file). Best-effort; never raises."""
    env_vars = {}
    target_path = ".env"

    # If .env is missing locally, check the parent directory.
    if not os.path.exists(target_path):
        parent_fallback = os.path.join("..", ".env")
        if os.path.exists(parent_fallback):
            target_path = parent_fallback
        else:
            return env_vars

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                env_vars[key.strip()] = val.strip().strip('"').strip("'")
    except Exception:
        pass
    return env_vars
