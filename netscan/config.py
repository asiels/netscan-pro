"""JSON config file support with deep-merge over built-in defaults."""

from __future__ import annotations

import json
from pathlib import Path

DEFAULTS: dict = {
    "engine": "async",
    "ports": "1-1024",
    "timeout": 1.0,
    "concurrency": 500,
    "report": "table",
    "discover": "none",
    "nvd": False,
}


def load_config(path: str | None) -> dict:
    """Load a JSON config file over DEFAULTS. Silently skips when path is None."""
    cfg = dict(DEFAULTS)
    if not path:
        return cfg
    user_cfg = json.loads(Path(path).read_text())
    for key, value in user_cfg.items():
        cfg[key] = value
    return cfg
