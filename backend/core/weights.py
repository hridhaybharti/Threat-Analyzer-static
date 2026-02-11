from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict


def _default_weights_path() -> Path:
    # backend/core/weights.py -> backend/config/weights.json
    return Path(__file__).resolve().parents[1] / "config" / "weights.json"


@lru_cache(maxsize=1)
def load_weights() -> Dict[str, Any]:
    """Load heuristic weights from JSON.

    Tunable via env var:
      SECURITY_ANALYZER_WEIGHTS=/path/to/weights.json

    If the file is missing or invalid, returns safe defaults (all weights 1.0).
    """

    path_str = os.environ.get("SECURITY_ANALYZER_WEIGHTS")
    path = Path(path_str) if path_str else _default_weights_path()

    defaults: Dict[str, Any] = {
        "version": 1,
        "default_weight": 1.0,
        "by_bucket": {"reputation": 1.0, "structure": 1.0, "network": 1.0},
        "by_signal": {},
    }

    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            return defaults

        # Minimal validation + normalization
        default_weight = float(data.get("default_weight", 1.0))
        by_bucket = data.get("by_bucket", {})
        by_signal = data.get("by_signal", {})

        if not isinstance(by_bucket, dict):
            by_bucket = {}
        if not isinstance(by_signal, dict):
            by_signal = {}

        return {
            "version": int(data.get("version", 1)),
            "default_weight": default_weight if default_weight > 0 else 1.0,
            "by_bucket": {
                "reputation": float(by_bucket.get("reputation", 1.0)),
                "structure": float(by_bucket.get("structure", 1.0)),
                "network": float(by_bucket.get("network", 1.0)),
            },
            "by_signal": {str(k): float(v) for k, v in by_signal.items()},
            "path": str(path),
        }

    except Exception:
        return defaults
