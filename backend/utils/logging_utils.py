from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, Optional


def target_fingerprint(target: str) -> str:
    """Return a stable, non-reversible fingerprint for logging.

    We avoid logging raw targets to reduce accidental leakage of sensitive inputs.
    """

    h = hashlib.sha256(target.encode("utf-8", errors="ignore")).hexdigest()
    return h[:12]


def log_analysis_event(
    logger: logging.Logger,
    *,
    analysis_id: Optional[int],
    target: str,
    target_type: str,
    verdict: str,
    risk_score: int,
    confidence: float,
    latency_ms: int,
    persistence_ok: bool,
) -> None:
    payload: Dict[str, Any] = {
        "event": "analysis_completed",
        "analysis_id": analysis_id,
        "target_fp": target_fingerprint(target),
        "target_len": len(target),
        "type": target_type,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "latency_ms": latency_ms,
        "persistence_ok": persistence_ok,
    }

    # Emit as a JSON string to keep it structured even with default logging formatters.
    logger.info(json.dumps(payload, separators=(",", ":")))
