from __future__ import annotations

from typing import Any, Dict, List, Tuple

from backend.core.scorer import score_signals_detailed
from backend.core.verdict import verdict_for_score
from backend.heuristics.domain_heuristics import domain_signals
from backend.heuristics.ip_heuristics import ip_signals
from backend.heuristics.url_heuristics import url_signals
from backend.utils.validators import is_ip, parse_url_loose


def analyze_url_explain(url: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    _, parsed = parse_url_loose(url)
    host = (parsed.hostname or "").strip("[]")

    signals: List[Dict[str, Any]] = []

    # URL-level heuristics
    signals.extend(url_signals(url))

    # Host-level heuristics
    if host and is_ip(host):
        signals.extend(ip_signals(host))
    elif host:
        signals.extend(domain_signals(host))

    risk_score, confidence, breakdown, scoring_math = score_signals_detailed(signals)

    result: Dict[str, Any] = {
        "target": url,
        "type": "url",
        "risk_score": risk_score,
        "confidence": confidence,
        "verdict": verdict_for_score(risk_score),
        "signals": signals,
        "breakdown": breakdown,
    }

    explain = {
        "target": url,
        "type": "url",
        "signals": signals,
        "breakdown": breakdown,
        "scoring": scoring_math,
    }

    return result, explain


def analyze_url(url: str) -> Dict[str, Any]:
    return analyze_url_explain(url)[0]
