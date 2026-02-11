from __future__ import annotations

from typing import Any, Dict, Tuple

from backend.core.scorer import score_signals_detailed
from backend.core.verdict import verdict_for_score
from backend.heuristics.domain_heuristics import domain_signals
from backend.utils.validators import normalize_domain


def analyze_domain_explain(domain: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    d = normalize_domain(domain)
    signals = domain_signals(d)

    risk_score, confidence, breakdown, scoring_math = score_signals_detailed(signals)

    result: Dict[str, Any] = {
        "target": domain,
        "type": "domain",
        "risk_score": risk_score,
        "confidence": confidence,
        "verdict": verdict_for_score(risk_score),
        "signals": signals,
        "breakdown": breakdown,
    }

    explain = {
        "target": domain,
        "type": "domain",
        "signals": signals,
        "breakdown": breakdown,
        "scoring": scoring_math,
    }

    return result, explain


def analyze_domain(domain: str) -> Dict[str, Any]:
    return analyze_domain_explain(domain)[0]
