from __future__ import annotations

from typing import Any, Dict, Tuple

from backend.core.scorer import score_signals_detailed
from backend.core.verdict import verdict_for_score
from backend.heuristics.ip_heuristics import ip_signals, ip_signals_async
from backend.utils.validators import normalize_ip


def analyze_ip_explain(ip: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    ipn = normalize_ip(ip)
    signals = ip_signals(ipn)

    risk_score, confidence, breakdown, scoring_math = score_signals_detailed(signals)

    result: Dict[str, Any] = {
        "target": ip,
        "type": "ip",
        "risk_score": risk_score,
        "confidence": confidence,
        "verdict": verdict_for_score(risk_score),
        "signals": signals,
        "breakdown": breakdown,
    }

    explain = {
        "target": ip,
        "type": "ip",
        "signals": signals,
        "breakdown": breakdown,
        "scoring": scoring_math,
    }

    return result, explain


async def analyze_ip_explain_async(ip: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    ipn = normalize_ip(ip)
    signals = await ip_signals_async(ipn)

    risk_score, confidence, breakdown, scoring_math = score_signals_detailed(signals)

    result: Dict[str, Any] = {
        "target": ip,
        "type": "ip",
        "risk_score": risk_score,
        "confidence": confidence,
        "verdict": verdict_for_score(risk_score),
        "signals": signals,
        "breakdown": breakdown,
    }

    explain = {
        "target": ip,
        "type": "ip",
        "signals": signals,
        "breakdown": breakdown,
        "scoring": scoring_math,
    }

    return result, explain


def analyze_ip(ip: str) -> Dict[str, Any]:
    return analyze_ip_explain(ip)[0]
