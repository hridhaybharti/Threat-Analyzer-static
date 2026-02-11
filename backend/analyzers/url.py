from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Tuple

from backend.core.scorer import score_signals_detailed
from backend.core.verdict import verdict_for_score
from backend.heuristics.domain_heuristics import domain_signals, domain_signals_async
from backend.heuristics.ip_heuristics import ip_signals, ip_signals_async
from backend.heuristics.url_heuristics import url_signals, url_signals_async
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


async def analyze_url_explain_async(url: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    _, parsed = parse_url_loose(url)
    host = (parsed.hostname or "").strip("[]")

    # Run URL and Host signals in parallel
    url_task = url_signals_async(url)
    
    if host and is_ip(host):
        host_task = ip_signals_async(host)
    elif host:
        host_task = domain_signals_async(host)
    else:
        host_task = asyncio.Future()
        host_task.set_result([])

    url_list, host_list = await asyncio.gather(url_task, host_task)
    
    signals = []
    signals.extend(url_list)
    signals.extend(host_list)

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
