from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from backend.core.weights import load_weights


BUCKETS = ("reputation", "structure", "network")


def _clamp_int(value: float, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, int(round(value))))


def _clamp_float(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(value)))


def _infer_bucket(signal: Dict[str, Any]) -> str:
    bucket = signal.get("bucket")
    if bucket in BUCKETS:
        return str(bucket)

    # Backwards-compatible inference if a signal doesn't set bucket explicitly.
    category = str(signal.get("category") or "")
    if category == "ip":
        return "network"
    if category == "domain":
        return "reputation"
    if category == "url":
        return "structure"

    return "structure"


def _has_evidence(signal: Dict[str, Any]) -> bool:
    ev = signal.get("evidence")
    if isinstance(ev, dict):
        # Ignore evidence that is only an error.
        meaningful = {k: v for k, v in ev.items() if k != "error" and v not in (None, "", [], {})}
        return bool(meaningful)
    return bool(ev)


def score_signals_detailed(
    signals: Iterable[Dict[str, Any]],
) -> Tuple[int, float, Dict[str, int], Dict[str, Any]]:
    """Score signals into risk_score/confidence, plus breakdown and math.

    This function is intended for production use and for auditability (explain endpoint).

    Returns:
      risk_score: int 0..100
      confidence: float 0..1
      breakdown: {reputation, structure, network} -> int 0..100 (risk-only contribution)
      math: dict containing scoring details and per-signal contributions
    """

    signals_list = list(signals)
    if not signals_list:
        breakdown = {"reputation": 0, "structure": 0, "network": 0}
        return 0, 0.2, breakdown, {"signals": [], "weights": load_weights()}

    weights = load_weights()
    default_weight = float(weights.get("default_weight", 1.0))
    by_bucket = weights.get("by_bucket", {}) or {}
    by_signal = weights.get("by_signal", {}) or {}

    weighted_sum = 0.0
    risk_mass = 0.0
    trust_mass = 0.0

    breakdown_raw = {"reputation": 0.0, "structure": 0.0, "network": 0.0}
    per_signal: List[Dict[str, Any]] = []

    evidence_hits = 0
    informative_hits = 0
    conf_sum = 0.0

    for s in signals_list:
        name = str(s.get("name") or "Unknown")
        impact = float(s.get("impact", 0))
        signal_conf = _clamp_float(s.get("confidence", 0.5), 0.0, 1.0)

        bucket = _infer_bucket(s)
        bucket_weight = float(by_bucket.get(bucket, 1.0))
        signal_weight = float(by_signal.get(name, 1.0))
        inline_weight = float(s.get("weight", 1.0))

        # Ensure weights are non-negative and sane.
        if default_weight <= 0:
            default_weight = 1.0
        if bucket_weight <= 0:
            bucket_weight = 1.0
        if signal_weight <= 0:
            signal_weight = 1.0
        if inline_weight <= 0:
            inline_weight = 1.0

        final_weight = default_weight * bucket_weight * signal_weight * inline_weight
        contribution = impact * signal_conf * final_weight

        weighted_sum += contribution
        risk_mass += max(0.0, contribution)
        trust_mass += max(0.0, -contribution)

        breakdown_raw[bucket] = breakdown_raw.get(bucket, 0.0) + max(0.0, contribution)

        if _has_evidence(s):
            evidence_hits += 1
        if abs(impact) > 0:
            informative_hits += 1

        conf_sum += signal_conf

        per_signal.append(
            {
                "name": name,
                "bucket": bucket,
                "impact": impact,
                "signal_confidence": signal_conf,
                "weight": round(final_weight, 4),
                "contribution": round(contribution, 4),
            }
        )

    # Risk is the signed sum of contributions, clamped into a user-friendly range.
    risk_score = _clamp_int(weighted_sum, 0, 100)

    # Confidence model (heuristic-only, explainable):
    # - increases with the number of heuristics executed
    # - increases when evidence is available
    # - decreases when risk vs trust contributions strongly contradict each other
    n = len(signals_list)
    coverage_factor = min(1.0, n / 8.0)
    evidence_ratio = evidence_hits / max(1, n)

    avg_signal_conf = conf_sum / max(1, n)

    if risk_mass > 0 and trust_mass > 0:
        contradiction = min(risk_mass, trust_mass) / max(risk_mass, trust_mass)
    else:
        contradiction = 0.0

    base = 0.15 + (0.45 * avg_signal_conf) + (0.2 * coverage_factor) + (0.2 * evidence_ratio)

    # If almost everything is zero-impact, we are less certain.
    if informative_hits < 2:
        base *= 0.65

    confidence = base - (0.35 * contradiction)
    confidence = _clamp_float(confidence, 0.05, 0.98)

    breakdown = {k: _clamp_int(v, 0, 100) for k, v in breakdown_raw.items()}

    math = {
        "weights": weights,
        "weighted_sum": round(weighted_sum, 4),
        "risk_mass": round(risk_mass, 4),
        "trust_mass": round(trust_mass, 4),
        "contradiction": round(contradiction, 4),
        "coverage_factor": round(coverage_factor, 4),
        "evidence_ratio": round(evidence_ratio, 4),
        "avg_signal_confidence": round(avg_signal_conf, 4),
        "signals": per_signal,
        "breakdown_raw": {k: round(v, 4) for k, v in breakdown_raw.items()},
    }

    return risk_score, round(confidence, 2), breakdown, math


def score_signals(signals: Iterable[Dict[str, Any]]) -> Tuple[int, float]:
    """Compatibility wrapper used by simple callers."""

    risk_score, confidence, _, _ = score_signals_detailed(signals)
    return risk_score, confidence
