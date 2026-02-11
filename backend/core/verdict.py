from __future__ import annotations


SAFE = "SAFE"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS = "MALICIOUS"


def verdict_for_score(risk_score: int) -> str:
    """Map an integer risk score (0-100) to a simple, explainable verdict."""
    if risk_score >= 70:
        return MALICIOUS
    if risk_score >= 30:
        return SUSPICIOUS
    return SAFE
