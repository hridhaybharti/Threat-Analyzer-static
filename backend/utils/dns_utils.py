from __future__ import annotations

from typing import Any, Dict, List

import dns.resolver


def _resolve(domain: str, rdtype: str, lifetime: float = 2.0) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, rdtype, lifetime=lifetime)
        return [str(a).strip() for a in answers]
    except Exception:
        return []


def dns_overview(domain: str) -> Dict[str, Any]:
    """Lightweight DNS checks used by heuristics."""

    a = _resolve(domain, "A")
    aaaa = _resolve(domain, "AAAA")
    ns = _resolve(domain, "NS")
    mx = _resolve(domain, "MX")

    return {
        "A": a,
        "AAAA": aaaa,
        "NS": ns,
        "MX": mx,
        "has_a_or_aaaa": bool(a or aaaa),
        "has_ns": bool(ns),
        "has_mx": bool(mx),
    }
