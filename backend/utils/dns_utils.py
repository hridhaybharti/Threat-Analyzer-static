from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import dns.resolver


def _resolve(domain: str, rdtype: str, lifetime: float = 2.0) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, rdtype, lifetime=lifetime)
        return [str(a).strip() for a in answers]
    except Exception:
        return []


async def _resolve_async(domain: str, rdtype: str, lifetime: float = 2.0) -> List[str]:
    """Asynchronous DNS resolution using asyncio.to_thread."""
    return await asyncio.to_thread(_resolve, domain, rdtype, lifetime)


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


async def dns_overview_async(domain: str) -> Dict[str, Any]:
    """Asynchronous version of dns_overview running resolutions in parallel."""

    tasks = [
        _resolve_async(domain, "A"),
        _resolve_async(domain, "AAAA"),
        _resolve_async(domain, "NS"),
        _resolve_async(domain, "MX"),
    ]

    a, aaaa, ns, mx = await asyncio.gather(*tasks)

    return {
        "A": a,
        "AAAA": aaaa,
        "NS": ns,
        "MX": mx,
        "has_a_or_aaaa": bool(a or aaaa),
        "has_ns": bool(ns),
        "has_mx": bool(mx),
    }
