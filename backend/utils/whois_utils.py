from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import whois


def _pick_earliest_date(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, list):
        dates = [d for d in value if isinstance(d, datetime)]
        return min(dates) if dates else None
    if isinstance(value, datetime):
        return value
    return None


def whois_summary(domain: str) -> Dict[str, Any]:
    """Best-effort WHOIS lookup.

    WHOIS is inconsistent across TLDs/registrars; this must be resilient.
    """

    try:
        w = whois.whois(domain)
    except Exception as e:
        return {"ok": False, "error": str(e)}

    creation = _pick_earliest_date(getattr(w, "creation_date", None) or w.get("creation_date"))
    registrar = getattr(w, "registrar", None) or w.get("registrar")

    return {
        "ok": True,
        "creation_date": creation,
        "registrar": registrar,
    }


async def whois_summary_async(domain: str) -> Dict[str, Any]:
    """Asynchronous version of whois_summary using asyncio.to_thread."""
    return await asyncio.to_thread(whois_summary, domain)


def domain_age_days(domain: str) -> Tuple[Optional[int], Dict[str, Any]]:
    summary = whois_summary(domain)
    if not summary.get("ok"):
        return None, summary

    creation = summary.get("creation_date")
    if not isinstance(creation, datetime):
        return None, summary

    if creation.tzinfo is None:
        creation = creation.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    delta = now - creation
    return max(0, int(delta.days)), summary


async def domain_age_days_async(domain: str) -> Tuple[Optional[int], Dict[str, Any]]:
    """Asynchronous version of domain_age_days."""
    summary = await whois_summary_async(domain)
    if not summary.get("ok"):
        return None, summary

    creation = summary.get("creation_date")
    if not isinstance(creation, datetime):
        return None, summary

    if creation.tzinfo is None:
        creation = creation.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    delta = now - creation
    return max(0, int(delta.days)), summary
