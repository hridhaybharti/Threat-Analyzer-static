from __future__ import annotations

import math
from typing import Any, Dict, List

import requests

from backend.utils.validators import is_ip, parse_url_loose
from backend.heuristics.ssl_heuristics import ssl_certificate_signal


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "secure",
    "update",
    "password",
    "signin",
    "account",
    "billing",
    "invoice",
    "support",
    "confirm",
    "unlock",
    "session",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "s.id",
    "lnkd.in",
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def shortener_signal(url: str) -> Dict[str, Any]:
    _, p = parse_url_loose(url)
    host = (p.hostname or "").strip("[]").lower()

    if host in SHORTENER_DOMAINS:
        return {
            "name": "URL Shortener Detected",
            "category": "url",
            "bucket": "reputation",
            "impact": 20,
            "confidence": 0.8,
            "description": "URL uses a common shortener, which hides the final destination.",
            "evidence": {"host": host},
        }

    return {
        "name": "URL Shortener Detected",
        "category": "url",
        "bucket": "reputation",
        "impact": 0,
        "confidence": 0.45,
        "description": "URL is not a known shortener domain.",
        "evidence": {"host": host},
    }


def homograph_signal(url: str) -> Dict[str, Any]:
    """Best-effort homograph/IDN indicator.

    True homograph detection requires script-aware processing; this signal is intentionally simple and explainable.
    """

    _, p = parse_url_loose(url)
    host = (p.hostname or "").strip("[]")
    host_lower = host.lower()

    has_unicode = any(ord(c) > 127 for c in host)
    has_punycode = any(label.startswith("xn--") for label in host_lower.split(".") if label)

    if has_unicode or has_punycode:
        return {
            "name": "Homograph/IDN Indicator",
            "category": "url",
            "bucket": "structure",
            "impact": 22,
            "confidence": 0.7,
            "description": "Hostname contains IDN/punycode or non-ASCII characters (possible lookalike risk).",
            "evidence": {"host": host, "has_unicode": has_unicode, "has_punycode": has_punycode},
        }

    return {
        "name": "Homograph/IDN Indicator",
        "category": "url",
        "bucket": "structure",
        "impact": 0,
        "confidence": 0.5,
        "description": "No IDN/punycode indicators detected in hostname.",
        "evidence": {"host": host},
    }


def suspicious_keywords_signal(url: str) -> Dict[str, Any]:
    _, p = parse_url_loose(url)
    hay = (p.path + "?" + (p.query or "")).lower()
    hits = sorted([k for k in SUSPICIOUS_KEYWORDS if k in hay])

    if hits:
        impact = 18 if len(hits) >= 2 else 12
        return {
            "name": "Suspicious Keywords",
            "category": "url",
            "bucket": "reputation",
            "impact": impact,
            "confidence": 0.75,
            "description": "URL contains keywords commonly used in phishing lures.",
            "evidence": {"keywords": hits},
        }

    return {
        "name": "Suspicious Keywords",
        "category": "url",
        "bucket": "reputation",
        "impact": 0,
        "confidence": 0.4,
        "description": "No common phishing keywords detected in path/query.",
        "evidence": {},
    }


def length_entropy_signal(url: str) -> Dict[str, Any]:
    u, _ = parse_url_loose(url)
    L = len(u)
    ent = _entropy(u)

    impact = 0
    desc_parts: List[str] = []

    if L >= 120:
        impact += 20
        desc_parts.append("very long")
    elif L >= 75:
        impact += 10
        desc_parts.append("long")

    # Benign URLs often have entropy ~3-4; higher can suggest randomization/obfuscation.
    if ent >= 4.2:
        impact += 12
        desc_parts.append("high-entropy")
    elif ent >= 3.9:
        impact += 6
        desc_parts.append("moderately high-entropy")

    if impact > 0:
        desc = "URL is " + " and ".join(desc_parts) + ", which can indicate obfuscation or tracking."
    else:
        desc = "URL length/entropy are within typical ranges."

    return {
        "name": "URL Length & Entropy",
        "category": "url",
        "bucket": "structure",
        "impact": impact,
        "confidence": 0.65,
        "description": desc,
        "evidence": {"length": L, "entropy": round(ent, 2)},
    }


def path_query_entropy_signal(url: str) -> Dict[str, Any]:
    _, p = parse_url_loose(url)

    path = p.path or ""
    query = p.query or ""

    ent_path = _entropy(path)
    ent_query = _entropy(query)

    impact = 0
    if len(path) >= 25 and ent_path >= 3.9:
        impact += 8
    if len(query) >= 35 and ent_query >= 4.0:
        impact += 12

    if impact > 0:
        desc = "Path/query are unusually high-entropy, which can indicate obfuscation, tracking, or encoded payloads."
        conf = 0.65
    else:
        desc = "Path/query entropy are within typical ranges."
        conf = 0.45

    return {
        "name": "Path/Query Entropy",
        "category": "url",
        "bucket": "structure",
        "impact": impact,
        "confidence": conf,
        "description": desc,
        "evidence": {
            "path_length": len(path),
            "query_length": len(query),
            "path_entropy": round(ent_path, 2),
            "query_entropy": round(ent_query, 2),
        },
    }


def excessive_subdomains_signal(url: str) -> Dict[str, Any]:
    _, p = parse_url_loose(url)
    host = (p.hostname or "").strip("[]").lower()

    if is_ip(host) or not host:
        return {
            "name": "Excessive Subdomains",
            "category": "url",
            "bucket": "structure",
            "impact": 0,
            "confidence": 0.4,
            "description": "Subdomain heuristic not applicable to IP hosts.",
            "evidence": {"host": host},
        }

    labels = [x for x in host.split(".") if x]
    # Rough heuristic: many phishing URLs use deep subdomains.
    if len(labels) >= 6:
        return {
            "name": "Excessive Subdomains",
            "category": "url",
            "bucket": "structure",
            "impact": 14,
            "confidence": 0.7,
            "description": "Host contains unusually many dot-separated labels.",
            "evidence": {"host": host, "label_count": len(labels)},
        }

    return {
        "name": "Excessive Subdomains",
        "category": "url",
        "bucket": "structure",
        "impact": 0,
        "confidence": 0.5,
        "description": "Subdomain depth is not unusually high.",
        "evidence": {"host": host, "label_count": len(labels)},
    }


def ip_based_url_signal(url: str) -> Dict[str, Any]:
    _, p = parse_url_loose(url)
    host = (p.hostname or "").strip("[]").lower()

    if host and is_ip(host):
        return {
            "name": "IP-Based URL",
            "category": "url",
            "bucket": "structure",
            "impact": 30,
            "confidence": 0.9,
            "description": "URL host is an IP address (common in malware/phishing infrastructure).",
            "evidence": {"host": host},
        }

    return {
        "name": "IP-Based URL",
        "category": "url",
        "bucket": "structure",
        "impact": 0,
        "confidence": 0.6,
        "description": "URL host is a domain name.",
        "evidence": {"host": host},
    }


def redirect_count_signal(url: str, max_redirects: int = 5) -> Dict[str, Any]:
    u, p = parse_url_loose(url)

    if p.scheme not in {"http", "https"}:
        return {
            "name": "Redirect Count",
            "category": "url",
            "bucket": "network",
            "impact": 0,
            "confidence": 0.3,
            "description": "Redirect heuristic only applies to http/https URLs.",
            "evidence": {"scheme": p.scheme},
        }

    try:
        # Keep it quick and safe: small timeout, no large downloads.
        resp = requests.get(u, allow_redirects=True, timeout=3.0, stream=True)
        history_len = len(resp.history)
        capped = min(history_len, max_redirects)

        if capped >= 3:
            impact = 16
            conf = 0.7
            desc = f"URL performed {history_len} redirects (can indicate traffic laundering)."
        elif capped == 2:
            impact = 8
            conf = 0.6
            desc = f"URL performed {history_len} redirects (mild risk signal)."
        else:
            impact = 0
            conf = 0.55
            desc = "No meaningful redirect chain observed."

        return {
            "name": "Redirect Count",
            "category": "url",
            "bucket": "network",
            "impact": impact,
            "confidence": conf,
            "description": desc,
            "evidence": {"redirects": history_len},
        }

    except Exception as e:
        # Network may be unavailable in evaluation environments; keep it explainable.
        return {
            "name": "Redirect Count",
            "category": "url",
            "bucket": "network",
            "impact": 0,
            "confidence": 0.2,
            "description": "Redirect check could not be performed (network blocked or request failed).",
            "evidence": {"error": str(e)},
        }


def url_signals(url: str) -> List[Dict[str, Any]]:
    return [
        shortener_signal(url),
        homograph_signal(url),
        suspicious_keywords_signal(url),
        length_entropy_signal(url),
        path_query_entropy_signal(url),
        excessive_subdomains_signal(url),
        ip_based_url_signal(url),
        redirect_count_signal(url),
        ssl_certificate_signal(url),
    ]
