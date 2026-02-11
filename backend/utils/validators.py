from __future__ import annotations

import ipaddress
import re
from typing import Literal, Tuple
from urllib.parse import urlparse

TargetType = Literal["domain", "url", "ip"]


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def normalize_domain(value: str) -> str:
    d = value.strip().lower().rstrip(".")
    # Convert Unicode domains to IDNA (punycode) for consistent analysis.
    try:
        d = d.encode("idna").decode("ascii")
    except Exception:
        # IDNA encoding failed; keep original domain.
        pass
    return d


def _looks_like_url(value: str) -> bool:
    v = value.strip()
    if "://" in v:
        return True
    # Common scheme-less URLs like example.com/path
    return ("/" in v or "?" in v or "#" in v) and "." in v


def normalize_url(value: str) -> str:
    v = value.strip()
    if not v:
        raise ValueError("Empty target")
    if "://" not in v:
        # Treat scheme-less inputs as HTTP URLs for parsing.
        v = "http://" + v
    return v


from urllib.parse import urlparse, ParseResult

def parse_url_loose(value: str) -> Tuple[str, ParseResult]:
    u = normalize_url(value)
    p = urlparse(u)
    if not p.netloc:
        raise ValueError("Invalid URL: missing host")
    return u, p


def detect_target_type(value: str) -> Tuple[TargetType, str]:
    v = value.strip()
    if not v:
        raise ValueError("Empty target")

    if is_ip(v):
        return "ip", normalize_ip(v)

    if _looks_like_url(v):
        return "url", normalize_url(v)

    d = normalize_domain(v)
    if _DOMAIN_RE.match(d):
        return "domain", d

    raise ValueError("Target is not a valid domain, URL, or IP address")
