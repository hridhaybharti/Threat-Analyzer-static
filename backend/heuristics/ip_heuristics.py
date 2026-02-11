from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache
from typing import Any, Dict, List, Optional

from ipwhois import IPWhois


# NOTE: Country-based scoring is a weak heuristic and should be treated carefully.
# Keep it small and adjust for your threat model.
COUNTRY_RISK = {
    "RU": 8,
    "IR": 8,
    "KP": 10,
}

HOSTING_KEYWORDS = {
    "hosting",
    "cloud",
    "datacenter",
    "data center",
    "vps",
    "colocation",
    "colo",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "digitalocean",
    "ovh",
    "hetzner",
}

VPN_TOR_KEYWORDS = {
    "vpn",
    "tunnel",
    "proxy",
    "tor",
}

PROVIDER_CLUSTERS = {
    "aws": {"amazon", "aws"},
    "gcp": {"google"},
    "azure": {"microsoft", "azure"},
    "cloudflare": {"cloudflare"},
    "ovh": {"ovh"},
    "hetzner": {"hetzner"},
    "digitalocean": {"digitalocean"},
}


@lru_cache(maxsize=2048)
def _rdap_lookup(ip: str) -> Dict[str, Any]:
    # Cached to avoid repeated network lookups for the same IP.
    return IPWhois(ip).lookup_rdap(depth=1)


@lru_cache(maxsize=2048)
def _reverse_dns(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.lower()
    except Exception:
        return None


def private_public_signal(ip: str) -> Dict[str, Any]:
    addr = ipaddress.ip_address(ip)

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return {
            "name": "Private vs Public IP",
            "category": "ip",
            "bucket": "network",
            "impact": -4,
            "confidence": 0.9,
            "description": "IP is non-public (private/loopback/link-local), reducing internet exposure.",
            "evidence": {"ip": ip, "is_private": True},
        }

    return {
        "name": "Private vs Public IP",
        "category": "ip",
        "bucket": "network",
        "impact": 0,
        "confidence": 0.7,
        "description": "IP is publicly routable.",
        "evidence": {"ip": ip, "is_private": False},
    }


def ipv6_specific_signal(ip: str) -> Dict[str, Any]:
    addr = ipaddress.ip_address(ip)
    if addr.version != 6:
        return {
            "name": "IPv6 Specific Heuristics",
            "category": "ip",
            "bucket": "network",
            "impact": 0,
            "confidence": 0.3,
            "description": "Not an IPv6 address; IPv6-specific heuristics not applicable.",
            "evidence": {"ip": ip},
        }

    # Special-purpose IPv6 ranges are uncommon in benign use and can be suspicious.
    six_to_four = ipaddress.ip_network("2002::/16")
    teredo = ipaddress.ip_network("2001:0::/32")
    documentation = ipaddress.ip_network("2001:db8::/32")

    if addr in documentation:
        return {
            "name": "IPv6 Specific Heuristics",
            "category": "ip",
            "bucket": "network",
            "impact": 10,
            "confidence": 0.7,
            "description": "IP is in the IPv6 documentation range (unlikely to be legitimate on the public internet).",
            "evidence": {"ip": ip, "range": "2001:db8::/32"},
        }

    if addr in six_to_four:
        return {
            "name": "IPv6 Specific Heuristics",
            "category": "ip",
            "bucket": "network",
            "impact": 8,
            "confidence": 0.6,
            "description": "IP is in the 6to4 range (transition mechanism; can be abused).",
            "evidence": {"ip": ip, "range": "2002::/16"},
        }

    if addr in teredo:
        return {
            "name": "IPv6 Specific Heuristics",
            "category": "ip",
            "bucket": "network",
            "impact": 8,
            "confidence": 0.6,
            "description": "IP is in the Teredo range (transition mechanism; can be abused).",
            "evidence": {"ip": ip, "range": "2001:0::/32"},
        }

    return {
        "name": "IPv6 Specific Heuristics",
        "category": "ip",
        "bucket": "network",
        "impact": 0,
        "confidence": 0.45,
        "description": "IPv6 address did not match special transition/documentation ranges.",
        "evidence": {"ip": ip},
    }


def _provider_cluster(asn_desc: str, net_name: Optional[str]) -> Optional[str]:
    hay = (asn_desc or "").lower() + " " + (net_name or "").lower()
    for provider, keys in PROVIDER_CLUSTERS.items():
        if any(k in hay for k in keys):
            return provider
    return None


def asn_isp_type_signal(ip: str) -> Dict[str, Any]:
    try:
        data = _rdap_lookup(ip)
        asn = data.get("asn")
        asn_desc = (data.get("asn_description") or "").lower()
        net_name = (data.get("network", {}) or {}).get("name")

        is_hosting = any(k in asn_desc for k in HOSTING_KEYWORDS)
        provider = _provider_cluster(asn_desc, net_name)

        if is_hosting:
            return {
                "name": "ASN / ISP Type",
                "category": "ip",
                "bucket": "network",
                "impact": 10,
                "confidence": 0.65,
                "description": "ASN description suggests hosting/cloud infrastructure (often abused at scale).",
                "evidence": {
                    "asn": asn,
                    "asn_description": data.get("asn_description"),
                    "network": net_name,
                    "provider_cluster": provider,
                },
            }

        return {
            "name": "ASN / ISP Type",
            "category": "ip",
            "bucket": "network",
            "impact": 0,
            "confidence": 0.55,
            "description": "ASN does not strongly indicate hosting/cloud infrastructure.",
            "evidence": {
                "asn": asn,
                "asn_description": data.get("asn_description"),
                "network": net_name,
                "provider_cluster": provider,
            },
        }

    except Exception as e:
        return {
            "name": "ASN / ISP Type",
            "category": "ip",
            "bucket": "network",
            "impact": 0,
            "confidence": 0.2,
            "description": "ASN lookup failed (could not determine ISP type).",
            "evidence": {"error": str(e)},
        }


def hosting_provider_cluster_signal(ip: str) -> Dict[str, Any]:
    """Provide a lightweight provider grouping for auditability and clustering."""

    try:
        data = _rdap_lookup(ip)
        asn_desc = data.get("asn_description") or ""
        net_name = (data.get("network", {}) or {}).get("name")

        provider = _provider_cluster(str(asn_desc), str(net_name) if net_name else None)
        if provider:
            return {
                "name": "Hosting Provider Cluster",
                "category": "ip",
                "bucket": "network",
                "impact": 6,
                "confidence": 0.55,
                "description": "IP appears to belong to a major hosting/cloud provider cluster.",
                "evidence": {"provider_cluster": provider, "asn_description": asn_desc, "network": net_name},
            }

        return {
            "name": "Hosting Provider Cluster",
            "category": "ip",
            "bucket": "network",
            "impact": 0,
            "confidence": 0.35,
            "description": "No hosting provider cluster matched.",
            "evidence": {"asn_description": asn_desc, "network": net_name},
        }

    except Exception as e:
        return {
            "name": "Hosting Provider Cluster",
            "category": "ip",
            "bucket": "network",
            "impact": 0,
            "confidence": 0.2,
            "description": "Provider clustering could not be computed.",
            "evidence": {"error": str(e)},
        }


def country_risk_signal(ip: str) -> Dict[str, Any]:
    try:
        data = _rdap_lookup(ip)
        cc = (data.get("asn_country_code") or "").upper()
        risk = COUNTRY_RISK.get(cc, 0)

        if risk > 0:
            return {
                "name": "Country Risk",
                "category": "ip",
                "bucket": "network",
                "impact": risk,
                "confidence": 0.45,
                "description": "Country-based risk heuristic triggered (weak signal; threat-model dependent).",
                "evidence": {"country_code": cc, "risk": risk},
            }

        return {
            "name": "Country Risk",
            "category": "ip",
            "bucket": "network",
            "impact": 0,
            "confidence": 0.35,
            "description": "No country risk heuristic triggered.",
            "evidence": {"country_code": cc},
        }

    except Exception as e:
        return {
            "name": "Country Risk",
            "category": "ip",
            "bucket": "network",
            "impact": 0,
            "confidence": 0.2,
            "description": "Country lookup failed.",
            "evidence": {"error": str(e)},
        }


def tor_vpn_indicators_signal(ip: str) -> Dict[str, Any]:
    rdns = _reverse_dns(ip) or ""

    try:
        data = _rdap_lookup(ip)
        asn_desc = (data.get("asn_description") or "").lower()
    except Exception:
        asn_desc = ""

    hits: List[str] = []
    for k in VPN_TOR_KEYWORDS:
        if k in rdns or k in asn_desc:
            hits.append(k)

    if hits:
        return {
            "name": "TOR/VPN Indicators",
            "category": "ip",
            "bucket": "network",
            "impact": 18,
            "confidence": 0.55,
            "description": "Reverse DNS / ASN description suggest VPN/proxy/TOR-like infrastructure.",
            "evidence": {"reverse_dns": rdns or None, "asn_description": asn_desc or None, "hits": sorted(set(hits))},
        }

    return {
        "name": "TOR/VPN Indicators",
        "category": "ip",
        "bucket": "network",
        "impact": 0,
        "confidence": 0.35,
        "description": "No obvious TOR/VPN indicators found via reverse DNS / ASN keywords.",
        "evidence": {"reverse_dns": rdns or None},
    }


def ip_signals(ip: str) -> List[Dict[str, Any]]:
    return [
        private_public_signal(ip),
        ipv6_specific_signal(ip),
        asn_isp_type_signal(ip),
        hosting_provider_cluster_signal(ip),
        country_risk_signal(ip),
        tor_vpn_indicators_signal(ip),
    ]
