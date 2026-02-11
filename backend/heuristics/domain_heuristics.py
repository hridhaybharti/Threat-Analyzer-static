from __future__ import annotations

import asyncio
import math
from typing import Any, Dict, List, Optional

from backend.utils.dns_utils import dns_overview, dns_overview_async
from backend.utils.whois_utils import domain_age_days, domain_age_days_async
from backend.utils.reputation import reputation_service


SUSPICIOUS_TLDS = {
    "top",
    "xyz",
    "tk",
    "ml",
    "ga",
    "cf",
    "buzz",
    "rest",
    "work",
    "date",
    "download",
    "review",
    "accountant",
}

# Small, explainable lists (academic/demo purpose). Extend as needed.
REPUTABLE_REGISTRARS = {
    "cloudflare, inc.",
    "namecheap, inc.",
    "godaddy.com, llc",
    "gandi sas",
    "tucows domains inc.",
    "markmonitor inc.",
}

SUSPICIOUS_REGISTRAR_KEYWORDS = {
    "privacy",
    "protect",
    "whoisguard",
}

# A small brand list for typosquatting heuristics; keep it limited and transparent.
BRANDS = {
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "netflix",
    "github",
    "dropbox",
    "steam",
    "discord",
    "spotify",
    "bankofamerica",
    "chase",
    "wellsfargo",
    "icloud",
    "outlook",
    "office",
    "telegram",
    "chatgpt",
    "openai",
    "google",
    "youtube",
    "linkedin",
    "twitter",
    "x",
}

# Domains that are virtually guaranteed to be safe (Top-tier global services).
TOP_TIER_DOMAINS = {
    "chatgpt.com",
    "openai.com",
    "google.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "youtube.com",
}

PARKING_NS_KEYWORDS = {
    "sedoparking",
    "parkingcrew",
    "bodis",
    "afternic",
    "uniregistrymarket",
    "namebrightdns",
    "domainparking",
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


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein edit distance.

    This is only used against a small local brand list, so performance is fine.
    """

    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            ins = cur[j - 1] + 1
            delete = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def _tld(domain: str) -> str:
    parts = [p for p in domain.split(".") if p]
    return parts[-1].lower() if len(parts) >= 2 else ""


def _sld(domain: str) -> str:
    parts = [p for p in domain.split(".") if p]
    return parts[-2].lower() if len(parts) >= 2 else domain.lower()


def suspicious_tld_signal(domain: str) -> Optional[Dict[str, Any]]:
    tld = _tld(domain)
    if tld in SUSPICIOUS_TLDS:
        return {
            "name": "Suspicious TLD",
            "category": "domain",
            "bucket": "structure",
            "impact": 18,
            "confidence": 0.8,
            "description": f"The .{tld} TLD is statistically over-represented in abuse reports.",
            "evidence": {"tld": tld},
        }
    return None


def domain_age_signal(domain: str, days_meta: Optional[Tuple[Optional[int], Dict[str, Any]]] = None) -> Dict[str, Any]:
    if days_meta is None:
        days, meta = domain_age_days(domain)
    else:
        days, meta = days_meta

    if days is None:
        return {
            "name": "Domain Age",
            "category": "domain",
            "bucket": "reputation",
            "impact": 0,
            "confidence": 0.2,
            "description": "WHOIS domain age could not be determined.",
            "evidence": {k: str(v) for k, v in (meta or {}).items() if k != "creation_date"},
        }

    # Age bucketing (explicit, explainable)
    if days < 30:
        age_bucket = "lt_30d"
    elif days < 90:
        age_bucket = "lt_90d"
    elif days < 365:
        age_bucket = "lt_1y"
    else:
        age_bucket = "gte_1y"

    if days < 30:
        impact = 30
        conf = 0.75
        desc = f"Domain appears very new ({days} days old)."
    elif days < 180:
        impact = 15
        conf = 0.65
        desc = f"Domain is relatively new ({days} days old)."
    elif days < 365:
        impact = 5
        conf = 0.55
        desc = f"Domain is under 1 year old ({days} days old)."
    else:
        impact = -6
        conf = 0.6
        desc = f"Domain age is over 1 year ({days} days old), which is a mild trust signal."

    return {
        "name": "Domain Age",
        "category": "domain",
        "bucket": "reputation",
        "impact": impact,
        "confidence": conf,
        "description": desc,
        "evidence": {"age_days": days, "age_bucket": age_bucket},
    }


def registrar_reputation_signal(domain: str, days_meta: Optional[Tuple[Optional[int], Dict[str, Any]]] = None) -> Dict[str, Any]:
    if days_meta is None:
        _, meta = domain_age_days(domain)
    else:
        _, meta = days_meta
    
    registrar = (meta.get("registrar") or "") if isinstance(meta, dict) else ""
    registrar_norm = str(registrar).strip().lower()

    if not registrar_norm:
        return {
            "name": "Registrar Reputation",
            "category": "domain",
            "bucket": "reputation",
            "impact": 5,
            "confidence": 0.4,
            "description": "Registrar could not be identified (weak risk signal).",
            "evidence": {},
        }

    if registrar_norm in REPUTABLE_REGISTRARS:
        return {
            "name": "Registrar Reputation",
            "category": "domain",
            "bucket": "reputation",
            "impact": -4,
            "confidence": 0.55,
            "description": "Registrar is commonly used by reputable organizations (weak trust signal).",
            "evidence": {"registrar": registrar},
        }

    if any(k in registrar_norm for k in SUSPICIOUS_REGISTRAR_KEYWORDS):
        return {
            "name": "Registrar Reputation",
            "category": "domain",
            "bucket": "reputation",
            "impact": 10,
            "confidence": 0.5,
            "description": "Registrar string suggests heavy privacy/proxying (weak risk signal).",
            "evidence": {"registrar": registrar},
        }

    return {
        "name": "Registrar Reputation",
        "category": "domain",
        "bucket": "reputation",
        "impact": 2,
        "confidence": 0.35,
        "description": "Registrar is not in the local reputation lists (very weak risk signal).",
        "evidence": {"registrar": registrar},
    }


def registrar_randomness_signal(domain: str, days_meta: Optional[Tuple[Optional[int], Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Detect unusual registrar strings.

    This is a weak heuristic: registrar names are usually human-readable, so we treat this as low confidence.
    """

    if days_meta is None:
        _, meta = domain_age_days(domain)
    else:
        _, meta = days_meta

    registrar = (meta.get("registrar") or "") if isinstance(meta, dict) else ""
    registrar_s = str(registrar).strip()
    registrar_norm = registrar_s.lower()

    if not registrar_s:
        return {
            "name": "Registrar Randomness",
            "category": "domain",
            "bucket": "reputation",
            "impact": 0,
            "confidence": 0.2,
            "description": "Registrar could not be identified; randomness check skipped.",
            "evidence": {},
        }

    # Simple, explainable indicators of "random" strings.
    digits = sum(ch.isdigit() for ch in registrar_s)
    non_alnum = sum((not ch.isalnum()) for ch in registrar_s)
    length = max(1, len(registrar_s))
    digit_ratio = digits / length
    non_alnum_ratio = non_alnum / length
    ent = _entropy(registrar_norm)

    suspicious = (digit_ratio > 0.2) or (non_alnum_ratio > 0.25) or (ent >= 4.2)

    if suspicious:
        return {
            "name": "Registrar Randomness",
            "category": "domain",
            "bucket": "reputation",
            "impact": 6,
            "confidence": 0.35,
            "description": "Registrar string looks unusually noisy/random (weak risk signal).",
            "evidence": {
                "registrar": registrar_s,
                "digit_ratio": round(digit_ratio, 3),
                "non_alnum_ratio": round(non_alnum_ratio, 3),
                "entropy": round(ent, 2),
            },
        }

    return {
        "name": "Registrar Randomness",
        "category": "domain",
        "bucket": "reputation",
        "impact": 0,
        "confidence": 0.35,
        "description": "Registrar string looks typical.",
        "evidence": {"entropy": round(ent, 2)},
    }


def dns_validity_signals(domain: str, ov: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    if ov is None:
        ov = dns_overview(domain)
    
    signals: List[Dict[str, Any]] = []

    if not ov.get("has_ns"):
        signals.append(
            {
                "name": "DNS Nameservers",
                "category": "domain",
                "bucket": "network",
                "impact": 12,
                "confidence": 0.7,
                "description": "No NS records found (domain may be misconfigured or newly staged).",
                "evidence": {"NS": ov.get("NS", [])},
            }
        )
    else:
        signals.append(
            {
                "name": "DNS Nameservers",
                "category": "domain",
                "bucket": "network",
                "impact": -3,
                "confidence": 0.5,
                "description": "NS records exist (weak trust signal).",
                "evidence": {"NS": ov.get("NS", [])[:3]},
            }
        )

    if not ov.get("has_a_or_aaaa"):
        signals.append(
            {
                "name": "DNS A/AAAA",
                "category": "domain",
                "bucket": "network",
                "impact": 14,
                "confidence": 0.75,
                "description": "No A/AAAA records found (domain does not resolve).",
                "evidence": {"A": ov.get("A", []), "AAAA": ov.get("AAAA", [])},
            }
        )
    else:
        signals.append(
            {
                "name": "DNS A/AAAA",
                "category": "domain",
                "bucket": "network",
                "impact": -2,
                "confidence": 0.5,
                "description": "Domain resolves to at least one IP (weak trust signal).",
                "evidence": {"A": ov.get("A", [])[:3], "AAAA": ov.get("AAAA", [])[:3]},
            }
        )

    return signals


def parked_domain_signal(domain: str, ov: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Best-effort parked domain detection.

    This relies on NS keywords and the absence of typical email infrastructure (MX).
    It will miss many parked domains, and it can false-positive.
    """

    if ov is None:
        ov = dns_overview(domain)
    
    ns = [str(x).lower() for x in (ov.get("NS") or [])]

    ns_hit = None
    for n in ns:
        for k in PARKING_NS_KEYWORDS:
            if k in n:
                ns_hit = k
                break
        if ns_hit:
            break

    if ns_hit and (not ov.get("has_mx")):
        return {
            "name": "Parked Domain Suspected",
            "category": "domain",
            "bucket": "reputation",
            "impact": 12,
            "confidence": 0.55,
            "description": "Nameserver suggests domain parking, and no MX records were found.",
            "evidence": {"ns_keyword": ns_hit, "NS": ns[:3], "has_mx": bool(ov.get("has_mx"))},
        }

    return {
        "name": "Parked Domain Suspected",
        "category": "domain",
        "bucket": "reputation",
        "impact": 0,
        "confidence": 0.35,
        "description": "No strong parked-domain indicators found.",
        "evidence": {"NS": ns[:3], "has_mx": bool(ov.get("has_mx"))},
    }


def idn_punycode_signal(domain: str) -> Optional[Dict[str, Any]]:
    sld = _sld(domain)
    # Punycode domains are sometimes used for IDN/homoglyph attacks.
    if sld.startswith("xn--"):
        return {
            "name": "IDN/Punycode",
            "category": "domain",
            "bucket": "structure",
            "impact": 15,
            "confidence": 0.6,
            "description": "Domain uses punycode (can be normal, but also used in lookalike attacks).",
            "evidence": {"sld": sld},
        }
    return None


# Common homoglyph mapping for visual similarity checks
HOMOGLYPH_MAP = {
    'l': 'i', '1': 'i', '|': 'i', 'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ı': 'i',
    '0': 'o', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o', 'ø': 'o',
    'vv': 'w', 'rn': 'm',
    'a': 'a', 'à': 'a', 'á': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a', 'å': 'a', 'ɑ': 'a',
    'e': 'e', 'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e', 'е': 'e',
    'i': 'i', 'ï': 'i', 'í': 'i', 'ì': 'i', 'î': 'i', 'ɩ': 'i',
    's': 's', 'ś': 's', 'š': 's', 'ş': 's', 'ѕ': 's',
}

def _homoglyph_skeleton(text: str) -> str:
    """Normalize text to a 'skeleton' form to detect visual lookalikes."""
    t = text.lower()
    # Handle complex multi-char homoglyphs first
    t = t.replace('vv', 'w').replace('rn', 'm')
    
    skeleton = []
    for char in t:
        # Check map, otherwise keep char
        skeleton.append(HOMOGLYPH_MAP.get(char, char))
    
    return "".join(skeleton)


def homoglyph_attack_signal(domain: str) -> Optional[Dict[str, Any]]:
    sld = _sld(domain)
    if not sld or len(sld) < 4:
        return None

    # Don't flag domains that are already in our reputable list
    normalized_domain = domain.lower().strip(".")
    if normalized_domain.startswith("www."):
        normalized_domain = normalized_domain[4:]
    if normalized_domain in TOP_TIER_DOMAINS or reputation_service.is_reputable(domain):
        return None

    skeleton = _homoglyph_skeleton(sld)
    
    # Check if the skeleton matches a known high-value brand
    for brand in BRANDS:
        brand_skeleton = _homoglyph_skeleton(brand)
        if skeleton == brand_skeleton and sld != brand:
            return {
                "name": "Homoglyph Lookalike Detected",
                "category": "domain",
                "bucket": "structure",
                "impact": 35, # High risk impact
                "confidence": 0.85,
                "description": f"Domain '{sld}' is visually similar to the protected brand '{brand}' using homoglyph characters.",
                "evidence": {"sld": sld, "lookalike_of": brand, "skeleton": skeleton},
            }

    return None


# Keyboard adjacency map for QWERTY layout
KEYBOARD_ADJACENCY = {
    'q': 'wa', 'w': 'qes', 'e': 'wrsd', 'r': 'etdf', 't': 'ryfg', 'y': 'tugh', 'u': 'yijh', 'i': 'uokj', 'o': 'ilpk', 'p': 'ol',
    'a': 'qwsz', 's': 'wedaxz', 'd': 'erfsxc', 'f': 'rtgvcd', 'g': 'tyhbvf', 'h': 'yujnbg', 'j': 'uikmnh', 'k': 'iolmj', 'l': 'kop',
    'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
}

def _is_keyboard_neighbor(char1: str, char2: str) -> bool:
    if char1 == char2: return True
    return char2 in KEYBOARD_ADJACENCY.get(char1, "")


def _identify_typo_type(typo: str, brand: str) -> Optional[str]:
    """Categorize the type of typosquatting attack."""
    if typo == brand: return None
    
    # 1. Omission (gogle)
    for i in range(len(brand)):
        if brand[:i] + brand[i+1:] == typo:
            return "omission"
            
    # 2. Repetition (gooogle)
    for i in range(len(typo)):
        if typo[:i] + typo[i+1:] == brand and typo[i] == typo[i-1 if i > 0 else 0]:
            return "repetition"
            
    # 3. Transposition (goolge)
    for i in range(len(brand) - 1):
        swapped = list(brand)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        if "".join(swapped) == typo:
            return "transposition"
            
    # 4. Keyboard Neighbor (goofle)
    if len(typo) == len(brand):
        diff_count = 0
        is_neighbor = False
        for c1, c2 in zip(typo, brand):
            if c1 != c2:
                diff_count += 1
                if _is_keyboard_neighbor(c1, c2):
                    is_neighbor = True
        if diff_count == 1 and is_neighbor:
            return "keyboard_neighbor"
            
    return "bit_flip" if _edit_distance(typo, brand) == 1 else None


def typosquatting_signal(domain: str) -> Optional[Dict[str, Any]]:
    sld = _sld(domain)
    if not sld or len(sld) < 4:
        return None

    # Skip reputable
    normalized_domain = domain.lower().strip(".")
    if normalized_domain.startswith("www."):
        normalized_domain = normalized_domain[4:]
    if normalized_domain in TOP_TIER_DOMAINS or reputation_service.is_reputable(domain):
        return None

    for brand in BRANDS:
        typo_type = _identify_typo_type(sld, brand)
        
        if typo_type:
            impact = 32 if typo_type in ["omission", "transposition", "keyboard_neighbor"] else 25
            return {
                "name": "Typosquatting Suspected",
                "category": "domain",
                "bucket": "structure",
                "impact": impact,
                "confidence": 0.8,
                "description": f"Domain '{sld}' appears to be a '{typo_type}' typo of the protected brand '{brand}'.",
                "evidence": {"sld": sld, "brand": brand, "type": typo_type},
            }

    return None


def reputable_domain_signal(domain: str) -> Optional[Dict[str, Any]]:
    # 1. Check hardcoded top-tier list first (fastest)
    d = domain.lower().strip(".")
    if d.startswith("www."):
        d = d[4:]

    is_reputable = (d in TOP_TIER_DOMAINS) or reputation_service.is_reputable(domain)

    if is_reputable:
        return {
            "name": "Top-Tier Reputable Domain",
            "category": "domain",
            "bucket": "reputation",
            "impact": -65,  # Increased trust impact
            "confidence": 0.98,
            "description": f"Domain {domain} is recognized as a highly reputable global service.",
            "evidence": {"domain": d, "source": "Tranco-100K"},
        }
    return None


async def domain_signals_async(domain: str) -> List[Dict[str, Any]]:
    """Asynchronous version of domain_signals that runs I/O in parallel."""
    
    # Run DNS and WHOIS lookups in parallel
    dns_task = dns_overview_async(domain)
    whois_task = domain_age_days_async(domain)
    
    ov, days_meta = await asyncio.gather(dns_task, whois_task)
    
    signals: List[Dict[str, Any]] = []

    st = suspicious_tld_signal(domain)
    if st:
        signals.append(st)

    rt = reputable_domain_signal(domain)
    if rt:
        signals.append(rt)

    signals.append(domain_age_signal(domain, days_meta=days_meta))
    signals.append(registrar_reputation_signal(domain, days_meta=days_meta))
    signals.append(registrar_randomness_signal(domain, days_meta=days_meta))
    signals.extend(dns_validity_signals(domain, ov=ov))
    signals.append(parked_domain_signal(domain, ov=ov))

    ips = idn_punycode_signal(domain)
    if ips:
        signals.append(ips)

    ts = typosquatting_signal(domain)
    if ts:
        signals.append(ts)

    hs = homoglyph_attack_signal(domain)
    if hs:
        signals.append(hs)

    return signals


def domain_signals(domain: str) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []

    st = suspicious_tld_signal(domain)
    if st:
        signals.append(st)

    rt = reputable_domain_signal(domain)
    if rt:
        signals.append(rt)

    signals.append(domain_age_signal(domain))
    signals.append(registrar_reputation_signal(domain))
    signals.append(registrar_randomness_signal(domain))
    signals.extend(dns_validity_signals(domain))
    signals.append(parked_domain_signal(domain))

    ips = idn_punycode_signal(domain)
    if ips:
        signals.append(ips)

    ts = typosquatting_signal(domain)
    if ts:
        signals.append(ts)

    hs = homoglyph_attack_signal(domain)
    if hs:
        signals.append(hs)

    return signals
