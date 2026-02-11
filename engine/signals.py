"""Compatibility shim for legacy signal imports.

This module maps legacy signal functions to the new implementation in `backend.heuristics`.
"""

import sys
import os
from typing import Any, Dict, List

# Ensure project root is in path BEFORE any backend imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Now import from backend (path is already set up)
from backend.heuristics.domain_heuristics import (
    domain_age_signal as _new_domain_age,
    registrar_reputation_signal,
    suspicious_tld_signal
)
from backend.heuristics.url_heuristics import (
    homograph_signal,
    shortener_signal,
    length_entropy_signal
)

# Re-export or map legacy functions

def domain_reputation_signal(domain: str) -> List[Dict[str, Any]]:
    """Legacy wrapper for domain reputation."""
    # Map to registrar reputation and TLD checks as a proxy
    signals = []
    
    tld_sig = suspicious_tld_signal(domain)
    if tld_sig:
        signals.append(tld_sig)
        
    reg_sig = registrar_reputation_signal(domain)
    if reg_sig:
        signals.append(reg_sig)
        
    return signals

def domain_age_signal(domain: str) -> List[Dict[str, Any]]:
    """Legacy wrapper for domain age."""
    # New implementation returns a single Dict, old returned List[Dict]
    sig = _new_domain_age(domain)
    return [sig] if sig else []

def url_structure_signal(url: str) -> List[Dict[str, Any]]:
    """Legacy wrapper for URL structure."""
    # Map to length/entropy signals
    sig = length_entropy_signal(url)
    return [sig] if sig else []

def obfuscation_signal(url: str) -> List[Dict[str, Any]]:
    """Legacy wrapper for obfuscation detection."""
    signals = []
    
    # Check for homographs/IDN
    homo = homograph_signal(url)
    if homo and homo.get("impact", 0) > 0:
        signals.append(homo)
        
    # Check for shorteners (often used to obfuscate)
    short = shortener_signal(url)
    if short and short.get("impact", 0) > 0:
        signals.append(short)
        
    return signals

# Warnings for deprecation
import warnings
warnings.warn("Importing from engine.signals is deprecated; use backend.heuristics.*", DeprecationWarning)
