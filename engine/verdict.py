# engine/verdict.py
"""
Verdict Calculator
Determines threat level and recommendation based on risk analysis.
"""

from typing import Literal

Verdict = Literal["TRUSTED", "LIKELY_SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL"]


import sys
import os

# Ensure project root is in path
try:
    import backend
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

"""Compatibility shim for verdict: delegate to backend implementation."""
# backend.engine doesn't exist, likely meant backend.core.verdict
try:
    from backend.core.verdict import *  # noqa: F401,F403
except ImportError:
    pass

import warnings
warnings.warn("Importing engine.verdict is deprecated; use backend.core.verdict", DeprecationWarning)

__all__ = [name for name in globals().keys() if not name.startswith("_")]


def get_verdict_recommendation(verdict: Verdict) -> str:
    """
    Get user-friendly recommendation for verdict.
    """
    recommendations = {
        "TRUSTED": "This appears to be safe. You can proceed with confidence.",
        "LIKELY_SAFE": "This appears mostly safe but has minor concerns. Exercise caution.",
        "SUSPICIOUS": "This shows multiple warning signs. Proceed with extreme caution.",
        "MALICIOUS": "This is likely malicious. Avoid clicking or interacting.",
        "CRITICAL": "This is highly likely to be dangerous. Do not interact with this link."
    }
    return recommendations.get(verdict, "Unknown verdict")


def get_verdict_color(verdict: Verdict) -> str:
    """
    Get color indicator for verdict for UI display.
    """
    colors = {
        "TRUSTED": "green",
        "LIKELY_SAFE": "blue",
        "SUSPICIOUS": "orange",
        "MALICIOUS": "red",
        "CRITICAL": "darkred"
    }
    return colors.get(verdict, "gray")
