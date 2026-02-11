"""Compatibility shim for older imports.

This module re-exports the production `backend.analyzers.url` implementation
to maintain backward compatibility with legacy scripts.
"""

import sys
import os
from typing import Any, Dict, List, Optional

# Ensure project root is in path BEFORE any backend imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Now import from backend (path is already set up)
from backend.analyzers.url import analyze_url as _new_analyze_url
from backend.analyzers.url import analyze_url_explain as _new_analyze_url_explain

# Re-export useful types if they were previously available
# (Adjust based on what was originally here if known, but for now purely functional)

def analyze_url(url: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Analyze a URL for security threats using the new backend engine.
    
    Args:
        url: The URL to analyze
        verbose: If True, include detailed analysis info (explanation)
        
    Returns:
        Dictionary containing risk assessment and signals
    """
    if verbose:
        # The new engine returns (result, explain) tuple when asking for explanation
        # We need to merge them to match the old 'verbose' behavior which likely returned one big dict
        result, explain = _new_analyze_url_explain(url)
        
        # Merge explain into result for legacy consumers expecting a single dict
        # We'll add the explanation fields under keys that might be expected
        full_result = result.copy()
        full_result["analysis_details"] = explain
        full_result["signal_summary"] = explain.get("breakdown", {})
        
        # If the old format had 'signals' at the top level, ensure they are there
        if "signals" not in full_result and "signals" in explain:
            full_result["signals"] = explain["signals"]
            
        return full_result
    else:
        # strict return of the result dict
        return _new_analyze_url(url)

# Alias for backward compatibility if needed
analyze_domain = analyze_url
