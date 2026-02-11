from __future__ import annotations

import logging
import time
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.analyzers.domain import analyze_domain_explain
from backend.analyzers.ip import analyze_ip_explain
from backend.analyzers.url import analyze_url_explain
from backend.persistence.sqlite_store import save_analysis
from backend.utils.logging_utils import log_analysis_event
from backend.utils.validators import detect_target_type


logger = logging.getLogger("security_analyzer")
router = APIRouter(tags=["analyze"])


class AnalyzeRequest(BaseModel):
    # Preferred input
    target: Optional[str] = Field(None, description="Domain, URL, or IP address")

    # Backwards/FE-compatible input
    input: Optional[str] = Field(None, description="Domain, URL, or IP address")
    type: Optional[Literal["domain", "url", "ip"]] = Field(None, description="Optional explicit type")

    verbose: bool = Field(False, description="Reserved for future debug output")


def _resolve_target(req: AnalyzeRequest) -> str:
    t = (req.target or req.input or "").strip()
    if not t:
        raise ValueError("Missing target")
    return t


@router.post("/analyze", status_code=201)
def analyze(req: AnalyzeRequest) -> Dict[str, Any]:
    start = time.perf_counter()

    try:
        target = _resolve_target(req)

        # Compute analysis (public result) and explain blob (for persistence).
        if req.type == "url":
            result, explain = analyze_url_explain(target)
        elif req.type == "ip":
            result, explain = analyze_ip_explain(target)
        elif req.type == "domain":
            result, explain = analyze_domain_explain(target)
        else:
            detected, normalized = detect_target_type(target)
            if detected == "url":
                result, explain = analyze_url_explain(target)
            elif detected == "ip":
                result, explain = analyze_ip_explain(normalized)
            else:
                result, explain = analyze_domain_explain(normalized)

        analysis_id = None
        persistence_ok = False
        try:
            analysis_id = save_analysis(result=result, explain=explain)
            persistence_ok = True
        except Exception:
            # Best-effort persistence: never fail the request if SQLite is unavailable.
            persistence_ok = False

        latency_ms = int((time.perf_counter() - start) * 1000)
        log_analysis_event(
            logger,
            analysis_id=analysis_id,
            target=str(result.get("target", target)),
            target_type=str(result.get("type", "")),
            verdict=str(result.get("verdict", "")),
            risk_score=int(result.get("risk_score", 0)),
            confidence=float(result.get("confidence", 0.0)),
            latency_ms=latency_ms,
            persistence_ok=persistence_ok,
        )

        return result

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")
