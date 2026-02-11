from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from backend.persistence.sqlite_store import get_explain


router = APIRouter(tags=["explain"])


@router.get("/explain/{analysis_id}")
def explain(analysis_id: int) -> Dict[str, Any]:
    res = get_explain(analysis_id)
    if not res:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return res
