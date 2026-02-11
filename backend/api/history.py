from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Query

from backend.persistence.sqlite_store import clear_history as db_clear_history
from backend.persistence.sqlite_store import list_history as db_list_history


router = APIRouter(tags=["history"])


@router.get("/history")
def get_history(limit: int = Query(20, ge=1, le=100)) -> List[Dict[str, Any]]:
    # Stored in local SQLite for auditability.
    return db_list_history(limit=limit)


@router.delete("/history", status_code=204)
def clear_history() -> None:
    db_clear_history()
