from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


def _default_db_path() -> Path:
    # backend/persistence/sqlite_store.py -> backend/data/analyzer.sqlite3
    backend_dir = Path(__file__).resolve().parents[1]
    return backend_dir / "data" / "analyzer.sqlite3"


def get_db_path() -> Path:
    p = os.environ.get("SECURITY_ANALYZER_DB_PATH")
    return Path(p) if p else _default_db_path()


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Use a longer timeout and check_same_thread=False for FastAPI concurrency.
    conn = sqlite3.connect(str(db_path), timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Performance and Reliability tuning:
    # 1. Enable WAL mode (Write-Ahead Logging) for better concurrency.
    # 2. Set synchronous to NORMAL for a massive speed boost without sacrificing safety.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with _connect() as conn:
        # Tables are created within an implicit transaction.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              target TEXT NOT NULL,
              type TEXT NOT NULL,
              risk_score INTEGER NOT NULL,
              verdict TEXT NOT NULL,
              confidence REAL NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_explain (
              analysis_id INTEGER PRIMARY KEY,
              explain_json TEXT NOT NULL,
              FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
            )
            """
        )
        # Create an index on target for faster future lookups/history search
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_target ON analyses(target)")
        conn.commit()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_analysis(result: Dict[str, Any], explain: Dict[str, Any]) -> int:
    """Persist one analysis atomically.

    The public /api/analyze response is not modified, but we store additional explain data.
    """

    created_at = _utc_now_iso()

    with _connect() as conn:
        try:
            # Start an explicit transaction for atomicity
            conn.execute("BEGIN TRANSACTION")
            
            cur = conn.execute(
                """
                INSERT INTO analyses (target, type, risk_score, verdict, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(result.get("target")),
                    str(result.get("type")),
                    int(result.get("risk_score", 0)),
                    str(result.get("verdict")),
                    float(result.get("confidence", 0.0)),
                    created_at,
                ),
            )
            analysis_id = int(cur.lastrowid)

            conn.execute(
                """
                INSERT INTO analysis_explain (analysis_id, explain_json)
                VALUES (?, ?)
                """,
                (analysis_id, json.dumps(explain, default=str)),
            )

            conn.execute("COMMIT")
            return analysis_id
        except Exception as e:
            conn.execute("ROLLBACK")
            logger.error(f"Atomic save_analysis failed, transaction rolled back: {e}")
            raise e


def list_history(limit: int = 100) -> List[Dict[str, Any]]:
    limit = max(1, min(500, int(limit)))

    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT a.id, a.target, a.type, a.risk_score, a.verdict, a.confidence, a.created_at, e.explain_json
            FROM analyses a
            LEFT JOIN analysis_explain e ON e.analysis_id = a.id
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    items: List[Dict[str, Any]] = []
    for r in rows:
        explain: Dict[str, Any] = {}
        try:
            if r["explain_json"]:
                explain = json.loads(r["explain_json"])
        except Exception:
            explain = {}

        # Keep the original analysis response shape, with additive metadata.
        item: Dict[str, Any] = {
            "id": int(r["id"]),
            "timestamp": r["created_at"],
            "target": r["target"],
            "type": r["type"],
            "risk_score": int(r["risk_score"]),
            "confidence": float(r["confidence"]),
            "verdict": r["verdict"],
            "signals": explain.get("signals", []),
            "breakdown": explain.get("breakdown", {"reputation": 0, "structure": 0, "network": 0}),
        }
        items.append(item)

    return items


def clear_history() -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM analysis_explain")
        conn.execute("DELETE FROM analyses")
        conn.commit()


def get_explain(analysis_id: int) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        r = conn.execute(
            """
            SELECT a.id, a.target, a.type, a.risk_score, a.verdict, a.confidence, a.created_at, e.explain_json
            FROM analyses a
            LEFT JOIN analysis_explain e ON e.analysis_id = a.id
            WHERE a.id = ?
            """,
            (int(analysis_id),),
        ).fetchone()

    if not r:
        return None

    explain: Dict[str, Any] = {}
    try:
        if r["explain_json"]:
            explain = json.loads(r["explain_json"])
    except Exception:
        explain = {}

    return {
        "id": int(r["id"]),
        "timestamp": r["created_at"],
        "target": r["target"],
        "type": r["type"],
        "risk_score": int(r["risk_score"]),
        "confidence": float(r["confidence"]),
        "verdict": r["verdict"],
        "signals": explain.get("signals", []),
        "breakdown": explain.get("breakdown", {"reputation": 0, "structure": 0, "network": 0}),
        "scoring": explain.get("scoring", {}),
    }
