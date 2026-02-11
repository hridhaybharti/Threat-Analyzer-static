import os

from backend.persistence.sqlite_store import clear_history, get_explain, init_db, list_history, save_analysis


def test_sqlite_persistence_roundtrip(tmp_path, monkeypatch):
    db_path = tmp_path / "test.sqlite3"
    monkeypatch.setenv("SECURITY_ANALYZER_DB_PATH", str(db_path))

    init_db()

    result = {
        "target": "https://example.com",
        "type": "url",
        "risk_score": 10,
        "confidence": 0.5,
        "verdict": "SAFE",
        "signals": [],
        "breakdown": {"reputation": 0, "structure": 10, "network": 0},
    }
    explain = {"signals": [], "breakdown": result["breakdown"], "scoring": {"weighted_sum": 10}}

    analysis_id = save_analysis(result=result, explain=explain)

    hist = list_history(limit=10)
    assert hist
    assert hist[0]["id"] == analysis_id

    detail = get_explain(analysis_id)
    assert detail
    assert detail["id"] == analysis_id
    assert "scoring" in detail

    clear_history()
    assert list_history(limit=10) == []
