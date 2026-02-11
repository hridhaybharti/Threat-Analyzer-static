import json

from backend.core.scorer import score_signals_detailed
from backend.core.weights import load_weights


def test_score_ranges():
    signals = [
        {
            "name": "A",
            "category": "url",
            "bucket": "structure",
            "impact": 40,
            "confidence": 0.8,
            "description": "x",
            "evidence": {"k": "v"},
        }
    ]

    risk, conf, breakdown, math = score_signals_detailed(signals)
    assert 0 <= risk <= 100
    assert 0.0 <= conf <= 1.0
    assert set(breakdown.keys()) == {"reputation", "structure", "network"}
    assert "signals" in math


def test_contradiction_lowers_confidence():
    signals = [
        {"name": "Risk", "category": "url", "bucket": "structure", "impact": 30, "confidence": 0.9, "description": "x", "evidence": {"a": 1}},
        {"name": "Trust", "category": "url", "bucket": "structure", "impact": -30, "confidence": 0.9, "description": "x", "evidence": {"b": 1}},
    ]

    _, conf, _, math = score_signals_detailed(signals)
    assert math["contradiction"] > 0
    assert conf < 0.8


def test_weights_file_loads():
    w = load_weights()
    # We keep defaults at 1.0, but the file should load and include a path.
    assert w.get("default_weight") == 1.0
    assert "by_signal" in w
