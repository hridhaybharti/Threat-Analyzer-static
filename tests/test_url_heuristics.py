from backend.heuristics.url_heuristics import url_signals


def test_shortener_detection():
    sigs = url_signals("https://bit.ly/abc")
    s = next(x for x in sigs if x["name"] == "URL Shortener Detected")
    assert s["impact"] > 0


def test_homograph_punycode_indicator():
    sigs = url_signals("https://xn--pple-43d.com/login")
    s = next(x for x in sigs if x["name"] == "Homograph/IDN Indicator")
    assert s["impact"] > 0


def test_entropy_signal_present():
    sigs = url_signals("https://example.com/path?token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    s = next(x for x in sigs if x["name"] == "Path/Query Entropy")
    assert "query_entropy" in s.get("evidence", {})
