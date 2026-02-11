from backend.utils.validators import detect_target_type


def test_detect_ip():
    t, norm = detect_target_type("8.8.8.8")
    assert t == "ip"
    assert norm == "8.8.8.8"


def test_detect_domain():
    t, norm = detect_target_type("Example.COM")
    assert t == "domain"
    assert norm == "example.com"


def test_detect_url_scheme_less():
    t, norm = detect_target_type("example.com/path")
    assert t == "url"
    assert norm.startswith("http://")


def test_detect_url_with_scheme():
    t, norm = detect_target_type("https://example.com/path")
    assert t == "url"
    assert norm.startswith("https://")
