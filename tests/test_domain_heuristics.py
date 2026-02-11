from backend.heuristics.domain_heuristics import domain_signals


def test_domain_signals_are_stable(monkeypatch):
    # Avoid network calls.
    monkeypatch.setattr(
        "backend.utils.whois_utils.domain_age_days",
        lambda domain: (10, {"ok": True, "registrar": "Example Registrar", "creation_date": None}),
    )
    monkeypatch.setattr(
        "backend.utils.dns_utils.dns_overview",
        lambda domain: {"A": ["1.2.3.4"], "AAAA": [], "NS": ["ns1.example.net"], "MX": [], "has_a_or_aaaa": True, "has_ns": True, "has_mx": False},
    )

    sigs = domain_signals("example.com")
    assert isinstance(sigs, list)
    assert all("name" in s and "impact" in s and "description" in s for s in sigs)


def test_domain_age_bucket_present(monkeypatch):
    monkeypatch.setattr(
        "backend.utils.whois_utils.domain_age_days",
        lambda domain: (20, {"ok": True, "registrar": "Example Registrar", "creation_date": None}),
    )
    monkeypatch.setattr(
        "backend.utils.dns_utils.dns_overview",
        lambda domain: {"A": [], "AAAA": [], "NS": [], "MX": [], "has_a_or_aaaa": False, "has_ns": False, "has_mx": False},
    )

    sigs = domain_signals("example.com")
    age = next(s for s in sigs if s["name"] == "Domain Age")
    assert "age_bucket" in age.get("evidence", {})
