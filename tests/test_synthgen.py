import pytest

from app.synthgen import (
    LEGIT_ARCHETYPES, PHISH_ARCHETYPES, generate_legit, generate_phish,
)
from app.main import analyze_bytes


def _real_emails(items):
    return [x for x in items if "junk" not in x["name"]]


def test_generation_is_deterministic():
    a = generate_phish(50)
    b = generate_phish(50)
    assert [x["bytes"] for x in a] == [x["bytes"] for x in b]


def test_archetype_round_robin_coverage():
    phish = generate_phish(24)
    names = {x["name"].split("_")[1] for x in phish}
    assert len(PHISH_ARCHETYPES) == 12
    assert len(names) == 12

    legit = generate_legit(24)
    lnames = {x["name"].split("_")[1] for x in legit}
    assert len(LEGIT_ARCHETYPES) == 12
    assert len(lnames) == 12


def test_generated_phish_all_parse_and_score():
    for item in _real_emails(generate_phish(24)):
        r = analyze_bytes(item["bytes"])
        assert r["score"]["verdict"] in {"Benign", "Suspicious", "Malicious"}
        assert isinstance(r["score"]["score"], int)


def test_generated_legit_all_parse():
    for item in _real_emails(generate_legit(24)):
        r = analyze_bytes(item["bytes"])
        assert r["score"]["verdict"] in {"Benign", "Suspicious", "Malicious"}


def test_binary_junk_is_rejected_not_scored():
    from app.synthgen import generate_junk
    junk = generate_junk(4)
    assert len(junk) == 4
    for item in junk:
        with pytest.raises(ValueError, match="no email headers"):
            analyze_bytes(item["bytes"])


def test_phish_pool_contains_no_junk():
    for item in generate_phish(200):
        assert "junk" not in item["name"]
        assert b"From:" in item["bytes"] and b"Subject:" in item["bytes"]


def test_no_real_registrable_domains_in_phish_bodies():
    allowed = (".example", "example.com", "example.net", "example.org",
               "digi.com.my", "outlook.com.my", "myself.com",
               "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",


               "contoso-corp.com", "northwind-ltd.co.uk", "adventure-works.io")
    for item in _real_emails(generate_phish(60)):
        text = item["bytes"].decode("latin-1", errors="ignore").lower()
        import re
        domains = set(re.findall(r"@([a-z0-9.-]+)", text))
        bad = {d for d in domains
               if not any(d == a.strip(".") or d.endswith(a) or d.endswith(".example")
                          or d in ("digi.com.my", "outlook.com.my", "myself.com")
                          for a in allowed)}
        assert not bad, (item["name"], bad)
