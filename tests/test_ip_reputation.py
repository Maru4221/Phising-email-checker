import asyncio
from pathlib import Path

import pytest

from app import main as m
from app.main import analyze_bytes, ti_findings
from app.parser import origin_ip, parse_email

FIXTURE = Path(__file__).parent / "fixtures" / "advance_fee_phish.eml"


def test_extract_origin_ip_from_real_phish():
    msg = parse_email(FIXTURE.read_bytes())
    origin = origin_ip(msg)
    assert origin["ip"] == "41.175.19.6"
    assert origin["helo_ip"] == "141.98.9.34"
    assert origin["helo_mismatch"] is True


def test_analysis_includes_origin():
    report = analyze_bytes(FIXTURE.read_bytes())
    assert report["origin"]["ip"] == "41.175.19.6"

    assert any(f["title"] == "HELO identity mismatch" for f in report["findings"])


def test_findings_from_urlhaus_host_hit():
    findings = ti_findings(
        {"urlhaus_hosts": [{"source": "urlhaus", "queried": "1.2.3.4",
                            "found": True, "url_count": 3, "threat": "malware_download"}]},
        origin_ip="1.2.3.4",
    )
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert findings[0].title == "Origin IP hosts malware (URLhaus)"


@pytest.mark.parametrize("confidence,expected_sev", [
    (85, "high"), (40, "medium"), (3, "low"), (0, None),
])
def test_findings_from_abuseipdb_bands(confidence, expected_sev):
    findings = ti_findings(
        {"abuseipdb": [{"source": "abuseipdb", "queried": "1.2.3.4", "found": True,
                        "abuse_confidence_score": confidence, "total_reports": 7,
                        "country_code": "MY", "usage_type": "isp"}]},
        origin_ip="1.2.3.4",
    )
    if expected_sev is None:
        assert findings == []
    else:
        assert findings[0].severity.value == expected_sev


async def _fake_enrich_bad_ip(urls, hashes, origin_ip=None):
    return {
        "urlhaus_urls": [], "urlhaus_hashes": [], "vt_urls": [], "vt_hashes": [],
        "urlhaus_hosts": [{"source": "urlhaus", "queried": origin_ip, "found": True,
                           "url_count": 2, "threat": "malware_download", "tags": []}],
        "abuseipdb": [{"source": "abuseipdb", "queried": origin_ip, "found": True,
                       "abuse_confidence_score": 85, "total_reports": 12,
                       "country_code": "MY", "usage_type": "fixed line"}],
    }


def test_enrich_for_analysis_rescores_verdict(monkeypatch):
    monkeypatch.setattr(m.enrich, "enrich", _fake_enrich_bad_ip)

    analysis = analyze_bytes(FIXTURE.read_bytes())
    score_before = analysis["score"]["score"]

    updated = asyncio.run(m.apply_enrichment(analysis))

    assert updated["score"]["score"] > score_before
    titles = {f["title"] for f in updated["findings"]}
    assert "Origin IP hosts malware (URLhaus)" in titles
    assert "Origin IP has high abuse confidence" in titles
    assert updated["score"]["verdict"] == "Malicious"


async def _fake_enrich_clean(urls, hashes, origin_ip=None):
    return {"urlhaus_urls": [], "urlhaus_hashes": [], "vt_urls": [],
            "vt_hashes": [], "urlhaus_hosts": [], "abuseipdb": []}


def test_enrich_with_no_findings_keeps_score(monkeypatch):
    monkeypatch.setattr(m.enrich, "enrich", _fake_enrich_clean)
    analysis = analyze_bytes(FIXTURE.read_bytes())
    updated = asyncio.run(m.apply_enrichment(analysis))
    assert updated["score"] == analysis["score"]
