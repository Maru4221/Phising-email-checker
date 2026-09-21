from pathlib import Path

from fastapi.testclient import TestClient

from app.main import ANALYSIS_STORE, app

client = TestClient(app)

FIXTURE = Path(__file__).parent / "fixtures" / "advance_fee_phish.eml"

GOOD = (
    "From: GitHub <noreply@github.com>\r\n"
    "To: user@example.com\r\n"
    "Subject: Weekly digest\r\n"
    "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Here is your weekly summary.\r\n"
).encode()


def _bulk(files):
    return client.post(
        "/api/bulk",
        files=[("files", (name, content, "message/rfc822")) for name, content in files],
    )


def test_bulk_returns_rows_with_verdicts():
    resp = _bulk([("phish.eml", FIXTURE.read_bytes()), ("ok.eml", GOOD)])
    assert resp.status_code == 200
    rows = resp.json()["rows"]
    assert len(rows) == 2

    by_name = {r["name"]: r for r in rows}
    assert by_name["phish.eml"]["verdict"] == "Malicious"
    assert by_name["phish.eml"]["origin_ip"] == "41.175.19.6"
    assert by_name["ok.eml"]["verdict"] == "Benign"
    assert all(r["id"] for r in rows)


def test_bulk_handles_bad_and_empty_files():
    resp = _bulk([("garbage.eml", b"\x00\x01not an email at all"),
                  ("empty.eml", b"")])
    assert resp.status_code == 200
    rows = resp.json()["rows"]
    assert rows[0]["name"] == "empty.eml" or rows[1]["name"] == "empty.eml"
    assert any(r.get("error") for r in rows)

    assert all(not r["id"] for r in rows if r.get("error"))


def test_bulk_empty_request_rejected():
    resp = client.post("/api/bulk")
    assert resp.status_code == 400


def test_drill_down_returns_full_analysis():
    resp = _bulk([("phish.eml", FIXTURE.read_bytes())])
    aid = resp.json()["rows"][0]["id"]

    got = client.get(f"/api/analysis/{aid}")
    assert got.status_code == 200
    analysis = got.json()
    assert analysis["headers"]["subject"] == "Your compensation money approved."
    assert analysis["origin"]["ip"] == "41.175.19.6"


def test_drill_down_report_is_markdown():
    resp = _bulk([("phish.eml", FIXTURE.read_bytes())])
    aid = resp.json()["rows"][0]["id"]

    got = client.get(f"/api/analysis/{aid}/report")
    assert got.status_code == 200
    md = got.json()["markdown"]
    assert "# Phishing Triage Report" in md
    assert "not enriched yet" in md


def test_drill_down_unknown_id_404():
    assert client.get("/api/analysis/does-not-exist").status_code == 404


def test_store_is_bounded():
    from app.main import _store_put

    for i in range(250):
        _store_put({"headers": {"message_id": f"m{i:03d}@x"}, "score": {"verdict": "Benign", "score": 0}})
    assert len(ANALYSIS_STORE) <= 210
