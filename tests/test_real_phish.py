from pathlib import Path

from app.main import analyze_bytes

FIXTURE = Path(__file__).parent / "fixtures" / "advance_fee_phish.eml"


def test_advance_fee_phish_is_malicious():
    report = analyze_bytes(FIXTURE.read_bytes())
    assert report["score"]["verdict"] == "Malicious"
    assert report["score"]["score"] >= 7

    titles = {f["title"] for f in report["findings"]}

    assert "Advance-fee scam phrases" in titles
    assert "Requests personal information" in titles
    assert "Reply-To mismatch" in titles
    assert "SPF results conflict" in titles


def test_advance_fee_phish_detects_content_and_money_lure():
    report = analyze_bytes(FIXTURE.read_bytes())
    titles = {f["title"] for f in report["findings"]}
    assert "Large money amounts offered" in titles
    assert "Urgency pressure language" in titles


def test_legitimate_email_stays_benign():
    raw = (
        "From: GitHub <noreply@github.com>\r\n"
        "To: user@example.com\r\n"
        "Subject: Your weekly digest\r\n"
        "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Here is your weekly summary of activity. 3 pull requests merged, "
        "12 issues closed. Manage your notification settings.\r\n"
    ).encode()
    report = analyze_bytes(raw)
    assert report["score"]["verdict"] == "Benign", report["score"]
