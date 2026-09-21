from app.parser import analyze_email, auth_results, parse_email


def make_email(*, from_hdr='From: "Chase Bank" <security@chase-secure-login.com>',
               to="To: victim@example.com",
               subject="Subject: Urgent: verify your account",
               reply_to=None,
               auth_results="Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail",
               body="Click hxxp://phish.example/login now or call 203.0.113.5 support.",
               extra=""):
    lines = [from_hdr, to, subject]
    if reply_to:
        lines.append(reply_to)
    if auth_results:
        lines.append(auth_results)
    lines.append('Content-Type: text/plain; charset="utf-8"')
    lines.append("")
    lines.append(body)
    if extra:
        lines.append(extra)
    return "\r\n".join(lines).encode()


def test_auth_results_extraction():
    msg = parse_email(make_email())
    auth = auth_results(msg)
    assert auth == {"spf": "fail", "dkim": "none", "dmarc": "fail"}


def test_auth_results_missing():
    msg = parse_email(make_email(auth_results=None))
    auth = auth_results(msg)
    assert auth == {"spf": None, "dkim": None, "dmarc": None}


def test_display_name_spoof_detected():
    report = analyze_email(make_email(), get_domains=["example.com"])
    titles = [f.title for f in report["findings"]]
    assert "Display-name spoofing" in titles


def test_reply_to_mismatch_detected():
    report = analyze_email(
        make_email(reply_to="Reply-To: collector@totally-different.net"),
        get_domains=["example.com"],
    )
    titles = [f.title for f in report["findings"]]
    assert "Reply-To mismatch" in titles


def test_lookalike_domain_detected():

    report = analyze_email(
        make_email(from_hdr='From: IT Support <it@examp1e.com>'),
        get_domains=["example.com"],
    )
    titles = [f.title for f in report["findings"]]
    assert "Lookalike sender domain" in titles


def test_attachment_risky_extension_and_hash():
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = "a@b.example"
    msg["Subject"] = "invoice"
    msg.set_content("see attached")
    msg.add_attachment(b"MZfakebinary", maintype="application", subtype="octet-stream", filename="invoice.exe")

    from email import policy
    raw = msg.as_bytes(policy=policy.SMTP)
    report = analyze_email(raw, get_domains=["example.com"])

    assert len(report["attachments"]) == 1
    att = report["attachments"][0]
    assert att["risky"] is True
    assert att["extension"] == ".exe"
    assert att["sha256"]

    titles = [f.title for f in report["findings"]]
    assert "Risky attachment type" in titles


def test_body_text_extracted_for_iocs():
    report = analyze_email(make_email(), get_domains=["example.com"])

    assert "_bodies" in report
