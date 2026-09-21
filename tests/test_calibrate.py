from pathlib import Path

import pytest

from app.calibrate import collect_samples, compute_metrics, evaluate_file
from app.score import Verdict


def _touch(root: Path, rel: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"From: a@b.c\r\nSubject: t\r\n\r\nbody")
    return p


def test_collect_samples_subfolders(tmp_path: Path):
    _touch(tmp_path, "phish/a.eml")
    _touch(tmp_path, "legit/b.eml")
    samples = collect_samples(tmp_path)
    labels = {p.name: label for p, label in samples}
    assert labels == {"a.eml": "phish", "b.eml": "legit"}


def test_collect_samples_prefixes(tmp_path: Path):
    _touch(tmp_path, "phish_x.eml")
    _touch(tmp_path, "legit_y.eml")
    _touch(tmp_path, "unlabeled.eml")
    labels = {p.name: label for p, label in collect_samples(tmp_path)}
    assert labels == {"phish_x.eml": "phish", "legit_y.eml": "legit"}


def test_collect_samples_missing_dir(tmp_path: Path):
    assert collect_samples(tmp_path / "nope") == []


def _write_sample(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name

    p.write_bytes(content.encode("utf-8"))
    return p


CLEAR_PHISH = (
    'From: "PayPal Security" <no-reply@paypa1-verify.com>\r\n'
    "To: v@example.com\r\nSubject: account locked\r\n"
    "Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail\r\n"
    "Reply-To: collect@gmail.com\r\n"
    'Content-Type: text/html; charset="utf-8"\r\n\r\n'
    "<html><body><a href=\"http://evil.example/login\">https://paypal.com</a>"
    "<form action=\"http://evil.example/s\"><input type=\"password\" name=\"pw\"></form></body></html>\r\n"
)

CLEAN_LEGIT = (
    "From: Anna <anna@example.com>\r\nTo: bob@example.com\r\nSubject: hi\r\n"
    "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\n"
    'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
    "Lunch tomorrow?\r\n"
)


def test_evaluate_clear_phish_is_tp(tmp_path: Path):
    p = _write_sample(tmp_path, "p.eml", CLEAR_PHISH)
    r = evaluate_file(p, "phish")
    assert r["outcome"] == "TP"
    assert r["verdict"] in {"Suspicious", "Malicious"}


def test_evaluate_clean_legit_is_tn(tmp_path: Path):
    p = _write_sample(tmp_path, "l.eml", CLEAN_LEGIT)
    r = evaluate_file(p, "legit")
    assert r["outcome"] == "TN"
    assert r["verdict"] == "Benign"


def test_evaluate_headerless_garbage_is_flagged(tmp_path: Path):
    for name, content in (("bad.eml", "this is not an email at all"),
                          ("bin.eml", "\x00\x01\x02binary\x03")):
        p = _write_sample(tmp_path, name, content)
        r = evaluate_file(p, "phish")
        assert r["outcome"] == "error", (name, r)


def test_evaluate_custom_thresholds(tmp_path: Path):
    p = _write_sample(tmp_path, "p.eml", CLEAR_PHISH)
    default = evaluate_file(p, "phish")
    strict = evaluate_file(p, "phish", suspicious_min=50, malicious_min=60)
    assert strict["verdict"] == "Benign"
    assert strict["outcome"] == "FN"
    assert default["outcome"] == "TP"


def test_metrics_perfect():
    m = compute_metrics([
        {"outcome": "TP"}, {"outcome": "TP"},
        {"outcome": "TN"}, {"outcome": "TN"}, {"outcome": "TN"},
    ])
    assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["accuracy"] == 1.0


def test_metrics_with_errors():
    m = compute_metrics([{"outcome": "TP"}, {"outcome": "FN"}, {"outcome": "error"}])
    assert m["tp"] == 1 and m["fn"] == 1 and m["errors"] == 1
    assert m["recall"] == 0.5


def test_metrics_empty():
    m = compute_metrics([])
    assert m["accuracy"] == 0.0 and m["f1"] == 0.0


SEED_PHISH = (
    'From: "Microsoft 365" <security@rnicrosoft-verify.com>\r\n'
    "To: victim@example.com\r\nSubject: Action required: unusual sign-in\r\n"
    "Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail\r\n"
    "Reply-To: helpdesk.rnicrosoft@gmail.com\r\n"
    'Content-Type: text/html; charset="utf-8"\r\n\r\n'
    '<html><body><p>We detected an unusual sign-in. Your account will be '
    'suspended unless you confirm your identity.</p>'
    '<a href="http://rnicrosoft-verify.com/login?id=8842">'
    'https://login.microsoftonline.com</a></body></html>\r\n'
)

SEED_LOTTERY = (
    'From: "Lucky Draw Committee" <claims@intl-lottery-center.com>\r\n'
    "To: victim@example.com\r\n"
    "Subject: Congratulations - your email was selected\r\n"
    "Authentication-Results: mail.example.com; spf=softfail; dkim=none; dmarc=none\r\n"
    "Reply-To: agent.wilson@yahoo.com\r\n"
    'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
    "Dear lucky winner,\r\n\r\nYou have won the sum of 2.5 million GBP in the "
    "international lottery draw held this quarter. To claim your fund, provide "
    "your details within 48 hours:\r\n\r\nFULL NAME:\r\nHOME ADDRESS:\r\n"
    "TELEPHONE#:\r\nOCCUPATION:\r\n\r\nYours faithfully,\r\nClaims Agent\r\n"
)

SEED_LEGIT_GITHUB = (
    "From: GitHub <noreply@github.com>\r\n"
    "To: developer@example.com\r\nSubject: [repo] PR #42 approved\r\n"
    "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\n"
    'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
    "Your pull request was approved and merged into main.\r\n"
)

SEED_LEGIT_LUNCH = (
    "From: Anna <anna@example.com>\r\nTo: bob@example.com\r\n"
    "Subject: Lunch on Friday\r\n"
    "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\n"
    'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
    "Lunch at noon on Friday as usual?\r\n"
)


@pytest.mark.parametrize("raw,label,outcome", [
    (SEED_PHISH, "phish", "TP"),
    (SEED_LOTTERY, "phish", "TP"),
    (SEED_LEGIT_GITHUB, "legit", "TN"),
    (SEED_LEGIT_LUNCH, "legit", "TN"),
])
def test_seed_samples_are_classified_correctly(raw, label, outcome, tmp_path: Path):
    r = evaluate_file(_write_sample(tmp_path, "s.eml", raw), label)
    assert r["outcome"] == outcome, (r.get("verdict"), r.get("score"), r.get("findings"))
