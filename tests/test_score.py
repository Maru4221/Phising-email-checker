from app.score import Finding, Severity, Verdict, compute_score


def test_no_findings_is_benign():
    result = compute_score([])
    assert result.verdict == Verdict.BENIGN
    assert result.score == 0


def test_weights_sum():
    findings = [
        Finding(Severity.LOW, "a", "a", "headers"),
        Finding(Severity.MEDIUM, "b", "b", "iocs"),
        Finding(Severity.HIGH, "c", "c", "body"),
    ]
    result = compute_score(findings)
    assert result.score == 1 + 2 + 4
    assert result.verdict == Verdict.MALICIOUS


def test_malicious_threshold():
    findings = [
        Finding(Severity.HIGH, "a", "a", "headers"),
        Finding(Severity.HIGH, "b", "b", "headers"),
    ]
    result = compute_score(findings)
    assert result.score == 8
    assert result.verdict == Verdict.MALICIOUS


def test_info_findings_keep_benign():
    findings = [Finding(Severity.INFO, "ctx", "ctx", "headers")]
    assert compute_score(findings).verdict == Verdict.BENIGN
