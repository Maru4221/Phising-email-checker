from __future__ import annotations

import re
from typing import List

from .score import Finding, Severity

ADVANCE_FEE_PHRASES = [
    "dear beneficiary",
    "dear lucky winner",
    "dear winner",
    "compensation fund",
    "compensation funds",
    "compensation money",
    "unclaimed fund",
    "unclaimed inheritance",
    "inheritance fund",
    "next of kin",
    "lottery winning",
    "you have won",
    "lucky winner",
    "atm card",
    "master card loaded",
    "debit card loaded",
    "diplomat carrying",
    "diplomatic courier",
    "courier company",
    "delivery of your fund",
    "your fund is ready",
    "special envoy",
    "un & au",
    "united nations compensation",
    "payment of your inheritance",
    "moving to the treasury",
    "legalize your documents",
    "transfer the fund",
    "claims agent",
    "claim your fund",
    "beneficiary of the sum",
]

PII_LABELS = [
    "full name",
    "telephone",
    "phone number",
    "home address",
    "mailing address",
    "residential address",
    "date of birth",
    "occupation",
    "marital status",
    "bank account",
    "banking details",
    "social security",
    "passport number",
    "national id",
    "mothers maiden name",
]

URGENCY_PHRASES = [
    "last time",
    "final notice",
    "final warning",
    "act now",
    "respond immediately",
    "immediate response",
    "within 24 hours",
    "within 48 hours",
    "urgent reply",
    "as soon as possible",
    "before it is too late",
    "several attempts",
    "expires today",
    "account will be closed",
    "account will be suspended",
]

MONEY_RE = re.compile(
    r"\b\d{1,3}(?:[.,]\d{1,3})?\s*(?:million|billion|mn)\b"
    r"|\b(?:usd|eur|gbp)\s*\d{4,}"
    r"|\$\s?\d{1,3}(?:[,.]\d{3})+"
    r"|\b\d{4,}\s*(?:usd|dollars|euros|pounds)\b",
    re.IGNORECASE,
)

def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower())

def body_checks(text: str) -> List[Finding]:
    findings: List[Finding] = []
    body = _norm(text)
    if not body:
        return findings

    hits = [p for p in ADVANCE_FEE_PHRASES if p in body]
    if hits:
        findings.append(Finding(
            Severity.MEDIUM,
            "Advance-fee scam phrases",
            f"{len(hits)} scam phrase(s) in body: {', '.join(chr(34) + h + chr(34) for h in hits[:5])}",
            "body",
        ))

    pii_hits = [p for p in PII_LABELS if p in body]
    if len(pii_hits) >= 3:
        findings.append(Finding(
            Severity.MEDIUM,
            "Requests personal information",
            f"Body asks for {len(pii_hits)} personal detail(s): "
            + ", ".join(sorted(pii_hits)[:6]),
            "body",
        ))

    amounts = MONEY_RE.findall(text or "")
    if amounts:
        findings.append(Finding(
            Severity.MEDIUM,
            "Large money amounts offered",
            f"Body mentions money amount(s): {', '.join(a.strip() for a in amounts[:3])}",
            "body",
        ))

    urgency_hits = [p for p in URGENCY_PHRASES if p in body]
    if len(urgency_hits) >= 2:
        findings.append(Finding(
            Severity.MEDIUM,
            "Urgency pressure language",
            f"{len(urgency_hits)} urgency phrase(s): {', '.join(urgency_hits[:5])}",
            "body",
        ))
    elif len(urgency_hits) == 1:
        findings.append(Finding(
            Severity.LOW,
            "Urgency pressure language",
            f"Urgency phrase: {urgency_hits[0]}",
            "body",
        ))

    return findings
