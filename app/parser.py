from __future__ import annotations

import hashlib
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
from typing import Any, Dict, List, Optional

from difflib import SequenceMatcher

from .score import Finding, Severity

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".bat", ".cmd", ".com", ".cpl", ".js", ".jse",
    ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".hta", ".iso", ".img", ".vhd",
    ".lnk", ".msi", ".jar", ".reg", ".docm", ".xlsm", ".pptm", ".one", ".html",
}

LOOKALIKE_THRESHOLD = 0.90

def parse_email(raw: bytes) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(raw)

def _attachments(msg: EmailMessage) -> List[Dict[str, Any]]:
    attachments: List[Dict[str, Any]] = []
    for part in msg.iter_attachments():
        filename = part.get_filename() or "(unnamed)"
        ext = ""
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[1].lower()
        content = part.get_payload(decode=True) or b""
        attachments.append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "size_bytes": len(content),
            "extension": ext,
            "sha256": hashlib.sha256(content).hexdigest() if content else None,
            "risky": ext in RISKY_EXTENSIONS,
        })
    return attachments

def auth_results(msg: EmailMessage) -> Dict[str, Any]:
    blocks = [str(v).lower() for v in msg.get_all("Authentication-Results", [])]

    verdicts: Dict[str, List[str]] = {"spf": [], "dkim": [], "dmarc": []}
    verdict_pat = {
        "spf": r"\bspf=(pass|fail|softfail|none|neutral|temperror|permerror)\b",
        "dkim": r"\bdkim=(pass|fail|softfail|none|neutral|temperror|permerror)\b",
        "dmarc": r"\bdmarc=(pass|fail|softfail|none|neutral|temperror|permerror)\b",
    }
    for block in blocks:
        for mech, pat in verdict_pat.items():
            for m in re.finditer(pat, block):
                verdicts[mech].append(m.group(1))

    RANK0 = {"pass", "fail", "softfail", "none", "neutral", "temperror", "permerror"}
    for v in msg.get_all("Received-SPF", []):
        words = str(v).strip().split(None, 1)
        if words and words[0].lower() in RANK0:
            verdicts["spf"].append(words[0].lower())

    RANK = {"pass": 0, "neutral": 1, "none": 2, "policy": 2,
            "softfail": 3, "temperror": 2, "permerror": 2, "fail": 4}

    results: Dict[str, Any] = {}
    for mech, verdicts in verdicts.items():
        if not verdicts:
            results[mech] = None
        else:
            worst = max(verdicts, key=lambda v: RANK.get(v, 2))
            results[mech] = worst
            if len(set(verdicts)) > 1:
                results[f"{mech}_conflict"] = sorted(set(verdicts))

    for block in blocks:
        m = re.search(r"\bdmarc=[a-z]+[^;]*?\bp=(none|quarantine|reject)\b", block)
        if m:
            results["dmarc_policy"] = m.group(1)
            break
    return results

def _domain_of(addr: str) -> str:
    _, email_addr = parseaddr(addr)
    return email_addr.rsplit("@", 1)[-1].lower() if "@" in email_addr else ""

def _root_domain(domain: str) -> str:
    labels = domain.split(".")
    two_level_tlds = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "co.jp", "com.br"}
    if len(labels) >= 3 and ".".join(labels[-2:]) in two_level_tlds:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain

def identity_checks(msg: EmailMessage, get_domains: List[str]) -> Dict[str, Any]:
    from_hdr = msg.get("From", "")
    display_name, from_addr = parseaddr(from_hdr)
    reply_to_addrs = [addr for _, addr in getaddresses(msg.get_all("Reply-To", []))]
    return_path = parseaddr(msg.get("Return-Path", "") or "")[1]

    from_domain = from_addr.rsplit("@", 1)[-1].lower() if "@" in from_addr else ""
    reply_domain = reply_to_addrs[0].rsplit("@", 1)[-1].lower() if reply_to_addrs else ""
    return_domain = return_path.rsplit("@", 1)[-1].lower() if "@" in return_path else ""

    findings: List[Finding] = []

    if display_name:
        brand_domains = list(get_domains) + [
            "chase.com", "paypal.com", "microsoft.com", "apple.com",
            "amazon.com", "google.com", "dhl.com", "fedex.com", "irs.gov",
        ]
        for brand in brand_domains:
            brand_label = brand.split(".")[0]
            if brand_label and brand_label in display_name.lower() and not from_domain.endswith(brand):
                findings.append(Finding(
                    Severity.HIGH,
                    "Display-name spoofing",
                    f'Display name "{display_name}" references "{brand}" but the '
                    f"sender domain is {from_domain or 'unknown'}",
                    "headers",
                ))
                break

    if reply_domain and from_domain and reply_domain != from_domain:
        freemail = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                    "aol.com", "mail.ru", "yandex.com", "proton.me", "gmx.com"}
        if reply_domain in freemail or _root_domain(reply_domain) != _root_domain(from_domain):
            sev = Severity.HIGH if reply_domain in freemail else Severity.MEDIUM
            findings.append(Finding(
                sev,
                "Reply-To mismatch",
                f"Replies would go to {reply_to_addrs[0]}, not the From domain ({from_domain})"
                + (" — a free-mail account" if reply_domain in freemail else ""),
                "headers",
            ))

    if return_domain and from_domain and return_domain != from_domain and _root_domain(return_domain) != _root_domain(from_domain):
        findings.append(Finding(
            Severity.LOW,
            "Envelope-from mismatch",
            f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})",
            "headers",
        ))

    lookalike: Optional[str] = None
    if from_domain and get_domains:
        for cd in get_domains:
            ratio = SequenceMatcher(None, from_domain, cd.lower()).ratio()
            if 0.0 < ratio < 1.0 and ratio >= LOOKALIKE_THRESHOLD:
                lookalike = cd
                findings.append(Finding(
                    Severity.HIGH,
                    "Lookalike sender domain",
                    f"Sender domain {from_domain} closely resembles {cd} "
                    f"({ratio:.0%} similar)",
                    "headers",
                ))
                break

    return {
        "from": from_addr,
        "display_name": display_name,
        "from_domain": from_domain,
        "reply_to": reply_to_addrs,
        "return_path": return_path,
        "findings": findings,
        "lookalike": lookalike,
    }

def origin_ip(msg: EmailMessage) -> Dict[str, Any]:
    ip_re = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
    hops: List[Dict[str, str]] = []

    for hdr in msg.get_all("Received", []):
        text = " ".join(str(hdr).split())
        connection_ip = None
        helo_ip = None

        m = re.search(r"from\s+\S+\s*\((HELO|EHLO)\s*\[?([^)\]]+)\]?\)\s*\((?:[^)]*?)\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", text, re.IGNORECASE)
        if m:
            helo_raw = m.group(2).strip("[]")
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", helo_raw):
                helo_ip = helo_raw
            connection_ip = m.group(3)
        else:

            m2 = re.search(r"from\s+\S+\s*\((?:[^)]*?)\[(\d{1,3}(?:\.\d{1,3}){3})\]", text, re.IGNORECASE)
            if m2:
                connection_ip = m2.group(1)

        if connection_ip:
            hops.append({"connection_ip": connection_ip, "helo_ip": helo_ip, "raw": text[:200]})

    result: Dict[str, Any] = {"ip": None, "helo_ip": None, "helo_mismatch": False}
    if hops:
        oldest = hops[-1]
        result["ip"] = oldest["connection_ip"]
        result["helo_ip"] = oldest["helo_ip"]
        if oldest["helo_ip"] and oldest["helo_ip"] != oldest["connection_ip"]:
            result["helo_mismatch"] = True
    return result

def received_chain(msg: EmailMessage) -> List[Dict[str, str]]:
    hops: List[Dict[str, str]] = []
    for hdr in msg.get_all("Received", []):
        text = " ".join(str(hdr).split())
        m_from = re.search(r"from\s+(\S+)", text, re.IGNORECASE)
        m_by = re.search(r"by\s+(\S+)", text, re.IGNORECASE)
        hops.append({
            "from": m_from.group(1).strip("();,") if m_from else "?",
            "by": m_by.group(1).strip("();,") if m_by else "?",
        })
    return hops

def analyze_email(raw: bytes, get_domains: List[str]) -> Dict[str, Any]:
    msg = parse_email(raw)
    if not any(msg.get(h) for h in ("From", "Subject", "To", "Date")):
        raise ValueError("no email headers found — not a parseable email")
    attachments = _attachments(msg)

    for att in attachments:
        if att["risky"]:
            ext = att["extension"]
            sev = Severity.HIGH if ext in {".exe", ".iso", ".img", ".lnk", ".hta", ".scr"} else Severity.MEDIUM
            att["findings"] = [Finding(
                sev,
                "Risky attachment type",
                f"Attachment {att['filename']} has a high-risk extension ({ext})",
                "attachments",
            )]
        else:
            att["findings"] = []

    text_body = ""
    text_part = msg.get_body(preferencelist=("plain",))
    if text_part is not None:
        try:
            text_body = text_part.get_content()
        except Exception:
            text_body = ""

    identity = identity_checks(msg, get_domains)
    auth = auth_results(msg)
    origin = origin_ip(msg)

    findings: List[Finding] = list(identity["findings"])

    if origin["helo_mismatch"]:
        findings.append(Finding(
            Severity.MEDIUM,
            "HELO identity mismatch",
            f"Sending host connected from {origin['ip']} but announced itself "
            f"as {origin['helo_ip']} — spoofed HELO",
            "headers",
        ))
    for att in attachments:
        findings.extend(att["findings"])

    for mech in ("spf", "dkim", "dmarc"):
        verdict = auth.get(mech)
        conflict = auth.get(f"{mech}_conflict")
        if conflict:
            findings.append(Finding(
                Severity.MEDIUM, f"{mech.upper()} results conflict",
                f"Verifiers disagree on {mech.upper()}: "
                f"{' vs '.join(conflict)} — relayed through inconsistent hops",
                "headers",
            ))
        if verdict in {"fail", "softfail", "policy"}:
            sev = Severity.HIGH if mech == "dmarc" else Severity.MEDIUM
            findings.append(Finding(
                sev, f"{mech.upper()} {verdict}",
                f"Authentication-Results shows {mech}={verdict}", "headers",
            ))
        elif verdict in (None, "none"):
            title = f"{mech.upper()} result missing" if verdict is None else f"{mech.upper()} not signed/configured"
            findings.append(Finding(
                Severity.LOW, title,
                f"No positive {mech.upper()} verdict found in Authentication-Results headers",
                "headers",
            ))

    if auth.get("dmarc_policy") == "none" and auth.get("dmarc") in ("pass", "none", None):
        findings.append(Finding(
            Severity.LOW, "DMARC policy p=none",
            "Sender domain's DMARC policy enforces nothing (p=none) — "
            "spoofing this domain is not blocked by DMARC",
            "headers",
        ))

    return {
        "headers": {
            "from": identity["from"],
            "display_name": identity["display_name"],
            "reply_to": identity["reply_to"],
            "return_path": identity["return_path"],
            "subject": str(msg.get("Subject", "(no subject)")),
            "date": str(msg.get("Date", "")),
            "message_id": str(msg.get("Message-ID", "")),
            "authentication": auth,
            "received_chain": received_chain(msg),
        },
        "attachments": attachments,
        "identity": {k: v for k, v in identity.items() if k != "findings"},
        "origin": origin,
        "_bodies": {"text": text_body},
        "findings": findings,
    }
