from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Set

from bs4 import BeautifulSoup

from .score import Finding, Severity

COMMON_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "hotmail.com",
    "yahoo.com", "apple.com", "amazon.com", "cloudflare.com", "w3.org",
    "mimecast.com", "proofpoint.com", "office365.com", "sentry.io",
}

URL_RE = re.compile(
    r"\b(?:(?:h(?:tt|xx)ps?|ftp)://|www\.)"
    r"[^\s<>\"'()\[\]{}]+",
    re.IGNORECASE,
)

DEFANG_RE = re.compile(r"\bh(?:tt|xx)p(s?)://", re.IGNORECASE)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)

PRIVATE_IPS = {"127.0.0.1", "0.0.0.0"}

def refang(url: str) -> str:
    return DEFANG_RE.sub(r"http\1://", url)

def extract_urls(text: str) -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()
    for raw in URL_RE.findall(text or ""):
        url = refang(raw).rstrip(".,;:")

        if url.lower().startswith("www."):
            url = "http://" + url
        if url not in seen:
            seen.add(url)
            found.append(url)
    return found

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private or ip in PRIVATE_IPS
    except ValueError:
        return True

def extract_domains_and_ips(text: str) -> Dict[str, List[str]]:
    urls = set(u.lower() for u in extract_urls(text))
    domains: List[str] = []
    ips: List[str] = []
    seen: Set[str] = set()

    for ip in IP_RE.findall(text or ""):
        if is_private_ip(ip) or ip in seen:
            continue

        if any(ip in u for u in urls):
            continue
        seen.add(ip)
        ips.append(ip)

    for dom in DOMAIN_RE.findall(text or ""):
        d = dom.lower().rstrip(".")
        if d in seen or d in COMMON_DOMAINS:
            continue

        if any(f"://{d}" in u or f".{d}/" in u for u in urls):
            continue
        seen.add(d)
        domains.append(d)

    return {"domains": domains[:25], "ips": ips[:25]}

def flatten_html_text(html: str) -> str:
    return BeautifulSoup(html or "", "html.parser").get_text(" ")

def pull_iocs(text: str, html: str = "") -> Dict[str, List[str]]:
    soup = BeautifulSoup(html or "", "html.parser")
    hrefs = " ".join(a.get("href", "") for a in soup.find_all("a", href=True))
    combined = (text or "") + "\n" + soup.get_text(" ") + "\n" + hrefs
    result = extract_domains_and_ips(combined)
    result["urls"] = extract_urls(combined)
    return result

def html_checks(html: str) -> Dict[str, Any]:
    findings: List[Finding] = []
    soup = BeautifulSoup(html or "", "html.parser")

    forms = soup.find_all("form")
    for form in forms:
        inputs = [i.get("type", "text") for i in form.find_all("input")]
        has_creds = "password" in inputs or any(
            (i.get("name") or "").lower() in {"pass", "passwd", "pin"} for i in form.find_all("input")
        )
        action = form.get("action") or ""
        submits_out = bool(action) and not action.startswith(("#", "/"))
        if has_creds:
            sev = Severity.HIGH if submits_out else Severity.MEDIUM
            findings.append(Finding(
                sev,
                "Credential form in email",
                f"HTML body contains a form asking for a password"
                + (f" that submits to an external site ({action})" if submits_out else ""),
                "body",
            ))

    external_imgs = []
    for img in soup.find_all("img"):
        src = img.get("src", "")
        if src.startswith(("http://", "https://")):
            external_imgs.append(src)
    if external_imgs:
        findings.append(Finding(
            Severity.LOW,
            "External images",
            f"{len(external_imgs)} remote image(s) load from external hosts "
            "(possible tracking pixel / IP logger)",
            "body",
        ))

    scripts = soup.find_all("script")
    if scripts:
        findings.append(Finding(
            Severity.MEDIUM,
            "Script in email body",
            f"HTML body contains {len(scripts)} <script> tag(s)",
            "body",
        ))

    mismatches: List[str] = []
    for a in soup.find_all("a", href=True):
        text = a.get_text(strip=True)
        href = a["href"]
        m = re.match(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", text.strip().lower())
        if m and href.startswith("http"):
            hm = re.match(r"https?://([^/]+)", href)
            if hm and not hm.group(1).endswith(m.group(1)):
                mismatches.append(f'"{text.strip()}" -> {href}')
    if mismatches:
        findings.append(Finding(
            Severity.HIGH,
            "Link text does not match target",
            f"{len(mismatches)} link(s) display one domain but link elsewhere: "
            + "; ".join(mismatches[:3]),
            "body",
        ))

    return {
        "has_html": bool(html),
        "findings": findings,
        "external_images": external_imgs[:10],
    }
