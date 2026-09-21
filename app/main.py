from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import content, enrich, iocs, parser
from .enrich import get_abuseipdb_api_key, get_urlhaus_auth_key, get_vt_api_key
from .score import compute_score, finding_from_dict

load_dotenv()

app = FastAPI(title="Phish Triage", version="1.0.0")

STATIC_DIR = Path(__file__).parent / "static"

def get_domains() -> List[str]:
    raw = os.environ.get("COMPANY_DOMAINS", "example.com")
    return [d.strip().lower() for d in raw.split(",") if d.strip()]

def analyze_bytes(raw: bytes) -> Dict[str, Any]:

    raw = raw.replace(b"\r\r\n", b"\r\n")
    parsed = parser.analyze_email(raw, get_domains())
    body_text = _body_text(parsed)
    html_body = _body_html(raw)

    urls = iocs.pull_iocs(body_text, html_body)["urls"]
    dom_ips = {k: v for k, v in iocs.pull_iocs(body_text, html_body).items() if k != "urls"}
    html_flags = iocs.html_checks(html_body)

    body_findings = content.body_checks(body_text)
    findings = list(parsed["findings"]) + html_flags["findings"] + body_findings

    return {
        "headers": parsed["headers"],
        "identity": parsed["identity"],
        "attachments": parsed["attachments"],
        "origin": parsed["origin"],
        "iocs": {
            "urls": urls,
            "domains": dom_ips["domains"],
            "ips": dom_ips["ips"],
        },
        "html_flags": {
            "external_images": html_flags["external_images"],
        },
        "findings": [f.to_dict() for f in findings],
        "score": compute_score(findings).to_dict(),
    }

def ti_feed_status() -> Dict[str, bool]:
    return {
        "urlhaus": get_urlhaus_auth_key() is not None,
        "virustotal": get_vt_api_key() is not None,
        "abuseipdb": get_abuseipdb_api_key() is not None,
    }

async def apply_enrichment(analysis: Dict[str, Any]) -> Dict[str, Any]:
    origin_ip = (analysis.get("origin") or {}).get("ip")
    urls = analysis["iocs"]["urls"]
    hashes = [a["sha256"] for a in analysis.get("attachments", []) if a.get("sha256")]

    enrichment = await enrich.enrich(urls, hashes, origin_ip=origin_ip)
    new_ti = ti_findings(enrichment, origin_ip)

    analysis["enrichment"] = enrichment
    analysis["ti_feed_status"] = ti_feed_status()
    if new_ti:
        analysis["findings"] = analysis.get("findings", []) + [f.to_dict() for f in new_ti]
        rescored = compute_score([finding_from_dict(fd) for fd in analysis["findings"]])
        analysis["score"] = rescored.to_dict()
    return analysis

def ti_findings(en: Dict[str, Any], origin_ip: Optional[str]) -> List[Finding]:
    from .score import Finding, Severity

    out: List[Finding] = []

    for r in en.get("urlhaus_hosts", []):
        if r.get("found"):
            out.append(Finding(
                Severity.HIGH, "Origin IP hosts malware (URLhaus)",
                f"Sending IP {r['queried']} hosts known malware URL(s) "
                f"({r.get('url_count', '?')} tracked, threat: {r.get('threat') or 'unknown'})",
                "enrichment",
            ))

    for r in en.get("abuseipdb", []):
        score = r.get("abuse_confidence_score") or 0
        if not r.get("found"):
            continue
        detail = (f"AbuseIPDB confidence {score}/100, {r.get('total_reports', 0)} report(s)"
                  + (f", {r.get('country_code') or '?'}" if r.get("country_code") else "")
                  + (f", {r.get('usage_type') or 'unknown usage'}"))
        if score >= 75:
            out.append(Finding(Severity.HIGH, "Origin IP has high abuse confidence", detail, "enrichment"))
        elif score >= 25:
            out.append(Finding(Severity.MEDIUM, "Origin IP has elevated abuse reports", detail, "enrichment"))
        elif score >= 1:
            out.append(Finding(Severity.LOW, "Origin IP has minor abuse history", detail, "enrichment"))

    for r in en.get("urlhaus_urls", []):
        if r.get("found"):
            out.append(Finding(
                Severity.HIGH, "URL is known malware distribution (URLhaus)",
                f"{r['queried']} — {r.get('threat') or 'malware URL'}",
                "enrichment",
            ))

    for r in en.get("urlhaus_hashes", []):
        if r.get("found"):
            out.append(Finding(
                Severity.HIGH, "Attachment is known malware (URLhaus payload)",
                f"sha256 {r['queried']} — {r.get('signature') or 'flagged payload'}",
                "enrichment",
            ))

    for r in en.get("vt_urls", []) + en.get("vt_hashes", []):
        malicious = r.get("malicious", 0) or 0
        suspicious = r.get("suspicious", 0) or 0
        if not r.get("found"):
            continue
        if malicious >= 3:
            out.append(Finding(
                Severity.HIGH, "VirusTotal flags IOC as malicious",
                f"{r['queried']} detected by {malicious} engine(s)"
                + (f" ({r.get('popular_threat_name')})" if r.get("popular_threat_name") else ""),
                "enrichment",
            ))
        elif malicious + suspicious >= 1:
            out.append(Finding(
                Severity.MEDIUM, "VirusTotal flags IOC as suspicious",
                f"{r['queried']} — {malicious} malicious, {suspicious} suspicious engine hit(s)",
                "enrichment",
            ))

    return out

def _body_text(parsed: Dict[str, Any]) -> str:
    return parsed.get("_bodies", {}).get("text", "")

def _body_html(raw: bytes) -> str:
    msg = parser.parse_email(raw)
    html_part = msg.get_body(preferencelist=("html",))
    if html_part is not None:
        return html_part.get_content()
    return ""

@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")

@app.post("/api/analyze")
async def analyze(request: Request) -> JSONResponse:
    raw = await _read_email_body(request)
    if not raw or not raw.strip():
        raise HTTPException(status_code=400, detail="No email content provided. Upload a .eml file or paste raw email source.")

    try:
        report = analyze_bytes(raw)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse email: {type(exc).__name__}: {exc}")
    return JSONResponse(report)

async def _read_email_body(request: Request) -> bytes:
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file")
        if upload is not None and hasattr(upload, "read"):
            data = await upload.read()
            if data.strip():
                return data
        return b""
    return await request.body()

@app.post("/api/enrich")
async def enrich_endpoint(request: Request) -> JSONResponse:
    data = await request.json()
    analysis = await apply_enrichment(data)
    return JSONResponse({
        "enrichment": analysis["enrichment"],
        "findings": analysis["findings"],
        "score": analysis["score"],
    })

ANALYSIS_STORE: Dict[str, Dict[str, Any]] = {}
STORE_MAX = 200

def _store_put(analysis: Dict[str, Any]) -> str:
    raw_id = analysis.get("headers", {}).get("message_id") or f"id-{len(ANALYSIS_STORE)}-{id(analysis):x}"
    base = re.sub(r"[^A-Za-z0-9._@~-]", "_", raw_id)[:80] or "unnamed"
    aid = base
    n = 1
    while aid in ANALYSIS_STORE:
        aid = f"{base}~{n}"
        n += 1
    ANALYSIS_STORE[aid] = analysis
    while len(ANALYSIS_STORE) > STORE_MAX:
        ANALYSIS_STORE.pop(next(iter(ANALYSIS_STORE)))
    return aid

def _bulk_row(aid: str, name: str, a: Dict[str, Any]) -> Dict[str, Any]:
    origin = a.get("origin") or {}
    return {
        "id": aid,
        "name": name,
        "subject": a.get("headers", {}).get("subject", "(no subject)"),
        "from": a.get("headers", {}).get("from", ""),
        "verdict": a.get("score", {}).get("verdict", "?"),
        "score": a.get("score", {}).get("score", 0),
        "top_findings": [f["title"] for f in a.get("findings", [])
                         if f.get("severity") in {"high", "medium"}][:4],
        "origin_ip": origin.get("ip"),
        "helo_mismatch": bool(origin.get("helo_mismatch")),
        "urls": len(a.get("iocs", {}).get("urls", [])),
        "attachments": len(a.get("attachments", [])),
        "error": a.get("error"),
    }

@app.post("/api/bulk")
async def bulk_analyze(request: Request) -> JSONResponse:
    form = await request.form()
    rows: List[Dict[str, Any]] = []

    files = [v for _k, v in form.multi_items() if hasattr(v, "read")]
    if not files:
        raise HTTPException(status_code=400, detail="No files received.")

    for upload in files:
        name = getattr(upload, "filename", None) or "(unnamed).eml"
        data = await upload.read()
        if not data or not data.strip():
            rows.append({"id": None, "name": name, "error": "empty file"})
            continue
        try:
            analysis = analyze_bytes(data)
            aid = _store_put(analysis)
            rows.append(_bulk_row(aid, name, analysis))
        except Exception as exc:
            rows.append({"id": None, "name": name,
                         "error": f"{type(exc).__name__}: {exc}"})

    return JSONResponse({"rows": rows})

@app.get("/api/analysis/{aid}")
async def get_analysis(aid: str) -> JSONResponse:
    analysis = ANALYSIS_STORE.get(aid)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found (store evicted or server restarted).")
    return JSONResponse(analysis)

@app.get("/api/analysis/{aid}/report")
async def get_analysis_report(aid: str) -> JSONResponse:
    analysis = ANALYSIS_STORE.get(aid)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    md = markdown_report(analysis, analysis.get("enrichment") or {})
    return JSONResponse({"markdown": md, "analysis": analysis})

@app.post("/api/report")
async def report(request: Request) -> JSONResponse:
    raw = await _read_email_body(request)
    if not raw or not raw.strip():
        raise HTTPException(status_code=400, detail="No email content provided.")

    try:
        analysis = analyze_bytes(raw)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse email: {type(exc).__name__}: {exc}")

    analysis = await apply_enrichment(analysis)

    md = markdown_report(analysis, analysis["enrichment"])
    return JSONResponse({"markdown": md, "analysis": analysis})

def markdown_report(analysis: Dict[str, Any], enrichment: Dict[str, Any]) -> str:
    h = analysis["headers"]
    s = analysis["score"]
    lines: List[str] = []

    lines.append("# Phishing Triage Report")
    lines.append("")
    lines.append(f"**Subject:** {h.get('subject', '(no subject)')}  ")
    lines.append(f"**From:** {h.get('display_name', '')} <{h.get('from', '')}>  ")
    lines.append(f"**Date:** {h.get('date', '')}  ")
    lines.append(f"**Verdict:** **{s['verdict']}** (score {s['score']})")
    lines.append("")

    lines.append("## Authentication")
    auth = h.get("authentication", {})
    for mech in ("spf", "dkim", "dmarc"):
        lines.append(f"- **{mech.upper()}:** {auth.get(mech) or 'not present'}")
    lines.append("")

    lines.append("## Findings")
    if analysis["findings"]:
        for f in analysis["findings"]:
            lines.append(f"- **[{f['severity'].upper()}]** {f['title']} — {f['detail']}")
    else:
        lines.append("- No notable findings.")
    lines.append("")

    lines.append("## IOCs")
    ioc_lines = []
    for url in analysis["iocs"]["urls"]:
        ioc_lines.append(f"- URL: `{url}`")
    for dom in analysis["iocs"]["domains"]:
        ioc_lines.append(f"- Domain: `{dom}`")
    for ip in analysis["iocs"]["ips"]:
        ioc_lines.append(f"- IP: `{ip}`")
    for a in analysis["attachments"]:
        ioc_lines.append(f"- Attachment: `{a['filename']}` (sha256: `{a['sha256']}`)")
    if ioc_lines:
        lines.extend(ioc_lines)
    else:
        lines.append("- None extracted.")
    lines.append("")

    origin = analysis.get("origin") or {}
    if origin.get("ip"):
        lines.append(f"**Origin IP:** {origin['ip']}"
                     + (f" (HELO claimed {origin['helo_ip']})" if origin.get("helo_mismatch") else ""))
        lines.append("")

    lines.append("## Enrichment")
    urlhaus_bad = [r for r in enrichment.get("urlhaus_urls", []) if r.get("found")]
    urlhaus_host_bad = [r for r in enrichment.get("urlhaus_hosts", []) if r.get("found")]
    urlhaus_hash_bad = [r for r in enrichment.get("urlhaus_hashes", []) if r.get("found")]
    vt_bad = [r for r in enrichment.get("vt_urls", []) + enrichment.get("vt_hashes", [])
              if r.get("found") and (r.get("malicious", 0) or r.get("suspicious", 0))]
    abuse_bad = [r for r in enrichment.get("abuseipdb", [])
                 if r.get("found") and (r.get("abuse_confidence_score") or 0) >= 25]

    if origin.get("ip"):
        abuse_rows = [r for r in enrichment.get("abuseipdb", []) if r.get("queried") == origin["ip"]]
        if not any(k in enrichment for k in ("abuseipdb", "urlhaus_hosts", "urlhaus_urls")):
            lines.append(f"- Origin {origin['ip']} not enriched yet — click 'Enrich IOCs' or use 'Full report' to check reputation feeds.")
        elif abuse_rows and abuse_rows[0].get("found"):
            r0 = abuse_rows[0]
            lines.append(
                f"- AbuseIPDB: origin {origin['ip']} confidence "
                f"{r0.get('abuse_confidence_score', 0)}/100, "
                f"{r0.get('total_reports', 0)} report(s)"
                + (f", {r0.get('usage_type') or 'unknown usage'}" if r0.get("usage_type") else "")
            )
        elif abuse_rows:
            lines.append(f"- AbuseIPDB: origin {origin['ip']} not checked (no ABUSEIPDB_API_KEY configured).")

    if urlhaus_bad or urlhaus_host_bad or urlhaus_hash_bad or vt_bad or abuse_bad:
        for r in urlhaus_bad:
            lines.append(f"- URLhaus: `{r['queried']}` is a known malware URL ({r.get('threat', 'unknown threat')})")
        for r in urlhaus_host_bad:
            lines.append(f"- URLhaus: origin {r['queried']} hosts known malware URLs (count: {r.get('url_count', '?')})")
        for r in urlhaus_hash_bad:
            lines.append(f"- URLhaus: payload `{r['queried']}` known malware ({r.get('signature', 'no signature')})")
        for r in vt_bad:
            lines.append(f"- VirusTotal: `{r['queried']}` flagged by {r.get('malicious', 0)} engines")
    else:
        lines.append("- No malicious hits for extracted IOCs / origin IP.")
    lines.append("")

    return "\n".join(lines)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
