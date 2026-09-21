# Phishing Email Checker

A local phishing-email triage tool for SOC analysts. Drop in `.eml` files (one at a time or a whole folder), get an explainable verdict — Benign / Suspicious / Malicious — with every finding scored and traceable to its evidence.

Everything runs locally. Only IOC lookups (URLs, hashes, the sending IP) go out to threat-intelligence feeds.

## Features

- **Header & identity analysis** — SPF / DKIM / DMARC verdicts (including conflicting results across hops), display-name spoofing, lookalike sender domains, Reply-To and envelope-from mismatches, DMARC `p=none` warning.
- **Received-chain forensics** — extracts the true origin IP (sees through spoofed HELO), flags HELO identity mismatch.
- **Body & HTML analysis** — credential forms posting off-site, link-text vs href mismatch, external images, embedded scripts.
- **Content heuristics** — advance-fee / lottery / gift-card / urgent-payment wording, requests for personal data.
- **IOC extraction** — URLs (including defanged `hxxp://`), domains, IPs, attachments with SHA-256 hashing and risky-extension flagging.
- **Threat-intel enrichment (all optional)** — URLhaus (URLs, payloads, host), VirusTotal (URLs, files), AbuseIPDB (sending IP reputation). TTL-cached, fail-soft, and results feed back into the verdict.
- **Weighted verdict engine** — every finding carries a severity; the score maps to Benign / Suspicious / Malicious. Thresholds are configurable.
- **Bulk triage** — drag a folder of emails, get a sortable/filterable verdict table, drill into any row, export CSV.
- **Markdown reports** — ticket-ready report per email.

## Requirements

- Python 3.11+

## Setup

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # Linux/macOS
copy .env.example .env
```

Edit `.env` and set `COMPANY_DOMAINS` to your own domain(s) — that enables lookalike-sender detection against your org. API keys for URLhaus / VirusTotal / AbuseIPDB are optional; without them enrichment is skipped gracefully.

## Run

```bash
.venv\Scripts\uvicorn app.main:app --port 8501
```

Open http://localhost:8501, then drop a `.eml` file (or a whole folder) onto the page.

## API

| Method | Route | Purpose |
|---|---|---|
| POST | `/api/analyze` | Analyze one email (raw body or multipart `file`) |
| POST | `/api/bulk` | Analyze many emails at once |
| POST | `/api/enrich` | Run TI lookups and rescore an analysis |
| POST | `/api/report` | Analyze + enrich + return a Markdown report |
| GET | `/api/analysis/{id}` | Fetch a stored bulk analysis |

## CLI

Batch-score a folder of labeled samples and report precision/recall:

```bash
.venv\Scripts\python calibrate.py --dir samples
.venv\Scripts\python calibrate.py --suspicious-min 4 --malicious-min 9
```

Generate a synthetic validation corpus (200 phishing + 200 legitimate emails across 12 archetypes each) and measure detection / false-positive rates:

```bash
.venv\Scripts\python run_validation.py
```

## Tests

```bash
.venv\Scripts\python -m pytest tests/ -q
```

## Configuration

| Variable | Purpose |
|---|---|
| `COMPANY_DOMAINS` | Comma-separated list of your org's domains |
| `PHISH_SUSPICIOUS_MIN` | Score threshold for Suspicious (default 3) |
| `PHISH_MALICIOUS_MIN` | Score threshold for Malicious (default 7) |
| `URLHAUS_AUTH_KEY` | Free key from auth.abuse.ch |
| `ABUSEIPDB_API_KEY` | Free key from abuseipdb.com |
| `VT_API_KEY` | VirusTotal API key |

> Triage aid only — always confirm with your own procedures before escalating.
