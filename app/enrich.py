from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

URLHAUS_URL_LOOKUP = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HASH_LOOKUP = "https://urlhaus-api.abuse.ch/v1/payload/"
URLHAUS_HOST_LOOKUP = "https://urlhaus-api.abuse.ch/v1/host/"
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
VT_URL_LOOKUP = "https://www.virustotal.com/api/v3/urls"
VT_FILE_LOOKUP = "https://www.virustotal.com/api/v3/files/"

TIMEOUT = 10.0
CACHE_TTL = 60 * 60

@dataclass
class TTLCache:
    ttl: int = CACHE_TTL
    _store: Dict[str, Any] = field(default_factory=dict)

    def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if not entry:
            return None
        value, ts = entry
        if time.time() - ts > self.ttl:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (value, time.time())

cache = TTLCache()

def get_vt_api_key() -> Optional[str]:
    return os.environ.get("VT_API_KEY") or None

def get_urlhaus_auth_key() -> Optional[str]:
    return os.environ.get("URLHAUS_AUTH_KEY") or None

def get_abuseipdb_api_key() -> Optional[str]:
    return os.environ.get("ABUSEIPDB_API_KEY") or None

def _uh(client: httpx.AsyncClient) -> Dict[str, str]:
    key = get_urlhaus_auth_key()
    return {"Auth-Key": key} if key else {}

async def lookup_urlhaus_url(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    key = f"urlhaus:url:{url}"
    cached = cache.get(key)
    if cached is not None:
        return cached

    result: Dict[str, Any] = {"source": "urlhaus", "queried": url, "found": False}
    if not _uh(client):
        result["skipped"] = "no URLHAUS_AUTH_KEY configured"
        return result
    try:
        resp = await client.post(URLHAUS_URL_LOOKUP, data={"url": url}, headers=_uh(client))
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "ok":
            result.update({
                "found": True,
                "threat": data.get("threat"),
                "tags": data.get("tags", []),
                "urlhaus_reference": data.get("urlhaus_reference"),
            })
        elif data.get("query_status") != "no_results":
            result["error"] = f"urlhaus query_status={data.get('query_status')}"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    cache.set(key, result)
    return result

async def lookup_urlhaus_hash(sha256: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    key = f"urlhaus:hash:{sha256}"
    cached = cache.get(key)
    if cached is not None:
        return cached

    result: Dict[str, Any] = {"source": "urlhaus", "queried": sha256, "found": False}
    if not _uh(client):
        result["skipped"] = "no URLHAUS_AUTH_KEY configured"
        return result
    try:
        resp = await client.post(URLHAUS_HASH_LOOKUP, data={"sha256": sha256}, headers=_uh(client))
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "ok" and data.get("sha256"):
            result.update({
                "found": True,
                "file_type": data.get("file_type"),
                "signature": data.get("signature"),
                "tags": data.get("tags", []),
            })
        elif data.get("query_status") != "no_results":
            result["error"] = f"urlhaus query_status={data.get('query_status')}"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    cache.set(key, result)
    return result

async def lookup_urlhaus_host(host: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    key = f"urlhaus:host:{host}"
    cached = cache.get(key)
    if cached is not None:
        return cached

    result: Dict[str, Any] = {"source": "urlhaus", "queried": host, "found": False}
    if not _uh(client):
        result["skipped"] = "no URLHAUS_AUTH_KEY configured"
        return result
    try:
        resp = await client.post(URLHAUS_HOST_LOOKUP, data={"host": host}, headers=_uh(client))
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "ok":
            url_count = data.get("url_count")
            urls = data.get("urls") or []
            sample = next((u for u in urls if isinstance(u, dict) and u.get("url")), None)
            result.update({
                "found": bool(url_count or urls),
                "url_count": url_count if isinstance(url_count, int) else len(urls),
                "threat": sample.get("threat") if sample else None,
                "tags": sample.get("tags", []) if sample else [],
            })
        elif data.get("query_status") != "no_results":
            result["error"] = f"urlhaus query_status={data.get('query_status')}"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    cache.set(key, result)
    return result

async def lookup_abuseipdb(ip: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
    api_key = get_abuseipdb_api_key()
    if not api_key:
        return None
    key = f"abuseipdb:{ip}"
    cached = cache.get(key)
    if cached is not None:
        return cached

    result: Dict[str, Any] = {"source": "abuseipdb", "queried": ip}
    try:
        resp = await client.get(
            ABUSEIPDB_CHECK,
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": api_key, "Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        result.update({
            "found": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor"),
        })
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    cache.set(key, result)
    return result

async def lookup_vt_url(url: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
    api_key = get_vt_api_key()
    if not api_key:
        return None
    key = f"vt:url:{url}"
    cached = cache.get(key)
    if cached is not None:
        return cached

    result: Dict[str, Any] = {"source": "virustotal", "queried": url}
    try:
        resp = await client.get(f"{VT_URL_LOOKUP}/{url}", headers={"x-apikey": api_key})
        if resp.status_code == 404:
            result["found"] = False
        else:
            resp.raise_for_status()
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            result.update({
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
            })
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    cache.set(key, result)
    return result

async def lookup_vt_hash(sha256: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
    api_key = get_vt_api_key()
    if not api_key:
        return None
    key = f"vt:hash:{sha256}"
    cached = cache.get(key)
    if cached is not None:
        return cached

    result: Dict[str, Any] = {"source": "virustotal", "queried": sha256}
    try:
        resp = await client.get(f"{VT_FILE_LOOKUP}{sha256}", headers={"x-apikey": api_key})
        if resp.status_code == 404:
            result["found"] = False
        else:
            resp.raise_for_status()
            attrs = resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            result.update({
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "popular_threat_name": attrs.get("popular_threat_classification", {})
                .get("suggested_threat_label"),
            })
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    cache.set(key, result)
    return result

async def enrich(
    urls: List[str],
    hashes: List[str],
    origin_ip: Optional[str] = None,
) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "urlhaus_urls": [], "urlhaus_hashes": [], "vt_urls": [], "vt_hashes": [],
        "urlhaus_hosts": [], "abuseipdb": [],
    }
    has_vt = get_vt_api_key() is not None

    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        for url in urls:
            results["urlhaus_urls"].append(await lookup_urlhaus_url(url, client))
            if has_vt:
                vt = await lookup_vt_url(url, client)
                if vt is not None:
                    results["vt_urls"].append(vt)
        for sha in hashes:
            if not sha:
                continue
            results["urlhaus_hashes"].append(await lookup_urlhaus_hash(sha, client))
            if has_vt:
                vt = await lookup_vt_hash(sha, client)
                if vt is not None:
                    results["vt_hashes"].append(vt)

        if origin_ip:
            results["urlhaus_hosts"].append(await lookup_urlhaus_host(origin_ip, client))
            abuse = await lookup_abuseipdb(origin_ip, client)
            if abuse is not None:
                results["abuseipdb"].append(abuse)

    return results
