"""Async NVD API 2.0 client with politeness throttling and on-disk caching.

Why these choices (design decisions):
* NVD allows ~5 requests/30s without an API key; we enforce that with a
  global token-bucket implemented as a serialized, timestamped sleep.
* Results are cached per (product, version) under .cache/nvd so repeat
  scans are instant and CI/tests never touch the network.
* Fail-soft: any network/API error degrades to local-DB results only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MIN_INTERVAL = 6.0  # seconds between requests without an API key (5 req/30s)
CACHE_DIR = Path(".cache/nvd")

_lock = asyncio.Lock()
_last_request = 0.0


async def _throttled_get(client: httpx.AsyncClient, params: dict) -> dict:
    global _last_request
    async with _lock:
        wait = max(0.0, MIN_INTERVAL - (time.monotonic() - _last_request))
        if wait:
            await asyncio.sleep(wait)
        _last_request = time.monotonic()
        resp = await client.get(NVD_BASE, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()


async def lookup_cves(
    product: str, version: str | None = None, api_key: str | None = None
) -> list[dict]:
    """Look up recent CVEs for a product/version. Cached and throttled."""
    key = hashlib.sha256(f"{product}:{version}".encode()).hexdigest()
    cache_file = CACHE_DIR / f"{key}.json"
    if cache_file.exists():
        return json.loads(cache_file.read_text())

    params = {"keywordSearch": f"{product} {version}".strip()}
    headers = {"apiKey": api_key} if api_key else {}
    try:
        async with httpx.AsyncClient(headers=headers) as client:
            data = await _throttled_get(client, params)
    except Exception as exc:  # fail-soft: offline scans still work
        log.warning("NVD lookup failed for %s: %s", product, exc)
        return []

    cves = [
        {
            "id": item["cve"]["id"],
            "description": next(
                (d["value"] for d in item["cve"].get("descriptions", []) if d["lang"] == "en"),
                "",
            ),
        }
        for item in data.get("vulnerabilities", [])
    ][:5]
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(cves))
    return cves
