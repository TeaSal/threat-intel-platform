"""
Phase 7 — GreyNoise Community API collector.

Fetches noise/intent classification for individual IP addresses.
Endpoint: GET https://api.greynoise.io/v3/community/{ip}

Community tier is free and requires no API key, but providing one via
GREYNOISE_API_KEY in .env raises rate limits and unlocks richer context.

Rate limit (community tier): ~1 req/s — this module enforces that with
a configurable inter-request delay.

Returns raw JSON per IP exactly as the API responds; normalization happens
in src/pipeline/normalize.py (normalize_greynoise_record).

Example community response:
{
  "ip": "1.2.3.4",
  "noise": true,
  "riot": false,
  "classification": "malicious",   # "malicious" | "benign" | "unknown"
  "name": "unknown",
  "link": "https://viz.greynoise.io/ip/1.2.3.4",
  "last_seen": "2026-09-30",
  "message": "This IP is classified as malicious."
}

404 → IP not in GreyNoise dataset (returned as None, skipped by caller).
429 → rate-limited; collector backs off and retries once before skipping.
"""

import time
import logging
from typing import List, Dict, Any, Optional

import requests

from src.config import GREYNOISE_API_KEY, GREYNOISE_COMMUNITY_URL

logger = logging.getLogger(__name__)

# Default delay between requests to respect community rate limit (1 req/s)
_DEFAULT_DELAY_SECS = 1.1
# Backoff pause on 429 before the single retry
_BACKOFF_SECS = 5.0


def _build_headers() -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if GREYNOISE_API_KEY:
        headers["key"] = GREYNOISE_API_KEY
    return headers


def _fetch_one(ip: str, session: requests.Session,
               delay: float = _DEFAULT_DELAY_SECS) -> Optional[Dict[str, Any]]:
    """
    Fetch GreyNoise community context for a single IP.

    Returns the raw JSON dict, or None if:
      - IP is not in the GreyNoise dataset (404)
      - Rate limit hit after one retry (429 × 2)
      - Any other non-retryable HTTP error
    """
    url = GREYNOISE_COMMUNITY_URL.format(ip=ip)
    headers = _build_headers()

    for attempt in (1, 2):
        try:
            resp = session.get(url, headers=headers, timeout=10)
        except requests.RequestException as exc:
            logger.warning("[greynoise] request error for %s: %s", ip, exc)
            return None

        if resp.status_code == 200:
            try:
                data = resp.json()
                data["_queried_ip"] = ip   # guarantee the IP is present in our output
                return data
            except ValueError:
                logger.warning("[greynoise] non-JSON response for %s", ip)
                return None

        if resp.status_code == 404:
            # IP not in dataset — normal, not an error
            return None

        if resp.status_code == 429:
            if attempt == 1:
                logger.warning(
                    "[greynoise] rate-limited on %s, backing off %.1fs then retrying",
                    ip, _BACKOFF_SECS,
                )
                time.sleep(_BACKOFF_SECS)
                continue   # retry
            else:
                logger.warning("[greynoise] rate-limited twice on %s, skipping", ip)
                return None

        # Any other error — log and skip
        logger.warning(
            "[greynoise] HTTP %s for %s — skipping", resp.status_code, ip
        )
        return None

    return None  # should not reach here


def fetch_greynoise_context(
    ip_list: List[str],
    delay_secs: float = _DEFAULT_DELAY_SECS,
    max_ips: int = 500,
) -> List[Dict[str, Any]]:
    """
    Fetch GreyNoise community context for a list of IP addresses.

    Parameters
    ----------
    ip_list     : list of IP strings to query
    delay_secs  : pause between requests (default 1.1s to stay under 1 req/s)
    max_ips     : hard cap — never query more than this many IPs per call
                  (protects against accidentally passing thousands of IPs)

    Returns
    -------
    list of raw GreyNoise response dicts (only IPs that returned data are included;
    IPs not found in GreyNoise are silently omitted).

    Notes
    -----
    - Not called in --synthetic mode (no fake GreyNoise data is generated).
    - Deduplication on IP is handled downstream by the existing dedup module.
    """
    if not ip_list:
        return []

    queried = list(dict.fromkeys(ip_list))[:max_ips]   # deduplicate + cap
    results: List[Dict[str, Any]] = []

    with requests.Session() as session:
        for i, ip in enumerate(queried):
            record = _fetch_one(ip, session, delay=delay_secs)
            if record is not None:
                results.append(record)
            # Enforce rate limit between every request (not just successful ones)
            if i < len(queried) - 1:
                time.sleep(delay_secs)

    return results


if __name__ == "__main__":
    # Quick smoke-test against a known public IP (does not require an API key)
    import json
    test_ips = ["8.8.8.8", "1.1.1.1"]
    print(f"[greynoise] querying {len(test_ips)} IPs (community tier)...")
    records = fetch_greynoise_context(test_ips)
    print(f"[greynoise] got {len(records)} result(s)")
    for r in records:
        print(json.dumps(r, indent=2))
