"""
Real collector for the AbuseIPDB v2 "blacklist" API.

Docs: https://docs.abuseipdb.com/#blacklist-endpoint
Requires a free API key: https://www.abuseipdb.com/register

This module returns the RAW API response (unmodified AbuseIPDB JSON) —
normalization happens separately in src/pipeline/normalize.py.
"""
import requests
from typing import List, Dict, Any

from src import config


def fetch_malicious_ips(confidence_minimum: int = None, limit: int = None) -> List[Dict[str, Any]]:
    """
    Fetch the AbuseIPDB blacklist: IPs reported with at least `confidence_minimum`
    confidence of abuse.

    Returns a list of raw record dicts exactly as AbuseIPDB returns them, e.g.:
    {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 92, "totalReports": 154,
     "lastReportedAt": "2026-08-01T12:00:00+00:00", "countryCode": "US", ...}

    NOTE: requires internet access and a valid API key. Not runnable in this sandbox.
    """
    if not config.ABUSEIPDB_API_KEY:
        raise RuntimeError(
            "ABUSEIPDB_API_KEY is not set. Get a free key at "
            "https://www.abuseipdb.com/register and put it in your .env file."
        )

    confidence_minimum = confidence_minimum or config.ABUSEIPDB_CONFIDENCE_MINIMUM
    limit = limit or config.ABUSEIPDB_LIMIT

    headers = {
        "Key": config.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "confidenceMinimum": confidence_minimum,
        "limit": limit,
    }

    resp = requests.get(config.ABUSEIPDB_BLACKLIST_URL, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    return data.get("data", [])


if __name__ == "__main__":
    results = fetch_malicious_ips(limit=20)
    print(f"Fetched {len(results)} raw IP records")
    if results:
        print(results[0])
