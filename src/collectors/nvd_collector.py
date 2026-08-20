"""
Real collector for the NVD CVE API 2.0.

Docs: https://nvd.nist.gov/developers/vulnerabilities
Requires no API key for light use, but an API key raises the rate limit
substantially (5 req/30s -> 50 req/30s) and is free to request.

This module returns RAW API responses (unmodified NVD JSON) — normalization
happens separately in src/pipeline/normalize.py, so this file's only job is
talking to the API correctly.
"""
import time
import requests
from typing import List, Dict, Any

from src import config


def fetch_recent_cves(pages: int = None, results_per_page: int = None) -> List[Dict[str, Any]]:
    """
    Fetch recently published CVEs from the NVD API, paginated.

    Returns a list of raw "vulnerability" objects exactly as NVD returns them,
    i.e. each item looks like: {"cve": {"id": ..., "descriptions": [...], "metrics": {...}, ...}}

    NOTE: requires internet access. Not runnable in this sandbox.
    """
    pages = pages or config.NVD_PAGES_TO_FETCH
    results_per_page = results_per_page or config.NVD_RESULTS_PER_PAGE

    headers = {
        # NVD blocks the default python-requests User-Agent with a 404.
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY

    all_vulnerabilities = []
    start_index = 0

    for _ in range(pages):
        # Build the URL manually to avoid any encoding quirks with requests params
        url = (
            f"{config.NVD_CVE_API_URL}"
            f"?resultsPerPage={results_per_page}&startIndex={start_index}"
        )

        resp = requests.get(url, headers=headers, timeout=30)

        if resp.status_code == 404:
            # NVD occasionally returns 404 for rate-limited unauthenticated requests.
            # Wait and retry once before giving up.
            time.sleep(10)
            resp = requests.get(url, headers=headers, timeout=30)

        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        all_vulnerabilities.extend(vulns)
        start_index += results_per_page

        # NVD rate limit courtesy delay (stricter without an API key)
        time.sleep(6 if not config.NVD_API_KEY else 1)

    return all_vulnerabilities


if __name__ == "__main__":
    results = fetch_recent_cves(pages=1, results_per_page=20)
    print(f"Fetched {len(results)} raw CVE records")
    if results:
        print(results[0])
