"""
Generates SYNTHETIC data in the exact raw JSON shape the real NVD 2.0 and
AbuseIPDB v2 APIs return. This lets the rest of the pipeline (normalize, dedup,
store, feature-engineer, label, train, evaluate, dashboard) be built and tested
end-to-end without internet access.

This is clearly synthetic/offline test data, not a claim of real collected
intelligence -- swap in src/collectors/*.py (unchanged) once you have API keys
and internet access, and the exact same normalize.py code will process real data.
"""
import random
import datetime as dt
from typing import List, Dict, Any

random.seed(42)

CWE_POOL = ["CWE-79", "CWE-89", "CWE-120", "CWE-200", "CWE-287", "CWE-352", "CWE-416", "CWE-787"]
VENDOR_POOL = ["Apache", "Microsoft", "Cisco", "Oracle", "Adobe", "Linux Kernel", "OpenSSL", "Fortinet"]
EXPLOIT_REF_TAGS = ["Exploit", "Third Party Advisory", "Vendor Advisory", "Patch", "Mailing List"]
COUNTRY_POOL = ["US", "CN", "RU", "BR", "IN", "NL", "DE", "VN", "KR", "FR"]
ISP_POOL = ["DigitalOcean LLC", "Amazon.com Inc.", "OVH SAS", "Alibaba Cloud", "Hetzner Online GmbH",
            "China Telecom", "Comcast Cable", "Choopa LLC"]


def _random_date(days_back_max: int) -> str:
    days_back = random.randint(0, days_back_max)
    d = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_back)
    return d.strftime("%Y-%m-%dT%H:%M:%S.000")


def generate_raw_nvd_response(n: int = 300) -> List[Dict[str, Any]]:
    """Mimics NVD API 2.0 'vulnerabilities' list structure."""
    records = []
    for i in range(n):
        cve_id = f"CVE-2025-{10000 + i}"
        base_score = round(random.betavariate(2, 3) * 10, 1)  # skew realistic: more mid/low than 10.0s
        has_exploit_ref = random.random() < 0.18  # ~18% of CVEs have a known public exploit reference
        published = _random_date(365)
        vendor = random.choice(VENDOR_POOL)
        cwe = random.choice(CWE_POOL)

        references = [{"url": f"https://example.com/advisory/{cve_id}", "tags": ["Vendor Advisory"]}]
        if has_exploit_ref:
            references.append({"url": f"https://exploit-db.example.com/{cve_id}", "tags": ["Exploit"]})

        record = {
            "cve": {
                "id": cve_id,
                "published": published,
                "lastModified": published,
                "descriptions": [
                    {"lang": "en",
                     "value": f"A vulnerability in {vendor} product allows remote attackers to "
                              f"trigger {cwe} under certain conditions."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": base_score, "baseSeverity":
                            "CRITICAL" if base_score >= 9 else "HIGH" if base_score >= 7
                            else "MEDIUM" if base_score >= 4 else "LOW"}}
                    ]
                },
                "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
                "references": references,
                "vendor": vendor,  # not a real NVD top-level field, kept for our own synthetic realism
                "reportCount": random.randint(1, 40),  # synthetic stand-in for citation/reference volume
            }
        }
        records.append(record)
    return records


def generate_raw_abuseipdb_response(n: int = 300) -> List[Dict[str, Any]]:
    """Mimics AbuseIPDB v2 blacklist endpoint 'data' list structure."""
    records = []
    used_ips = set()
    while len(records) < n:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        if ip in used_ips:
            continue
        used_ips.add(ip)

        confidence = int(min(100, max(0, random.betavariate(2, 2) * 100)))
        total_reports = int(random.expovariate(1 / 15)) + 1
        last_reported = _random_date(60)

        record = {
            "ipAddress": ip,
            "abuseConfidenceScore": confidence,
            "totalReports": total_reports,
            "lastReportedAt": last_reported,
            "countryCode": random.choice(COUNTRY_POOL),
            "isp": random.choice(ISP_POOL),
            "domain": None,
            "isWhitelisted": False,
        }
        records.append(record)
    return records


if __name__ == "__main__":
    cves = generate_raw_nvd_response(20)
    ips = generate_raw_abuseipdb_response(20)
    print("Sample CVE record:\n", cves[0])
    print("\nSample IP record:\n", ips[0])
