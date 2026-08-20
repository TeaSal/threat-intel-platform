"""
Maps raw, source-specific JSON (from either the real collectors or the
synthetic generator, which mimics the same shapes) into the COMMON SCHEMA
defined in src/schema.py.

This is the one place that needs to change when a new source is added.
Everything downstream (dedup, db, feature_engineering, labeling) only ever
sees NormalizedThreat objects and doesn't know or care which source they
came from.
"""
from typing import List, Dict, Any
import datetime as dt

from src.schema import NormalizedThreat
from src.config import SOURCE_RELIABILITY


def normalize_nvd_record(raw: Dict[str, Any]) -> NormalizedThreat:
    cve = raw["cve"]
    cve_id = cve["id"]

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    base_score = 0.0
    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        base_score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", 0.0)
    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
        base_score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", 0.0)
    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        base_score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", 0.0)

    references = cve.get("references", [])
    exploited_flag = any("Exploit" in ref.get("tags", []) for ref in references)

    report_count = cve.get("reportCount", len(references))  # fall back to reference count

    published = cve.get("published", "")
    last_modified = cve.get("lastModified", published)

    return NormalizedThreat(
        id=cve_id,
        threat_type="cve",
        title=cve_id,
        description=description[:500],
        severity_raw=float(base_score),          # already 0-10, matches our common scale
        report_count=int(report_count),
        first_seen=published,
        last_seen=last_modified,
        source="nvd",
        source_reliability=SOURCE_RELIABILITY["nvd"],
        exploited_flag=exploited_flag,
        extra={
            "vendor": cve.get("vendor", "unknown"),
            "cwe": _extract_cwe(cve),
            "reference_count": len(references),
        },
    )


def normalize_abuseipdb_record(raw: Dict[str, Any]) -> NormalizedThreat:
    ip = raw["ipAddress"]
    confidence = raw.get("abuseConfidenceScore", 0)
    total_reports = raw.get("totalReports", 0)
    last_reported = raw.get("lastReportedAt", "")

    # rescale AbuseIPDB's 0-100 confidence to our common 0-10 severity scale
    severity_raw = round((confidence / 100.0) * 10, 2)

    return NormalizedThreat(
        id=ip,
        threat_type="malicious_ip",
        title=f"Malicious IP {ip}",
        description=f"IP reported {total_reports} times with {confidence}% abuse confidence.",
        severity_raw=severity_raw,
        report_count=int(total_reports),
        first_seen=last_reported,   # blacklist endpoint doesn't give first-seen; best available proxy
        last_seen=last_reported,
        source="abuseipdb",
        source_reliability=SOURCE_RELIABILITY["abuseipdb"],
        exploited_flag=False,       # not a meaningful concept for this source/type
        extra={
            "country_code": raw.get("countryCode"),
            "isp": raw.get("isp"),
        },
    )


def _extract_cwe(cve: Dict[str, Any]) -> str:
    weaknesses = cve.get("weaknesses", [])
    if weaknesses:
        for desc in weaknesses[0].get("description", []):
            if desc.get("lang") == "en":
                return desc.get("value", "unknown")
    return "unknown"


def normalize_batch(raw_nvd: List[Dict[str, Any]], raw_abuseipdb: List[Dict[str, Any]]) -> List[NormalizedThreat]:
    normalized = []
    for r in raw_nvd:
        try:
            normalized.append(normalize_nvd_record(r))
        except (KeyError, TypeError, IndexError) as e:
            print(f"[normalize] skipping malformed NVD record: {e}")
    for r in raw_abuseipdb:
        try:
            normalized.append(normalize_abuseipdb_record(r))
        except (KeyError, TypeError, IndexError) as e:
            print(f"[normalize] skipping malformed AbuseIPDB record: {e}")
    return normalized
