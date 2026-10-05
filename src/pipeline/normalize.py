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


def normalize_greynoise_record(raw: Dict[str, Any]) -> NormalizedThreat:
    """
    Map a raw GreyNoise community API response to NormalizedThreat.

    GreyNoise classifies IPs as 'malicious' | 'benign' | 'unknown'.
    Only 'malicious' records should normally be passed here (the caller
    filters on classification), but we handle all values defensively.

    Severity mapping (0–10 scale):
      malicious → 7.0   (high confidence malicious actor)
      unknown   → 3.0   (insufficient signal)
      benign    → 0.5   (listed but not malicious — edge case)
    """
    ip            = raw.get("ip") or raw.get("_queried_ip", "unknown")
    classification= raw.get("classification", "unknown").lower()
    noise         = bool(raw.get("noise", False))
    riot          = bool(raw.get("riot", False))   # part of known-good infrastructure list
    name          = raw.get("name") or "unknown"
    last_seen     = raw.get("last_seen", "")
    message       = raw.get("message", "")
    link          = raw.get("link", "")

    # Convert last_seen date string "YYYY-MM-DD" to ISO datetime if needed
    if last_seen and len(last_seen) == 10:
        last_seen = last_seen + "T00:00:00.000"

    SEVERITY_MAP = {"malicious": 7.0, "unknown": 3.0, "benign": 0.5}
    severity_raw = SEVERITY_MAP.get(classification, 3.0)

    description = (
        message
        or f"IP {ip} classified as {classification} by GreyNoise"
        + (f" (actor: {name})" if name != "unknown" else "")
        + (" [internet noise]" if noise else "")
        + (" [RIOT — known-good infrastructure]" if riot else "")
        + "."
    )

    return NormalizedThreat(
        id=ip,
        threat_type="malicious_ip",
        title=f"Malicious IP {ip}",
        description=description[:500],
        severity_raw=severity_raw,
        report_count=1,          # GreyNoise community doesn't expose a report count
        first_seen=last_seen,    # community tier only provides last_seen
        last_seen=last_seen,
        source="greynoise",
        source_reliability=SOURCE_RELIABILITY["greynoise"],
        exploited_flag=False,    # not a meaningful concept for this source
        extra={
            "classification": classification,
            "noise":          noise,
            "riot":           riot,
            "actor_name":     name,
            "greynoise_link": link,
        },
    )


def _extract_cwe(cve: Dict[str, Any]) -> str:
    weaknesses = cve.get("weaknesses", [])
    if weaknesses:
        for desc in weaknesses[0].get("description", []):
            if desc.get("lang") == "en":
                return desc.get("value", "unknown")
    return "unknown"


def normalize_batch(
    raw_nvd: List[Dict[str, Any]],
    raw_abuseipdb: List[Dict[str, Any]],
    raw_greynoise: List[Dict[str, Any]] | None = None,
) -> List[NormalizedThreat]:
    """
    Normalize records from all sources into a single list of NormalizedThreat.

    Parameters
    ----------
    raw_nvd        : list of raw NVD v2.0 vulnerability dicts
    raw_abuseipdb  : list of raw AbuseIPDB blacklist dicts
    raw_greynoise  : list of raw GreyNoise community dicts (Phase 7, optional)
                     Only 'malicious' classified IPs are normalized; others skipped.
    """
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
    for r in (raw_greynoise or []):
        try:
            # Only normalize IPs GreyNoise classifies as malicious
            if r.get("classification", "").lower() != "malicious":
                continue
            normalized.append(normalize_greynoise_record(r))
        except (KeyError, TypeError, IndexError) as e:
            print(f"[normalize] skipping malformed GreyNoise record: {e}")
    return normalized
