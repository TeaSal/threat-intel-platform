"""
AI-Generated Threat Summaries — Phase 2
========================================

Generates concise, analyst-friendly summaries for every threat record.

APPROACH: Deterministic template-based NLP
-------------------------------------------
We deliberately do NOT use an external LLM API (e.g. OpenAI GPT) for the
following reasons:
  - Reproducibility: same input always produces the same summary.
  - Offline capability: no internet required after pipeline collection.
  - No API cost or key management.
  - No hallucination risk: every sentence is derived strictly from the
    structured fields in the database record.
  - Suitable for an academic prototype that must be demonstrable without
    a paid subscription.

If an LLM integration is ever added (e.g. via the OPENAI_API_KEY env var),
it should be an OPTIONAL enhancement layered on top of this module, falling
back to the template summary when the key is absent or the call fails.

WHAT EACH SUMMARY COVERS (per the Phase 2 spec):
  1. What the threat is
  2. Why it matters
  3. Severity level
  4. Exploitation status
  5. Relevant indicators (source, report count, recency, CWE, country)
  6. Why it received its priority (feature contributions)
  7. Recommended analyst attention

OUTPUT FORMAT:
  Plain text with section headers using markdown bold (**Section:**).
  Stored in the `ai_summary` column of the threats table.
  Rendered as rich markdown in the dashboard.
"""

import json
import math
import datetime as dt
from typing import Optional

# ── CWE human-readable descriptions ──────────────────────────────────────────
# Used to turn machine codes like "CWE-89" into readable analyst language.
CWE_DESCRIPTIONS = {
    "CWE-78":  "OS Command Injection",
    "CWE-89":  "SQL Injection",
    "CWE-94":  "Code Injection",
    "CWE-77":  "Command Injection",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-434": "Unrestricted File Upload",
    "CWE-611": "XML External Entity (XXE) Injection",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-287": "Improper Authentication",
    "CWE-200": "Sensitive Information Exposure",
    "CWE-22":  "Path Traversal",
    "CWE-416": "Use-After-Free Memory Corruption",
    "CWE-787": "Out-of-Bounds Memory Write",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-125": "Out-of-Bounds Memory Read",
    "CWE-269": "Improper Privilege Management",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-362": "Race Condition",
}

# High-risk countries (same set as labeling.py / feature_engineering.py)
HIGH_RISK_COUNTRIES = {
    "CN": "China", "RU": "Russia", "BR": "Brazil", "IN": "India",
    "VN": "Vietnam", "KR": "South Korea", "UA": "Ukraine", "TR": "Turkey",
    "IR": "Iran", "PK": "Pakistan", "ID": "Indonesia", "TH": "Thailand",
    "NG": "Nigeria", "BD": "Bangladesh", "PH": "Philippines",
}

RECENCY_HALF_LIFE_DAYS = 30  # mirror of feature_engineering.py


def _parse_extra(extra_json) -> dict:
    if not extra_json:
        return {}
    if isinstance(extra_json, dict):
        return extra_json
    try:
        return json.loads(extra_json)
    except (ValueError, TypeError):
        return {}


def _recency_label(last_seen: str) -> str:
    """Convert a last_seen ISO string into an analyst-friendly recency phrase."""
    if not last_seen:
        return "an unknown date"
    try:
        cleaned = last_seen.replace("Z", "+00:00")
        d = dt.datetime.fromisoformat(cleaned)
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        age_days = (dt.datetime.now(dt.timezone.utc) - d).days
        if age_days == 0:
            return "today"
        if age_days == 1:
            return "yesterday"
        if age_days <= 7:
            return f"{age_days} days ago"
        if age_days <= 30:
            return f"{age_days // 7} week{'s' if age_days >= 14 else ''} ago"
        if age_days <= 365:
            return f"{age_days // 30} month{'s' if age_days >= 60 else ''} ago"
        return f"over {age_days // 365} year{'s' if age_days >= 730 else ''} ago"
    except (ValueError, TypeError):
        return "an unknown date"


def _severity_band(severity_raw: float) -> tuple[str, str]:
    """Returns (band_label, risk_description) for a 0-10 severity score."""
    if severity_raw >= 9.0:
        return "Critical (9.0–10.0)", (
            "This represents the highest possible risk. Exploitation typically allows "
            "unauthenticated remote code execution, complete system compromise, or "
            "widespread data destruction with no user interaction required."
        )
    if severity_raw >= 7.0:
        return "High (7.0–8.9)", (
            "This represents a serious risk. Successful exploitation could allow "
            "significant data exposure, privilege escalation, or service disruption. "
            "Prompt remediation is recommended."
        )
    if severity_raw >= 4.0:
        return "Medium (4.0–6.9)", (
            "This represents a moderate risk. Exploitation may require specific "
            "conditions (e.g. authenticated access, local network position) but "
            "could still lead to meaningful impact if conditions are met."
        )
    if severity_raw >= 0.1:
        return "Low (0.1–3.9)", (
            "This represents a limited risk under normal conditions. Exploitation "
            "is typically difficult, requires significant attacker prerequisites, "
            "or results in minimal impact."
        )
    return "Informational (0.0)", (
        "No severity score is available. This record may be newly catalogued "
        "or represent a threat type for which scoring is not applicable."
    )


def _priority_explanation(row: dict, extra: dict) -> str:
    """
    Explains in plain English why this threat received its ML-predicted priority.
    Derives reasons from the same features the ML model trained on, so the
    explanation is consistent with the model's decision — not fabricated.
    """
    reasons = []

    sev = float(row.get("severity_raw") or 0)
    if sev >= 9.0:
        reasons.append(f"a very high severity score of {sev}/10")
    elif sev >= 7.0:
        reasons.append(f"an elevated severity score of {sev}/10")
    elif sev >= 4.0:
        reasons.append(f"a moderate severity score of {sev}/10")
    else:
        reasons.append(f"a low severity score of {sev}/10")

    if int(row.get("exploited_flag") or 0):
        reasons.append("confirmed exploitation evidence in the available data")

    report_count = int(row.get("report_count") or 0)
    if report_count >= 50:
        reasons.append(f"a very high report/reference count ({report_count}), "
                       "indicating widespread attention from the security community")
    elif report_count >= 10:
        reasons.append(f"a notable report/reference count of {report_count}")

    cwe = extra.get("cwe", "unknown")
    if cwe and cwe not in ("unknown", "NVD-CWE-Other", "NVD-CWE-noinfo"):
        cwe_name = CWE_DESCRIPTIONS.get(cwe, cwe)
        reasons.append(f"association with the {cwe_name} weakness class ({cwe})")

    ref_count = int(extra.get("reference_count") or 0)
    if ref_count >= 10:
        reasons.append(
            f"{ref_count} advisory references, suggesting broad industry awareness "
            "of this vulnerability"
        )

    country = extra.get("country_code", "")
    if country in HIGH_RISK_COUNTRIES and sev >= 4.0:
        reasons.append(
            f"origin from {HIGH_RISK_COUNTRIES[country]} ({country}), a region "
            "statistically over-represented in abuse intelligence reports"
        )

    src_rel = float(row.get("source_reliability") or 0.5)
    if src_rel >= 0.85:
        reasons.append(
            f"a high source reliability rating ({src_rel:.0%}), as this record "
            "comes from an authoritative, formally maintained data source"
        )

    if not reasons:
        return "Insufficient feature data to provide a detailed priority explanation."

    if len(reasons) == 1:
        return f"This threat received its priority primarily due to {reasons[0]}."

    joined = "; ".join(reasons[:-1]) + f"; and {reasons[-1]}"
    return f"This threat received its priority based on: {joined}."


def generate_cve_summary(row: dict) -> str:
    """Generate a structured analyst summary for a CVE record."""
    extra    = _parse_extra(row.get("extra_json"))
    cve_id   = row.get("id", "Unknown CVE")
    sev_raw  = float(row.get("severity_raw") or 0)
    priority = row.get("predicted_priority") or row.get("heuristic_label") or "Unknown"
    exploited = bool(int(row.get("exploited_flag") or 0))
    last_seen = row.get("last_seen", "")
    description = (row.get("description") or "").strip()
    vendor    = extra.get("vendor", "an unspecified vendor")
    cwe       = extra.get("cwe", "unknown")
    ref_count = int(extra.get("reference_count") or 0)
    report_count = int(row.get("report_count") or 0)

    cwe_name  = CWE_DESCRIPTIONS.get(cwe, cwe) if cwe not in ("unknown", "NVD-CWE-Other", "NVD-CWE-noinfo") else None
    sev_band, sev_desc = _severity_band(sev_raw)
    recency   = _recency_label(last_seen)

    lines = []

    # ── 1. What the threat is ──
    what = f"**{cve_id}** is a formally catalogued software vulnerability"
    if vendor and vendor != "unknown":
        what += f" affecting {vendor} products"
    if cwe_name:
        what += f", classified under the {cwe_name} weakness category ({cwe})"
    what += "."
    if description:
        # Trim to first 2 sentences for readability
        sentences = description.replace("...", "…").split(". ")
        short_desc = ". ".join(sentences[:2]).strip()
        if short_desc and not short_desc.endswith("."):
            short_desc += "."
        what += f" {short_desc}"
    lines.append("**What this threat is:**\n" + what)

    # ── 2. Why it matters ──
    why = sev_desc
    if cwe_name:
        why += (
            f" The {cwe_name} weakness class is frequently targeted by attackers "
            "because it often allows direct control over application behaviour or "
            "unauthorised access to sensitive resources."
        )
    if ref_count >= 5:
        why += (
            f" With {ref_count} advisory references, this vulnerability has attracted "
            "broad attention from security researchers and vendors."
        )
    lines.append("**Why it matters:**\n" + why)

    # ── 3. Severity ──
    lines.append(
        f"**Severity:** {sev_band} (score: {sev_raw}/10)\n"
        f"CVSS base score as reported by NVD. "
        f"This score reflects the worst-case impact under the most favourable "
        f"attacker conditions and should be contextualised against your environment."
    )

    # ── 4. Exploitation status ──
    if exploited:
        exploit_text = (
            "**Exploitation status:** Active exploitation evidence detected.\n"
            "At least one public exploit reference has been identified for this CVE "
            "(e.g. Exploit-DB, third-party PoC). This significantly increases urgency — "
            "the vulnerability is not merely theoretical."
        )
    else:
        exploit_text = (
            "**Exploitation status:** No exploitation evidence in current data.\n"
            "No public exploit references were identified at collection time. "
            "This may change as the vulnerability matures — monitor NVD references "
            "and threat intelligence feeds for updates."
        )
    lines.append(exploit_text)

    # ── 5. Relevant indicators ──
    indicators = []
    indicators.append(f"Source: NVD (National Vulnerability Database) — reliability 90%")
    indicators.append(f"Last updated: {recency}")
    if report_count:
        indicators.append(f"Reference/report count: {report_count}")
    if cwe_name:
        indicators.append(f"Weakness class: {cwe_name} ({cwe})")
    if ref_count:
        indicators.append(f"Advisory references: {ref_count}")
    lines.append(
        "**Relevant indicators:**\n" + "\n".join(f"- {i}" for i in indicators)
    )

    # ── 6. Priority explanation ──
    lines.append(
        f"**Priority assigned:** {priority}\n"
        + _priority_explanation(row, extra)
    )

    # ── 7. Analyst recommendation ──
    if priority == "Critical" or (priority == "High" and exploited):
        rec = (
            "**Analyst recommendation:** ESCALATE IMMEDIATELY.\n"
            "Cross-reference this CVE against your asset inventory and patch management "
            "system. If affected software is present in your environment, treat this as "
            "a P1 incident. Apply vendor patches or mitigations without delay. "
            "If no patch is available, implement compensating controls (WAF rules, "
            "network segmentation, or temporary service suspension)."
        )
    elif priority == "High":
        rec = (
            "**Analyst recommendation:** Review within 24–48 hours.\n"
            "Identify whether affected software versions are deployed in your environment. "
            "Prioritise patching in the next maintenance window. Monitor for exploitation "
            "indicators in your SIEM or EDR."
        )
    elif priority == "Medium":
        rec = (
            "**Analyst recommendation:** Schedule for routine patching.\n"
            "Add to the standard vulnerability management backlog. Monitor for any "
            "change in exploitation status that would elevate this to High priority."
        )
    else:
        rec = (
            "**Analyst recommendation:** Monitor and track.\n"
            "Log for awareness. No immediate action required unless this CVE affects "
            "a high-value asset in your environment."
        )
    lines.append(rec)

    return "\n\n".join(lines)


def generate_ip_summary(row: dict) -> str:
    """Generate a structured analyst summary for a malicious IP record."""
    extra      = _parse_extra(row.get("extra_json"))
    ip         = row.get("id", "Unknown IP")
    sev_raw    = float(row.get("severity_raw") or 0)
    priority   = row.get("predicted_priority") or row.get("heuristic_label") or "Unknown"
    last_seen  = row.get("last_seen", "")
    report_count = int(row.get("report_count") or 0)
    country_code = extra.get("country_code", "")
    isp          = extra.get("isp", "")
    src_rel      = float(row.get("source_reliability") or 0.6)

    # AbuseIPDB confidence is stored as severity_raw scaled to 0–10
    confidence_pct = round(sev_raw * 10)
    country_name   = HIGH_RISK_COUNTRIES.get(country_code, country_code or "an unspecified country")
    sev_band, sev_desc = _severity_band(sev_raw)
    recency = _recency_label(last_seen)
    is_high_risk_country = country_code in HIGH_RISK_COUNTRIES

    lines = []

    # ── 1. What the threat is ──
    what = (
        f"**{ip}** is an IP address flagged on the AbuseIPDB community blacklist "
        f"with a {confidence_pct}% abuse confidence score"
    )
    if country_name:
        what += f", geolocated to {country_name}"
    if isp:
        what += f" (ISP: {isp})"
    what += (
        f". It has been independently reported {report_count} time{'s' if report_count != 1 else ''} "
        f"by members of the AbuseIPDB community."
    )
    lines.append("**What this threat is:**\n" + what)

    # ── 2. Why it matters ──
    why = (
        f"A {confidence_pct}% confidence score means a significant proportion of "
        f"independent reporters agree this IP is engaged in abusive activity. "
        "Common behaviours reported for IPs at this confidence level include "
        "port scanning, brute-force login attempts, DDoS participation, spam "
        "relay, and command-and-control beaconing."
    )
    if is_high_risk_country:
        why += (
            f" Additionally, {country_name} is statistically over-represented in "
            "global abuse intelligence data, increasing the contextual risk of "
            "traffic originating from this address."
        )
    if report_count >= 100:
        why += (
            f" The high report volume ({report_count} reports) indicates sustained "
            "and repeated abusive behaviour rather than a one-off incident."
        )
    lines.append("**Why it matters:**\n" + why)

    # ── 3. Severity ──
    lines.append(
        f"**Severity:** {sev_band} (AbuseIPDB confidence: {confidence_pct}%)\n"
        "Severity is derived by rescaling AbuseIPDB's 0–100 confidence score to "
        "the platform's common 0–10 scale. A higher score reflects greater "
        "community consensus that this IP is actively malicious."
    )

    # ── 4. Exploitation status ──
    lines.append(
        "**Exploitation status:** Not applicable for IP-type threats.\n"
        "AbuseIPDB records reflect observed network-level abuse rather than "
        "software vulnerabilities. The relevant risk indicator is the confidence "
        "score and report count, not an exploit reference."
    )

    # ── 5. Relevant indicators ──
    indicators = [
        f"Source: AbuseIPDB — community reliability {int(src_rel * 100)}%",
        f"Last reported: {recency}",
        f"Total independent reports: {report_count}",
        f"Abuse confidence: {confidence_pct}%",
    ]
    if country_name:
        indicators.append(f"Origin country: {country_name} ({country_code})" + (" — high-risk region" if is_high_risk_country else ""))
    if isp:
        indicators.append(f"ISP/ASN: {isp}")
    lines.append(
        "**Relevant indicators:**\n" + "\n".join(f"- {i}" for i in indicators)
    )

    # ── 6. Priority explanation ──
    lines.append(
        f"**Priority assigned:** {priority}\n"
        + _priority_explanation(row, extra)
    )

    # ── 7. Analyst recommendation ──
    if priority == "Critical":
        rec = (
            "**Analyst recommendation:** BLOCK IMMEDIATELY.\n"
            "Add this IP to your perimeter firewall deny-list and WAF blocklist. "
            "Review firewall logs for any past connections from this address. "
            "If connections are found, investigate affected hosts for signs of "
            "compromise or data exfiltration."
        )
    elif priority == "High":
        rec = (
            "**Analyst recommendation:** Block and investigate within 24 hours.\n"
            "Add to firewall and IDS/IPS block rules. Search SIEM logs for "
            "historical connections from this IP across all monitored assets."
        )
    elif priority == "Medium":
        rec = (
            "**Analyst recommendation:** Add to watch-list and consider blocking.\n"
            "Evaluate whether this IP has appeared in any recent connection logs. "
            "Apply blocking in high-sensitivity environments; monitor in others."
        )
    else:
        rec = (
            "**Analyst recommendation:** Log and monitor.\n"
            "The current confidence score does not warrant immediate action. "
            "Retain for correlation with future reports or SIEM alerts."
        )
    lines.append(rec)

    return "\n\n".join(lines)


def generate_summary(row: dict) -> str:
    """
    Dispatcher: routes to the correct generator based on threat_type.
    Returns a plain-text markdown summary string.
    """
    threat_type = row.get("threat_type", "")
    if threat_type == "cve":
        return generate_cve_summary(row)
    if threat_type == "malicious_ip":
        return generate_ip_summary(row)
    # Fallback for future threat types
    return (
        f"**{row.get('id', 'Unknown')}** — threat type '{threat_type}' "
        "does not yet have a dedicated summary template. "
        f"Severity: {row.get('severity_raw', 'N/A')}/10. "
        f"Priority: {row.get('predicted_priority', 'N/A')}."
    )


def generate_all_summaries(rows: list) -> dict:
    """
    Generate summaries for all threat records.

    Parameters
    ----------
    rows : list of dicts as returned by db.fetch_all_as_dicts()

    Returns
    -------
    id_to_summary : dict {threat_id: summary_text}
    """
    id_to_summary = {}
    for row in rows:
        tid = row.get("id")
        if tid:
            id_to_summary[tid] = generate_summary(row)
    return id_to_summary


if __name__ == "__main__":
    from src.pipeline import db

    rows = db.fetch_all_as_dicts()
    if not rows:
        print("No records in DB. Run the pipeline first.")
    else:
        # Print a sample summary for the first CVE and first IP
        cves = [r for r in rows if r.get("threat_type") == "cve"]
        ips  = [r for r in rows if r.get("threat_type") == "malicious_ip"]
        if cves:
            print("=" * 70)
            print("SAMPLE CVE SUMMARY")
            print("=" * 70)
            print(generate_cve_summary(cves[0]))
        if ips:
            print("\n" + "=" * 70)
            print("SAMPLE IP SUMMARY")
            print("=" * 70)
            print(generate_ip_summary(ips[0]))
