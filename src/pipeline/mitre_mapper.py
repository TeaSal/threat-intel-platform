"""
MITRE ATT&CK Mapping Module — Phase 3
=======================================

Maps threat records to MITRE ATT&CK tactics and techniques where a reliable
inference can be made from the available structured data.

DESIGN PHILOSOPHY — CONSERVATIVE MAPPING
------------------------------------------
This module does NOT randomly assign MITRE techniques to every threat.
Doing so would be misleading and academically dishonest.

Instead, mappings are made ONLY when one of the following evidence sources
supports the inference:

  1. CWE code   — The CVE has an assigned weakness class (e.g. CWE-89 = SQL
                   Injection) that has a well-established, documented relationship
                   to a specific MITRE technique. Confidence: HIGH.

  2. Keywords   — The CVE description contains specific technical terms that
                   strongly indicate a particular attack pattern
                   (e.g. "remote code execution", "privilege escalation").
                   Confidence: MEDIUM (keywords can be ambiguous).

  3. Threat type — Malicious IPs (AbuseIPDB records) are inferred as
                   Reconnaissance or Initial Access activity based on the nature
                   of the AbuseIPDB blacklist. Confidence: LOW (we cannot verify
                   exact technique from an IP record alone).

Confidence levels:
  High     — CWE-to-technique mapping (documented MITRE relationship)
  Medium   — Keyword-based inference from description text
  Low      — Threat-type-level inference (broad category only)
  N/A      — Insufficient data for any reliable inference

Sources:
  MITRE ATT&CK Enterprise framework v14 (https://attack.mitre.org/)
  CWE-to-ATT&CK relationships documented in MITRE's own cross-references
  and the CAPEC (Common Attack Pattern Enumeration and Classification) mappings.

IMPORTANT LIMITATIONS:
  - This is heuristic inference from limited structured fields, not a
    full ATT&CK mapping by a trained analyst.
  - A single CVE may enable multiple techniques; we only infer the most
    directly supported ones.
  - IPs do not carry enough information to map beyond broad tactic level.
  - Mappings should be treated as investigative starting points, not
    definitive attributions.
"""

import json
import re
from typing import List, Dict, Any


# ── Data structures ────────────────────────────────────────────────────────────

class MitreMapping:
    """One inferred MITRE ATT&CK technique association for a threat."""
    __slots__ = ("threat_id", "tactic", "technique_id", "technique_name",
                 "confidence", "basis")

    def __init__(self, threat_id: str, tactic: str, technique_id: str,
                 technique_name: str, confidence: str, basis: str):
        self.threat_id      = threat_id
        self.tactic         = tactic
        self.technique_id   = technique_id
        self.technique_name = technique_name
        self.confidence     = confidence   # "High" | "Medium" | "Low"
        self.basis          = basis        # human-readable reason for this mapping

    def to_dict(self) -> dict:
        return {
            "threat_id":      self.threat_id,
            "tactic":         self.tactic,
            "technique_id":   self.technique_id,
            "technique_name": self.technique_name,
            "confidence":     self.confidence,
            "basis":          self.basis,
        }


# ── CWE → ATT&CK technique table ──────────────────────────────────────────────
# Built from:
#   - MITRE ATT&CK official CWE cross-references
#   - CAPEC → ATT&CK mappings
#   - NIST NVD CWE descriptions
#
# Format: CWE_ID → list of (tactic, technique_id, technique_name, basis_note)
# Only CWEs with a clear, well-documented ATT&CK relationship are listed.
# Multiple entries per CWE are possible (e.g. SQLi enables both Credential Access
# and Exfiltration depending on database contents).

CWE_TO_ATTACK: Dict[str, List[tuple]] = {
    # ── Injection weaknesses ────────────────────────────────────────────────
    "CWE-89": [
        ("Initial Access",        "T1190", "Exploit Public-Facing Application",
         "SQL Injection exploits public-facing web applications directly"),
        ("Credential Access",     "T1555", "Credentials from Password Stores",
         "SQL Injection can extract credential tables from databases"),
        ("Exfiltration",          "T1048", "Exfiltration Over Alternative Protocol",
         "SQLi can be used to exfiltrate database contents"),
    ],
    "CWE-78": [
        ("Execution",             "T1059", "Command and Scripting Interpreter",
         "OS Command Injection enables direct command execution on the host"),
        ("Privilege Escalation",  "T1068", "Exploitation for Privilege Escalation",
         "Commands may be executed in elevated context"),
    ],
    "CWE-77": [
        ("Execution",             "T1059", "Command and Scripting Interpreter",
         "Command Injection enables arbitrary command execution"),
    ],
    "CWE-94": [
        ("Execution",             "T1059", "Command and Scripting Interpreter",
         "Code Injection enables arbitrary code execution in the application context"),
        ("Initial Access",        "T1190", "Exploit Public-Facing Application",
         "Code Injection typically targets public-facing services"),
    ],
    # ── Cross-site / web weaknesses ─────────────────────────────────────────
    "CWE-79": [
        ("Credential Access",     "T1539", "Steal Web Session Cookie",
         "XSS is commonly used to steal session tokens via injected script"),
        ("Initial Access",        "T1189", "Drive-by Compromise",
         "Stored XSS can deliver malicious payloads to visiting users"),
    ],
    "CWE-352": [
        ("Credential Access",     "T1539", "Steal Web Session Cookie",
         "CSRF exploits authenticated sessions to perform unauthorised actions"),
        ("Impact",                "T1565", "Data Manipulation",
         "CSRF can force state-changing actions in the victim's context"),
    ],
    # ── Memory corruption ───────────────────────────────────────────────────
    "CWE-787": [
        ("Execution",             "T1203", "Exploitation for Client Execution",
         "Out-of-Bounds Write often leads to arbitrary code execution"),
        ("Privilege Escalation",  "T1068", "Exploitation for Privilege Escalation",
         "Memory corruption can enable kernel or process privilege escalation"),
    ],
    "CWE-120": [
        ("Execution",             "T1203", "Exploitation for Client Execution",
         "Classic Buffer Overflow can allow attacker-controlled code execution"),
        ("Privilege Escalation",  "T1068", "Exploitation for Privilege Escalation",
         "Stack/heap overflows frequently exploited for privilege escalation"),
    ],
    "CWE-125": [
        ("Discovery",             "T1082", "System Information Discovery",
         "Out-of-Bounds Read can leak memory contents including sensitive data"),
        ("Credential Access",     "T1552", "Unsecured Credentials",
         "Memory leaks can expose credentials or cryptographic keys in memory"),
    ],
    "CWE-416": [
        ("Execution",             "T1203", "Exploitation for Client Execution",
         "Use-After-Free vulnerabilities can be used for arbitrary code execution"),
        ("Privilege Escalation",  "T1068", "Exploitation for Privilege Escalation",
         "UAF is a common vector for kernel privilege escalation exploits"),
    ],
    # ── Server-side injection / SSRF ────────────────────────────────────────
    "CWE-918": [
        ("Discovery",             "T1016", "System Network Configuration Discovery",
         "SSRF allows probing of internal network services"),
        ("Initial Access",        "T1190", "Exploit Public-Facing Application",
         "SSRF exploits trust relationships of the server to reach internal resources"),
        ("Credential Access",     "T1552", "Unsecured Credentials",
         "SSRF can be used to retrieve cloud metadata credentials (e.g. AWS IMDSv1)"),
    ],
    "CWE-611": [
        ("Discovery",             "T1083", "File and Directory Discovery",
         "XXE allows reading local files on the server"),
        ("Initial Access",        "T1190", "Exploit Public-Facing Application",
         "XXE targets XML parsers in public-facing applications"),
    ],
    # ── Authentication / access control ─────────────────────────────────────
    "CWE-287": [
        ("Defense Evasion",       "T1078", "Valid Accounts",
         "Improper Authentication may allow attackers to bypass login controls"),
        ("Initial Access",        "T1078", "Valid Accounts",
         "Authentication bypass grants attacker access with no valid credentials"),
    ],
    "CWE-306": [
        ("Initial Access",        "T1078", "Valid Accounts",
         "Missing authentication for critical functions allows direct unauthorised access"),
        ("Lateral Movement",      "T1021", "Remote Services",
         "Unauthenticated remote services enable lateral movement"),
    ],
    "CWE-269": [
        ("Privilege Escalation",  "T1068", "Exploitation for Privilege Escalation",
         "Improper privilege management enables escalation to higher-privilege context"),
        ("Defense Evasion",       "T1548", "Abuse Elevation Control Mechanism",
         "Privilege mismanagement can be abused to bypass security controls"),
    ],
    # ── Information disclosure ───────────────────────────────────────────────
    "CWE-200": [
        ("Collection",            "T1213", "Data from Information Repositories",
         "Information Exposure allows attackers to collect sensitive data"),
        ("Discovery",             "T1082", "System Information Discovery",
         "Exposed information can reveal system details useful for further attack"),
    ],
    # ── Path traversal / file access ────────────────────────────────────────
    "CWE-22": [
        ("Collection",            "T1005", "Data from Local System",
         "Path Traversal allows reading arbitrary files on the server"),
        ("Discovery",             "T1083", "File and Directory Discovery",
         "Directory traversal reveals filesystem structure"),
    ],
    # ── Deserialization ──────────────────────────────────────────────────────
    "CWE-502": [
        ("Execution",             "T1059", "Command and Scripting Interpreter",
         "Unsafe Deserialization commonly leads to remote code execution"),
        ("Initial Access",        "T1190", "Exploit Public-Facing Application",
         "Deserialization vulnerabilities typically target public-facing endpoints"),
    ],
    # ── File upload ─────────────────────────────────────────────────────────
    "CWE-434": [
        ("Execution",             "T1505.003", "Server Software Component: Web Shell",
         "Unrestricted File Upload is the primary vector for web shell deployment"),
        ("Persistence",           "T1505",    "Server Software Component",
         "Uploaded files can establish persistent backdoors on the server"),
    ],
    # ── Race condition ──────────────────────────────────────────────────────
    "CWE-362": [
        ("Privilege Escalation",  "T1068", "Exploitation for Privilege Escalation",
         "Race conditions (TOCTOU) are frequently exploited for kernel privilege escalation"),
    ],
}


# ── Keyword → ATT&CK technique table ─────────────────────────────────────────
# Applied to CVE description text.
# Regex patterns are case-insensitive. Only include patterns that are
# specific enough to have < 5% false-positive rate in security text.
# Confidence: MEDIUM (keyword context can be ambiguous).

KEYWORD_TO_ATTACK: List[tuple] = [
    # pattern, tactic, technique_id, technique_name, basis_note
    (r"remote\s+code\s+exec",
     "Execution",          "T1203", "Exploitation for Client Execution",
     "Description mentions remote code execution"),

    (r"arbitrary\s+code\s+exec",
     "Execution",          "T1203", "Exploitation for Client Execution",
     "Description mentions arbitrary code execution"),

    (r"privilege\s+escal",
     "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation",
     "Description mentions privilege escalation"),

    (r"local\s+privilege\s+escal",
     "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation",
     "Description mentions local privilege escalation"),

    (r"denial.of.service|dos\b",
     "Impact",             "T1499", "Endpoint Denial of Service",
     "Description mentions denial-of-service condition"),

    (r"remote\s+code|unauthenticated.{0,30}exec",
     "Initial Access",     "T1190", "Exploit Public-Facing Application",
     "Description indicates unauthenticated remote exploitation"),

    (r"backdoor|reverse\s+shell|bind\s+shell",
     "Persistence",        "T1505.003", "Server Software Component: Web Shell",
     "Description mentions backdoor or shell implant"),

    (r"information\s+disclos|sensitive\s+data\s+expos|memory\s+leak|heap\s+leak",
     "Collection",         "T1005", "Data from Local System",
     "Description indicates sensitive data disclosure"),

    (r"directory\s+travers|path\s+travers",
     "Collection",         "T1005", "Data from Local System",
     "Description mentions directory/path traversal"),

    (r"authentication\s+bypass|bypass.{0,20}auth",
     "Defense Evasion",    "T1078", "Valid Accounts",
     "Description mentions authentication bypass"),

    (r"cross.site\s+script|xss\b",
     "Credential Access",  "T1539", "Steal Web Session Cookie",
     "Description mentions cross-site scripting"),

    (r"sql\s+inject",
     "Initial Access",     "T1190", "Exploit Public-Facing Application",
     "Description mentions SQL injection"),

    (r"command\s+inject|os\s+command",
     "Execution",          "T1059", "Command and Scripting Interpreter",
     "Description mentions command injection"),

    (r"heap\s+overflow|stack\s+overflow|buffer\s+overflow",
     "Execution",          "T1203", "Exploitation for Client Execution",
     "Description mentions memory overflow condition"),

    (r"use.after.free",
     "Execution",          "T1203", "Exploitation for Client Execution",
     "Description mentions use-after-free memory corruption"),

    (r"deserialization|deserializ",
     "Execution",          "T1059", "Command and Scripting Interpreter",
     "Description mentions unsafe deserialization"),

    (r"server.side\s+request\s+forg|ssrf\b",
     "Discovery",          "T1016", "System Network Configuration Discovery",
     "Description mentions SSRF"),

    (r"xml\s+external\s+entity|xxe\b",
     "Discovery",          "T1083", "File and Directory Discovery",
     "Description mentions XXE"),

    (r"race\s+condition|time.of.check|toctou",
     "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation",
     "Description mentions race condition"),

    (r"credential|password\s+hash|ntlm|kerberos",
     "Credential Access",  "T1552", "Unsecured Credentials",
     "Description references credential-related attack"),

    (r"lateral\s+mov|pivot\b",
     "Lateral Movement",   "T1021", "Remote Services",
     "Description mentions lateral movement"),

    (r"exfiltrat",
     "Exfiltration",       "T1041", "Exfiltration Over C2 Channel",
     "Description mentions data exfiltration"),

    (r"persist\b|persistenc",
     "Persistence",        "T1505", "Server Software Component",
     "Description mentions persistence mechanism"),
]


# ── Malicious IP tactic mappings ─────────────────────────────────────────────
# AbuseIPDB records represent network-level abuse. Without additional context
# (port, protocol, payload) we can only make broad tactic-level inferences.
# Confidence: LOW.

IP_BASE_MAPPINGS = [
    ("Reconnaissance",  "T1595", "Active Scanning",
     "AbuseIPDB blacklisted IPs are commonly associated with automated scanning activity"),
    ("Initial Access",  "T1190", "Exploit Public-Facing Application",
     "Malicious IPs frequently probe for exploitable public-facing services"),
]

# Additional mapping when report count is high — indicates sustained campaign activity
IP_HIGH_VOLUME_MAPPINGS = [
    ("Command and Control", "T1071", "Application Layer Protocol",
     "High report volume suggests sustained C2 or botnet beaconing activity"),
]

# Additional mapping when from high-risk country — geopolitical context only
IP_HIGH_RISK_COUNTRY_MAPPING = (
    "Reconnaissance", "T1589", "Gather Victim Identity Information",
    "High-risk country origin with repeated reporting suggests intelligence-gathering"
)

HIGH_RISK_COUNTRIES = {
    "CN", "RU", "BR", "IN", "VN", "KR", "UA", "TR", "IR", "PK",
    "ID", "TH", "NG", "BD", "PH",
}


# ── Core mapping functions ────────────────────────────────────────────────────

def _parse_extra(extra_json) -> dict:
    if not extra_json:
        return {}
    if isinstance(extra_json, dict):
        return extra_json
    try:
        return json.loads(extra_json)
    except (ValueError, TypeError):
        return {}


def _deduplicate_mappings(mappings: List[MitreMapping]) -> List[MitreMapping]:
    """
    When multiple evidence sources produce the same (threat_id, technique_id),
    keep the one with the highest confidence (High > Medium > Low).
    """
    confidence_rank = {"High": 0, "Medium": 1, "Low": 2}
    best: Dict[str, MitreMapping] = {}
    for m in mappings:
        key = (m.threat_id, m.technique_id)
        existing = best.get(key)
        if existing is None:
            best[key] = m
        elif confidence_rank.get(m.confidence, 99) < confidence_rank.get(existing.confidence, 99):
            best[key] = m   # replace with higher-confidence mapping
    return list(best.values())


def map_cve(row: dict) -> List[MitreMapping]:
    """Produce MITRE mappings for a CVE record."""
    tid   = row["id"]
    extra = _parse_extra(row.get("extra_json"))
    cwe   = extra.get("cwe", "unknown")
    desc  = (row.get("description") or "").lower()
    mappings: List[MitreMapping] = []

    # ── Evidence tier 1: CWE-based (High confidence) ──────────────────────
    if cwe and cwe not in ("unknown", "NVD-CWE-Other", "NVD-CWE-noinfo"):
        entries = CWE_TO_ATTACK.get(cwe, [])
        for tactic, tech_id, tech_name, basis in entries:
            mappings.append(MitreMapping(
                threat_id=tid, tactic=tactic,
                technique_id=tech_id, technique_name=tech_name,
                confidence="High",
                basis=f"CWE-based: {basis} (CWE: {cwe})",
            ))

    # ── Evidence tier 2: Keyword-based (Medium confidence) ────────────────
    if desc:
        seen_tech_ids = {m.technique_id for m in mappings}
        for pattern, tactic, tech_id, tech_name, basis in KEYWORD_TO_ATTACK:
            # Skip if this technique already covered by higher-confidence CWE match
            if tech_id in seen_tech_ids:
                continue
            if re.search(pattern, desc, re.IGNORECASE):
                mappings.append(MitreMapping(
                    threat_id=tid, tactic=tactic,
                    technique_id=tech_id, technique_name=tech_name,
                    confidence="Medium",
                    basis=f"Keyword-based: {basis}",
                ))
                seen_tech_ids.add(tech_id)

    return _deduplicate_mappings(mappings)


def map_ip(row: dict) -> List[MitreMapping]:
    """Produce MITRE mappings for a malicious IP record."""
    tid          = row["id"]
    extra        = _parse_extra(row.get("extra_json"))
    country_code = extra.get("country_code", "")
    report_count = int(row.get("report_count") or 0)
    mappings: List[MitreMapping] = []

    # Base mappings — apply to all blacklisted IPs
    for tactic, tech_id, tech_name, basis in IP_BASE_MAPPINGS:
        mappings.append(MitreMapping(
            threat_id=tid, tactic=tactic,
            technique_id=tech_id, technique_name=tech_name,
            confidence="Low",
            basis=f"IP-type inference: {basis}",
        ))

    # High volume — suggests automated/botnet activity
    if report_count >= 20:
        for tactic, tech_id, tech_name, basis in IP_HIGH_VOLUME_MAPPINGS:
            mappings.append(MitreMapping(
                threat_id=tid, tactic=tactic,
                technique_id=tech_id, technique_name=tech_name,
                confidence="Low",
                basis=f"High report volume ({report_count} reports): {basis}",
            ))

    # High-risk country — adds geo-context mapping
    if country_code in HIGH_RISK_COUNTRIES:
        tactic, tech_id, tech_name, basis = IP_HIGH_RISK_COUNTRY_MAPPING
        mappings.append(MitreMapping(
            threat_id=tid, tactic=tactic,
            technique_id=tech_id, technique_name=tech_name,
            confidence="Low",
            basis=f"Geographic inference ({country_code}): {basis}",
        ))

    return _deduplicate_mappings(mappings)


def map_threat(row: dict) -> List[MitreMapping]:
    """Dispatcher: routes to correct mapper based on threat_type."""
    threat_type = row.get("threat_type", "")
    if threat_type == "cve":
        return map_cve(row)
    if threat_type == "malicious_ip":
        return map_ip(row)
    return []   # unknown type — no mapping produced


def map_all_threats(rows: list) -> tuple[List[dict], dict]:
    """
    Map all threat records and return:
      - all_mappings_as_dicts : list of dicts ready for db.upsert_mitre_mappings()
      - stats                 : summary dict for pipeline logging

    Parameters
    ----------
    rows : list of dicts from db.fetch_all_as_dicts()
    """
    all_mappings: List[MitreMapping] = []
    n_mapped   = 0
    n_unmapped = 0

    for row in rows:
        ms = map_threat(row)
        if ms:
            all_mappings.extend(ms)
            n_mapped += 1
        else:
            n_unmapped += 1

    # Aggregate stats
    tactic_counts: Dict[str, int] = {}
    tech_counts:   Dict[str, int] = {}
    conf_counts:   Dict[str, int] = {"High": 0, "Medium": 0, "Low": 0}

    for m in all_mappings:
        tactic_counts[m.tactic]         = tactic_counts.get(m.tactic, 0) + 1
        tech_counts[m.technique_id]      = tech_counts.get(m.technique_id, 0) + 1
        conf_counts[m.confidence]        = conf_counts.get(m.confidence, 0) + 1

    stats = {
        "total_mappings": len(all_mappings),
        "threats_mapped":   n_mapped,
        "threats_unmapped": n_unmapped,
        "by_confidence":    conf_counts,
        "top_tactics":      sorted(tactic_counts.items(), key=lambda x: -x[1])[:5],
        "top_techniques":   sorted(tech_counts.items(),   key=lambda x: -x[1])[:5],
    }

    return [m.to_dict() for m in all_mappings], stats


if __name__ == "__main__":
    from src.pipeline import db

    rows = db.fetch_all_as_dicts()
    if not rows:
        print("No records in DB. Run the pipeline first.")
    else:
        mappings, stats = map_all_threats(rows)
        print(f"Total mappings produced : {stats['total_mappings']}")
        print(f"Threats mapped          : {stats['threats_mapped']}")
        print(f"Threats unmapped        : {stats['threats_unmapped']}")
        print(f"By confidence           : {stats['by_confidence']}")
        print(f"Top tactics             : {stats['top_tactics']}")
        print(f"Top techniques          : {stats['top_techniques']}")

        # Show a sample CVE mapping
        cve_row = next((r for r in rows if r["threat_type"] == "cve"), None)
        if cve_row:
            print(f"\nSample CVE: {cve_row['id']}")
            for m in map_cve(cve_row):
                print(f"  [{m.confidence:6}] {m.tactic:25} {m.technique_id:12} {m.technique_name}")
                print(f"           Basis: {m.basis}")
