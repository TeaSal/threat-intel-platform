"""
The COMMON SCHEMA every source gets normalized into.

This is the single most important design artifact in the project: every collector's
raw, source-specific JSON gets mapped into exactly these fields before anything else
(dedup, storage, feature engineering) touches it. Adding a new source later (e.g.
VirusTotal) only requires writing a new mapping into this schema, not changing any
downstream code.

Field notes:
- id: stable natural key. For CVEs, the CVE-ID (e.g. "CVE-2023-12345"). For IPs, the
  IP address itself. This is what deduplication keys on.
- threat_type: "cve" | "malicious_ip"  (extendable later, e.g. "malware_hash")
- severity_raw: the source's own severity/confidence signal, rescaled 0-10 so
  CVSS (0-10) and AbuseIPDB confidence (0-100) are comparable at a glance.
- report_count: how many times this source has seen/reported this indicator.
- first_seen / last_seen: ISO 8601 date strings.
- source: which collector produced this record ("nvd" | "abuseipdb").
- source_reliability: looked up from config.SOURCE_RELIABILITY at normalization time.
- exploited_flag: True if there's a known-exploitation signal (best-effort; for CVEs
  this looks for exploit-related reference tags, since we're not pulling CISA KEV
  separately in this beginner scope).
- extra: a dict of source-specific fields we don't want to throw away, kept as raw
  JSON in the DB for later inspection / dashboard drill-down, but NOT used as ML
  features directly (avoids leaking source-specific quirks into the model).
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any

COMMON_SCHEMA_FIELDS = [
    "id", "threat_type", "title", "description",
    "severity_raw", "report_count", "first_seen", "last_seen",
    "source", "source_reliability", "exploited_flag", "extra",
]


@dataclass
class NormalizedThreat:
    id: str
    threat_type: str          # "cve" | "malicious_ip"
    title: str
    description: str
    severity_raw: float       # rescaled 0-10
    report_count: int
    first_seen: str           # ISO date string
    last_seen: str            # ISO date string
    source: str                # "nvd" | "abuseipdb"
    source_reliability: float
    exploited_flag: bool
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
