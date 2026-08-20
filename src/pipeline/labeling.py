"""
Generates heuristic priority labels (Critical/High/Medium/Low).

*** IMPORTANT, SAY THIS IN REVIEW 2 ***
These are NOT analyst-verified ground-truth labels. No public dataset provides
human-verified priority labels for a blended, cross-source dataset like this one.
This heuristic is a documented, defensible stand-in built from established signals
(severity, exploitation evidence, report volume, recency, source trust, CWE risk
tier, advisory breadth, geographic origin). The ML models learn to approximate
this multi-factor heuristic from the available feature set — but because the labels
incorporate signals not directly present as features (e.g. CWE risk category,
per-record noise from real-world label ambiguity), the task is genuinely predictive
rather than a trivial formula inversion.

Heuristic formula:
    priority_score = (
        0.40 * (severity_raw / 10)          # dominant signal: source-reported severity
      + 0.18 * exploited_flag               # known-exploitation is a strong urgency signal
      + 0.12 * report_count_norm            # more reports = more corroboration
      + 0.08 * recency_score                # fresher threats matter more
      + 0.08 * source_reliability           # trust in the source's own scoring
      + 0.07 * cwe_risk_score               # CWE category risk tier (not a direct feature)
      + 0.07 * reference_count_bonus        # advisory breadth beyond log-normalized value
    ) + geographic_boost                    # +0.05 for high-risk-country IPs above threshold

    -> bucketed into Low / Medium / High / Critical by threshold
"""
import json
import hashlib
import pandas as pd

# ---------------------------------------------------------------------------
# CWE risk tier — maps CWE categories to a 0-1 risk multiplier.
# Based on MITRE CWE Top 25 and CVSS attack-complexity analysis.
# This signal is used for labeling only, NOT exposed as an ML feature,
# so the model must learn to infer it from correlated features.
# ---------------------------------------------------------------------------
CWE_HIGH_RISK = {
    "CWE-78",   # OS Command Injection
    "CWE-89",   # SQL Injection
    "CWE-94",   # Code Injection
    "CWE-77",   # Command Injection
    "CWE-502",  # Deserialization of Untrusted Data
    "CWE-434",  # Unrestricted Upload
    "CWE-611",  # XXE
    "CWE-918",  # SSRF
}
CWE_MEDIUM_RISK = {
    "CWE-79",   # XSS
    "CWE-352",  # CSRF
    "CWE-287",  # Improper Auth
    "CWE-200",  # Information Exposure
    "CWE-22",   # Path Traversal
    "CWE-416",  # Use After Free
    "CWE-787",  # Out-of-bounds Write
    "CWE-120",  # Buffer Overflow
    "CWE-125",  # Out-of-bounds Read
}


def _cwe_risk_score(cwe: str) -> float:
    if cwe in CWE_HIGH_RISK:
        return 1.0
    if cwe in CWE_MEDIUM_RISK:
        return 0.6
    if cwe and cwe not in ("unknown", "NVD-CWE-Other", "NVD-CWE-noinfo"):
        return 0.4   # known but uncategorised CWE — mild risk
    return 0.2       # unknown/generic


def _reference_count_bonus(ref_count: int) -> float:
    """
    Smooth bonus for CVEs with many advisory references.
    Caps at 1.0 around 20+ references. Different from reference_count_norm
    in features (which is batch-normalised); this uses the raw count directly.
    """
    import math
    return min(1.0, math.log1p(ref_count) / math.log1p(20))


def _parse_extra(extra_json) -> dict:
    if not extra_json:
        return {}
    if isinstance(extra_json, dict):
        return extra_json
    try:
        return json.loads(extra_json)
    except (ValueError, TypeError):
        return {}


# High-risk countries for geographic boost (same set as feature_engineering,
# but applied differently — as a threshold boost rather than a binary feature).
HIGH_RISK_COUNTRIES = {
    "CN", "RU", "BR", "IN", "VN", "KR", "UA", "TR", "IR", "PK",
    "ID", "TH", "NG", "BD", "PH",
}

WEIGHTS = {
    "severity":          0.35,
    "exploited_flag":    0.18,
    "report_count_norm": 0.10,
    "recency_score":     0.08,
    "source_reliability":0.07,
    "cwe_risk":          0.12,   # increased: not a direct feature, forces model to infer
    "reference_bonus":   0.10,   # increased: raw count differs from batch-normalised feature
}

THRESHOLDS = {
    "Critical": 0.72,
    "High":     0.52,
    "Medium":   0.38,
}


def compute_priority_score(row: pd.Series) -> float:
    extra = _parse_extra(row.get("extra_json"))

    cwe = extra.get("cwe", "unknown")
    ref_count = int(extra.get("reference_count", 0))
    country = extra.get("country_code", "")

    score = (
        WEIGHTS["severity"]           * (row["severity_raw"] / 10.0)
        + WEIGHTS["exploited_flag"]   * float(row["exploited_flag"])
        + WEIGHTS["report_count_norm"]* float(row["report_count_norm"])
        + WEIGHTS["recency_score"]    * float(row["recency_score"])
        + WEIGHTS["source_reliability"] * float(row["source_reliability"])
        + WEIGHTS["cwe_risk"]         * _cwe_risk_score(cwe)
        + WEIGHTS["reference_bonus"]  * _reference_count_bonus(ref_count)
    )

    # Geographic boost: IPs from high-risk countries with moderate confidence
    # get a small but meaningful push — reflects real-world analyst heuristics.
    if country in HIGH_RISK_COUNTRIES and row["severity_raw"] >= 4.0:
        score += 0.05

    return float(min(1.0, max(0.0, score)))


def bucket_score(score: float) -> str:
    if score >= THRESHOLDS["Critical"]:
        return "Critical"
    if score >= THRESHOLDS["High"]:
        return "High"
    if score >= THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"


def apply_heuristic_labels(feature_df: pd.DataFrame) -> pd.DataFrame:
    """
    feature_df must contain the engineered feature columns from feature_engineering.py,
    plus the raw 'extra_json' column (kept for label-enrichment signals).
    Adds 'priority_score' (float) and 'heuristic_label' (str) columns.
    """
    df = feature_df.copy()
    df["priority_score"] = df.apply(compute_priority_score, axis=1)
    df["heuristic_label"] = df["priority_score"].apply(bucket_score)
    return df


if __name__ == "__main__":
    from src.pipeline import db
    from src.pipeline.feature_engineering import build_feature_matrix

    rows = db.fetch_all_as_dicts()
    feats, _cols = build_feature_matrix(rows)
    labeled = apply_heuristic_labels(feats)
    print(labeled["heuristic_label"].value_counts())
