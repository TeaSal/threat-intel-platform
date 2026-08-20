"""
Turns rows from the `threats` table into an ML-ready feature matrix.

Features (documented for the report):
- severity_raw          : source's own severity/confidence, rescaled 0-10
- report_count_norm     : report_count, log-scaled and normalized (raw counts are
                           heavily right-skewed, e.g. some IPs have 500+ reports)
- recency_score         : 1.0 = just seen today, decaying toward 0 the older it is
- source_reliability    : trust weight for the source (from config.SOURCE_RELIABILITY)
- exploited_flag        : 1 if a known-exploitation signal exists, else 0
- reference_count_norm  : (NVD only) number of advisories/references for the CVE,
                           log-scaled and normalized. 0 for IP records.
                           More references = more widely discussed/impactful vulnerability.
- high_risk_country     : (AbuseIPDB only) 1 if the IP originates from a country
                           statistically over-represented in abuse reports. 0 otherwise.
- is_cve / is_ip        : one-hot encoding of threat_type
"""
import json
import datetime as dt
import numpy as np
import pandas as pd


RECENCY_HALF_LIFE_DAYS = 30  # a threat "loses half its recency weight" every 30 days

# Countries consistently over-represented in threat intelligence abuse reports.
# Source: AbuseIPDB public statistics + Spamhaus threat geography data.
HIGH_RISK_COUNTRIES = {
    "CN", "RU", "BR", "IN", "VN", "KR", "UA", "TR", "IR", "PK",
    "ID", "TH", "NG", "BD", "PH",
}


def _parse_date_safe(date_str: str):
    if not date_str:
        return None
    try:
        # handle both "...Z" style and NVD's "YYYY-MM-DDTHH:MM:SS.mmm" style
        cleaned = date_str.replace("Z", "+00:00")
        d = dt.datetime.fromisoformat(cleaned)
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return d
    except ValueError:
        return None


def _recency_score(last_seen: str, now: dt.datetime) -> float:
    d = _parse_date_safe(last_seen)
    if d is None:
        return 0.3  # unknown recency -> mild penalty, not zero
    age_days = max(0.0, (now - d).total_seconds() / 86400)
    return float(np.exp(-age_days / RECENCY_HALF_LIFE_DAYS))


def _parse_extra(extra_json) -> dict:
    if not extra_json:
        return {}
    if isinstance(extra_json, dict):
        return extra_json
    try:
        return json.loads(extra_json)
    except (ValueError, TypeError):
        return {}


def build_feature_matrix(rows: list) -> tuple:
    """
    rows: list of dicts as returned by db.fetch_all_as_dicts()
    Returns (DataFrame with engineered features, list of feature column names).
    """
    now = dt.datetime.now(dt.timezone.utc)
    df = pd.DataFrame(rows)

    if df.empty:
        return df, []

    # --- Core features (same as before) ---
    df["report_count"] = df["report_count"].fillna(0)
    df["report_count_norm"] = np.log1p(df["report_count"])
    rc_min, rc_max = df["report_count_norm"].min(), df["report_count_norm"].max()
    if rc_max > rc_min:
        df["report_count_norm"] = (df["report_count_norm"] - rc_min) / (rc_max - rc_min)
    else:
        df["report_count_norm"] = 0.0

    df["recency_score"] = df["last_seen"].apply(lambda x: _recency_score(x, now))
    df["exploited_flag"] = df["exploited_flag"].fillna(0).astype(int)
    df["severity_raw"] = df["severity_raw"].fillna(0.0)
    df["source_reliability"] = df["source_reliability"].fillna(0.5)

    # --- New features derived from extra_json ---
    extras = df["extra_json"].apply(_parse_extra)

    # reference_count_norm: how many advisories/references the CVE has
    # (meaningful signal of how much attention a vulnerability has received)
    ref_counts = extras.apply(lambda d: float(d.get("reference_count", 0)))
    df["reference_count_norm"] = np.log1p(ref_counts)
    ref_min, ref_max = df["reference_count_norm"].min(), df["reference_count_norm"].max()
    if ref_max > ref_min:
        df["reference_count_norm"] = (df["reference_count_norm"] - ref_min) / (ref_max - ref_min)
    else:
        df["reference_count_norm"] = 0.0

    # high_risk_country: 1 if AbuseIPDB IP comes from a high-abuse-rate country
    df["high_risk_country"] = extras.apply(
        lambda d: 1 if d.get("country_code", "") in HIGH_RISK_COUNTRIES else 0
    ).astype(int)

    # --- Threat type one-hot ---
    df["is_cve"] = (df["threat_type"] == "cve").astype(int)
    df["is_malicious_ip"] = (df["threat_type"] == "malicious_ip").astype(int)

    feature_cols = [
        "severity_raw",
        "report_count_norm",
        "recency_score",
        "source_reliability",
        "exploited_flag",
        "reference_count_norm",   # new: NVD advisory breadth
        "high_risk_country",      # new: geographic risk signal
        "is_cve",
        "is_malicious_ip",
    ]

    # extra_json is kept in the returned DataFrame so that labeling.py can
    # extract CWE, reference_count, and country_code for richer label signals.
    # It is NOT included in feature_cols and never passed to the ML models.
    keep_cols = ["id", "threat_type", "title", "extra_json"] + feature_cols
    return df[keep_cols].copy(), feature_cols


if __name__ == "__main__":
    from src.pipeline import db
    rows = db.fetch_all_as_dicts()
    feats, cols = build_feature_matrix(rows)
    print(feats.head())
    print("Feature columns:", cols)
