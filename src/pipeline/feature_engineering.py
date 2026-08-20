"""
Turns rows from the `threats` table into an ML-ready feature matrix.

Features (documented for the report):
- severity_raw          : source's own severity/confidence, rescaled 0-10
- report_count_norm     : report_count, log-scaled and normalized (raw counts are
                           heavily right-skewed, e.g. some IPs have 500+ reports)
- recency_score         : 1.0 = just seen today, decaying toward 0 the older it is
- source_reliability    : trust weight for the source (from config.SOURCE_RELIABILITY)
- exploited_flag        : 1 if a known-exploitation signal exists, else 0
- is_cve / is_ip         : one-hot encoding of threat_type
"""
import datetime as dt
import numpy as np
import pandas as pd


RECENCY_HALF_LIFE_DAYS = 30  # a threat "loses half its recency weight" every 30 days


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


def build_feature_matrix(rows: list) -> pd.DataFrame:
    """
    rows: list of dicts as returned by db.fetch_all_as_dicts()
    Returns a DataFrame with engineered features plus id/threat_type kept for traceability.
    """
    now = dt.datetime.now(dt.timezone.utc)
    df = pd.DataFrame(rows)

    if df.empty:
        return df

    df["report_count"] = df["report_count"].fillna(0)
    df["report_count_norm"] = np.log1p(df["report_count"])
    # min-max normalize within this batch so it's comparable to other 0-1 features
    rc_min, rc_max = df["report_count_norm"].min(), df["report_count_norm"].max()
    if rc_max > rc_min:
        df["report_count_norm"] = (df["report_count_norm"] - rc_min) / (rc_max - rc_min)
    else:
        df["report_count_norm"] = 0.0

    df["recency_score"] = df["last_seen"].apply(lambda x: _recency_score(x, now))
    df["exploited_flag"] = df["exploited_flag"].fillna(0).astype(int)
    df["severity_raw"] = df["severity_raw"].fillna(0.0)
    df["source_reliability"] = df["source_reliability"].fillna(0.5)

    df["is_cve"] = (df["threat_type"] == "cve").astype(int)
    df["is_malicious_ip"] = (df["threat_type"] == "malicious_ip").astype(int)

    feature_cols = [
        "severity_raw", "report_count_norm", "recency_score",
        "source_reliability", "exploited_flag", "is_cve", "is_malicious_ip",
    ]

    keep_cols = ["id", "threat_type", "title"] + feature_cols
    return df[keep_cols].copy(), feature_cols


if __name__ == "__main__":
    from src.pipeline import db
    rows = db.fetch_all_as_dicts()
    feats, cols = build_feature_matrix(rows)
    print(feats.head())
    print("Feature columns:", cols)
