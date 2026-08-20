"""
Generates heuristic priority labels (Critical/High/Medium/Low).

*** IMPORTANT, SAY THIS IN REVIEW 2 ***
These are NOT analyst-verified ground-truth labels. No public dataset provides
human-verified priority labels for a blended, cross-source dataset like this one.
This heuristic is a documented, defensible stand-in built from established signals
(severity, exploitation evidence, report volume, recency, source trust), and the
ML models are trained to generalize this heuristic across the full feature set --
not simply to memorize it 1:1. We are explicit about this limitation rather than
presenting the labels as ground truth.

Heuristic formula:
    priority_score = (
        0.45 * (severity_raw / 10)          # dominant signal: source-reported severity
      + 0.20 * exploited_flag                # known-exploitation is a strong urgency signal
      + 0.15 * report_count_norm             # more reports = more corroboration
      + 0.10 * recency_score                 # fresher threats matter more
      + 0.10 * source_reliability            # trust in the source's own scoring
    )
    -> bucketed into Low / Medium / High / Critical by threshold
"""
import pandas as pd

WEIGHTS = {
    "severity_component": 0.45,
    "exploited_flag": 0.20,
    "report_count_norm": 0.15,
    "recency_score": 0.10,
    "source_reliability": 0.10,
}

# Thresholds on the resulting 0-1 priority_score
THRESHOLDS = {
    "Critical": 0.75,
    "High": 0.55,
    "Medium": 0.35,
    # anything below Medium threshold -> Low
}


def compute_priority_score(row: pd.Series) -> float:
    severity_component = row["severity_raw"] / 10.0
    score = (
        WEIGHTS["severity_component"] * severity_component
        + WEIGHTS["exploited_flag"] * row["exploited_flag"]
        + WEIGHTS["report_count_norm"] * row["report_count_norm"]
        + WEIGHTS["recency_score"] * row["recency_score"]
        + WEIGHTS["source_reliability"] * row["source_reliability"]
    )
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
    feature_df must contain the engineered feature columns from feature_engineering.py.
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
