"""
Threat Clustering Module — Phase 1 Post-Review-2 Extension
===========================================================

Groups related threats into clusters so analysts can spot patterns such as:
- A wave of high-severity CVEs in a short window
- A batch of malicious IPs from the same geographic region / ISP
- A mix of CVEs and IPs that share exploitation characteristics

ALGORITHM CHOICE: K-Means
--------------------------
We evaluated three options:

  DBSCAN — good for arbitrary shapes and built-in noise detection, but requires
  careful tuning of eps/min_samples and produces unstable cluster IDs across
  runs (ordering changes as data grows), making dashboard display harder.

  Hierarchical / Agglomerative — interpretable dendrogram, but O(n²) memory
  and does not scale if the dataset grows to tens of thousands of records.

  K-Means — stable integer cluster IDs, O(n·k·iter) runtime, works well on
  the available feature space (all numeric, same scale after StandardScaler),
  and is well-understood for academic demonstration. The main downside is
  needing to choose k in advance; we address this with automatic k selection
  via the silhouette score on a small candidate range.

TEXT FEATURES (title + description)
-------------------------------------
NVD descriptions contain useful signal (vendor names, vulnerability class).
We build a small TF-IDF matrix (max 50 dimensions, SVD-reduced to min(20, n-1)
to avoid the curse of dimensionality) and concatenate it with the numeric
feature block. If text is sparse or unhelpful, the numeric features dominate.
The text block is weighted at 0.3 relative to the numeric block (0.7) so it
enriches but does not override the structured signals.

OUTPUT
------
Returns a dict {threat_id: cluster_id} suitable for db.update_cluster_ids().
Also returns a summary DataFrame for pipeline logging and dashboard use.
"""

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from src.config import RANDOM_SEED

import warnings

# ── Numeric features we cluster on ────────────────────────────────────────────
# These are all already present in the feature_engineering output DataFrame.
# We deliberately exclude reference_count_norm and high_risk_country because
# they are very sparse (mostly 0) and add noise without adding signal at the
# typical dataset size. Add them back if the dataset grows >5 000 rows.
CLUSTER_NUMERIC_FEATURES = [
    "severity_raw",
    "exploited_flag",
    "recency_score",
    "report_count_norm",
    "source_reliability",
    "is_cve",
    "is_malicious_ip",
]

# Weight of the text (TF-IDF) block relative to the numeric block.
# 0.0 = purely numeric clustering; 1.0 = purely text clustering.
TEXT_WEIGHT = 0.30

# Candidate values of k we evaluate when auto-selecting.
K_MIN = 3
K_MAX = 8

# Minimum number of threats required to attempt clustering.
# Below this, every threat gets cluster_id = 0 (single "unclustered" group).
MIN_THREATS_FOR_CLUSTERING = 10


def _build_text_matrix(df: pd.DataFrame, n_components: int = 20) -> np.ndarray | None:
    """
    Build a TF-IDF + SVD text matrix from the title and description columns.
    Returns a (n_samples, n_components) dense array, or None if text is too sparse.
    """
    texts = (
        df["title"].fillna("") + " " + df["description"].fillna("")
    ).tolist()

    # If every text is empty/whitespace, skip text features
    non_empty = sum(1 for t in texts if t.strip())
    if non_empty < 5:
        return None

    try:
        tfidf = TfidfVectorizer(
            max_features=100,
            stop_words="english",
            min_df=1,
            sublinear_tf=True,
        )
        tfidf_matrix = tfidf.fit_transform(texts)  # sparse (n, vocab)

        # Reduce to dense via SVD; cap components at (n_samples-1) to avoid error
        actual_components = min(n_components, tfidf_matrix.shape[0] - 1, tfidf_matrix.shape[1])
        if actual_components < 2:
            return None

        svd = TruncatedSVD(n_components=actual_components, random_state=RANDOM_SEED)
        return svd.fit_transform(tfidf_matrix)  # dense (n, actual_components)

    except Exception:
        return None


def _select_k(X: np.ndarray, k_min: int, k_max: int) -> int:
    """
    Choose the number of clusters k by maximising the silhouette score over
    a small candidate range. Falls back to k_min if silhouette cannot be computed
    (e.g. n_samples is too small).
    """
    best_k = k_min
    best_score = -1.0

    for k in range(k_min, min(k_max + 1, X.shape[0])):
        try:
            km = KMeans(n_clusters=k, random_state=RANDOM_SEED, n_init=10)
            labels = km.fit_predict(X)
            # silhouette_score requires at least 2 distinct labels
            if len(set(labels)) < 2:
                continue
            score = silhouette_score(X, labels, sample_size=min(500, X.shape[0]))
            if score > best_score:
                best_score = score
                best_k = k
        except Exception:
            continue

    return best_k


def cluster_threats(feature_df: pd.DataFrame) -> tuple[dict, pd.DataFrame, int]:
    """
    Assign a cluster_id to every threat in feature_df.

    Parameters
    ----------
    feature_df : pd.DataFrame
        The output of build_feature_matrix() — must contain CLUSTER_NUMERIC_FEATURES,
        plus 'id', 'title'. 'description' is used if present.

    Returns
    -------
    id_to_cluster : dict {threat_id: cluster_id}
    cluster_summary : pd.DataFrame
        One row per cluster with aggregate statistics.
    k : int
        The number of clusters chosen.
    """
    n = len(feature_df)

    # ── Edge case: too few records ─────────────────────────────────────────
    if n < MIN_THREATS_FOR_CLUSTERING:
        print(f"[cluster] only {n} threats — skipping clustering (need >= {MIN_THREATS_FOR_CLUSTERING})")
        id_to_cluster = {row["id"]: 0 for _, row in feature_df.iterrows()}
        summary = pd.DataFrame([{
            "cluster_id": 0,
            "size": n,
            "avg_severity": feature_df["severity_raw"].mean(),
            "pct_exploited": feature_df["exploited_flag"].mean() * 100,
            "threat_types": "mixed",
            "sources": "mixed",
            "dominant_priority": "—",
            "is_notable": False,
        }])
        return id_to_cluster, summary, 1

    # ── 1. Numeric feature block ───────────────────────────────────────────
    missing_cols = [c for c in CLUSTER_NUMERIC_FEATURES if c not in feature_df.columns]
    if missing_cols:
        raise ValueError(f"[cluster] Missing feature columns: {missing_cols}")

    X_num = feature_df[CLUSTER_NUMERIC_FEATURES].fillna(0).to_numpy(dtype=float)
    scaler = StandardScaler()
    X_num_scaled = scaler.fit_transform(X_num)

    # ── 2. Text feature block (optional enrichment) ────────────────────────
    has_description = "description" in feature_df.columns
    text_df = feature_df.copy()
    if not has_description:
        text_df["description"] = ""

    X_text = _build_text_matrix(text_df)

    if X_text is not None:
        # Normalise text block to unit variance, then blend
        text_scaler = StandardScaler()
        X_text_scaled = text_scaler.fit_transform(X_text)
        # Weighted concatenation: numeric block gets weight (1 - TEXT_WEIGHT),
        # text block gets weight TEXT_WEIGHT, so neither block dominates unfairly.
        X = np.hstack([
            X_num_scaled * (1.0 - TEXT_WEIGHT),
            X_text_scaled * TEXT_WEIGHT,
        ])
        print(f"[cluster] combined feature matrix: {X_num_scaled.shape[1]} numeric "
              f"+ {X_text_scaled.shape[1]} text-SVD dims = {X.shape[1]} total")
    else:
        X = X_num_scaled
        print(f"[cluster] using {X_num_scaled.shape[1]} numeric features only (text too sparse)")

    # ── 3. Choose k automatically ──────────────────────────────────────────
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        k = _select_k(X, K_MIN, K_MAX)

    print(f"[cluster] selected k={k} clusters (silhouette-optimal over k={K_MIN}..{K_MAX})")

    # ── 4. Final K-Means fit ───────────────────────────────────────────────
    km = KMeans(n_clusters=k, random_state=RANDOM_SEED, n_init=15)
    labels = km.fit_predict(X)

    id_to_cluster = dict(zip(feature_df["id"].tolist(), labels.tolist()))

    # ── 5. Build cluster summary ───────────────────────────────────────────
    # Attach labels back to the df for aggregation
    agg_df = feature_df.copy()
    agg_df["cluster_id"] = labels

    # Pull in heuristic_label if it was added by labeling.py (present after apply_heuristic_labels)
    has_priority = "heuristic_label" in agg_df.columns

    rows = []
    for cid in sorted(agg_df["cluster_id"].unique()):
        g = agg_df[agg_df["cluster_id"] == cid]

        # Dominant priority (most common heuristic label)
        if has_priority:
            label_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            label_counts = g["heuristic_label"].value_counts()
            dominant = label_counts.index[0] if len(label_counts) > 0 else "—"
            n_critical = int((g["heuristic_label"] == "Critical").sum())
            n_high = int((g["heuristic_label"] == "High").sum())
        else:
            dominant = "—"
            n_critical = 0
            n_high = 0

        # Threat types present
        if "threat_type" in agg_df.columns:
            types = g["threat_type"].value_counts().to_dict()
            types_str = ", ".join(f"{t}({c})" for t, c in types.items())
        else:
            types_str = "—"

        # Sources present
        if "source" in feature_df.columns:
            src_series = feature_df.loc[feature_df["id"].isin(g["id"]), "source"]
            sources_str = ", ".join(src_series.value_counts().index.tolist())
        else:
            sources_str = "—"

        avg_sev = round(float(g["severity_raw"].mean()), 2)
        pct_exp = round(float(g["exploited_flag"].mean()) * 100, 1)

        # A cluster is "notable" if it has high avg severity OR exploited threats
        is_notable = avg_sev >= 7.0 or pct_exp >= 20.0 or n_critical >= 3

        rows.append({
            "cluster_id": int(cid),
            "size": len(g),
            "avg_severity": avg_sev,
            "pct_exploited": pct_exp,
            "n_critical": n_critical,
            "n_high": n_high,
            "dominant_priority": dominant,
            "threat_types": types_str,
            "sources": sources_str,
            "is_notable": is_notable,
        })

    cluster_summary = pd.DataFrame(rows).sort_values("avg_severity", ascending=False)

    # Log summary
    print("[cluster] cluster summary:")
    for _, row in cluster_summary.iterrows():
        notable_tag = " ⚠ NOTABLE" if row["is_notable"] else ""
        print(f"  Cluster {row['cluster_id']:>2}: {row['size']:>4} threats | "
              f"avg_sev={row['avg_severity']:.2f} | "
              f"exploited={row['pct_exploited']:.0f}% | "
              f"{row['dominant_priority']}{notable_tag}")

    return id_to_cluster, cluster_summary, k


if __name__ == "__main__":
    from src.pipeline import db
    from src.pipeline.feature_engineering import build_feature_matrix
    from src.pipeline.labeling import apply_heuristic_labels

    rows = db.fetch_all_as_dicts()
    feats, _ = build_feature_matrix(rows)
    labeled = apply_heuristic_labels(feats)

    # Attach source/threat_type back for summary richness
    raw_df = pd.DataFrame(rows)[["id", "source", "threat_type", "description"]]
    labeled = labeled.merge(raw_df, on="id", how="left")

    id_to_cluster, summary, k = cluster_threats(labeled)
    print(f"\nAssigned {len(id_to_cluster)} threats to {k} clusters")
    print(summary.to_string(index=False))
