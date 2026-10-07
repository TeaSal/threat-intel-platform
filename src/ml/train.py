"""
Trains and compares three beginner-friendly classifiers on the heuristically
labeled dataset: Logistic Regression, Decision Tree, Random Forest.

No deep learning: at this dataset size (hundreds to low-thousands of rows,
~7 features) a neural network would be both unnecessary and likely to
underperform tree-based methods, so it's deliberately excluded from scope.

Phase 11 — Class Imbalance:
Adds an optional SMOTE oversampling strategy (Strategy B) alongside the
existing class_weight="balanced" baseline (Strategy A). SMOTE requires
the `imbalanced-learn` package; if it is not installed the module falls
back to Strategy A silently.
"""
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

from src.config import MODELS_DIR, RANDOM_SEED, PRIORITY_LABELS

FEATURE_COLS = [
    "severity_raw",
    "report_count_norm",
    "recency_score",
    "source_reliability",
    "exploited_flag",
    "reference_count_norm",   # NVD: advisory breadth signal
    "high_risk_country",      # AbuseIPDB: geographic risk signal
    "is_cve",
    "is_malicious_ip",
]

# ── Phase 11: SMOTE availability check ────────────────────────────────────────
try:
    from imblearn.over_sampling import SMOTE
    _SMOTE_AVAILABLE = True
except ImportError:
    _SMOTE_AVAILABLE = False


def _smote_resample(X_train: np.ndarray, y_train: np.ndarray) -> tuple:
    """
    Apply SMOTE oversampling to the training set.
    Falls back to the original data if SMOTE is unavailable or if any class
    has fewer than 2 samples (SMOTE requirement).
    Returns (X_resampled, y_resampled, used_smote_flag).
    """
    if not _SMOTE_AVAILABLE:
        return X_train, y_train, False

    class_counts = pd.Series(y_train).value_counts()
    if (class_counts < 2).any():
        print(
            "[train] WARNING: SMOTE skipped — at least one class has < 2 samples. "
            f"Class counts: {class_counts.to_dict()}"
        )
        return X_train, y_train, False

    try:
        # k_neighbors must be < min class count
        k = max(1, min(5, class_counts.min() - 1))
        sm = SMOTE(random_state=RANDOM_SEED, k_neighbors=k)
        X_res, y_res = sm.fit_resample(X_train, y_train)
        return X_res, y_res, True
    except Exception as e:
        print(f"[train] WARNING: SMOTE failed ({e}). Falling back to class_weight='balanced'.")
        return X_train, y_train, False


def prepare_train_test(labeled_df: pd.DataFrame, test_size: float = 0.25):
    X = labeled_df[FEATURE_COLS].to_numpy(dtype=float)
    y = labeled_df["heuristic_label"].astype(str).to_numpy()

    # Stratified splitting requires >=2 members per class. With a heuristic labeler,
    # very rare classes (e.g. only 1 "Critical" record) can occur, especially on small
    # or synthetic batches -- this is realistic and worth noting in the report as a
    # class-imbalance risk. Fall back to a non-stratified split rather than crashing.
    class_counts = pd.Series(y).value_counts()
    can_stratify = (class_counts >= 2).all() and len(class_counts) > 1
    if not can_stratify:
        print(f"[train] WARNING: stratified split not possible, class counts: "
              f"{class_counts.to_dict()}. Falling back to a random (non-stratified) split. "
              f"This is a class-imbalance risk worth flagging .")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=RANDOM_SEED,
        stratify=y if can_stratify else None,
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    return X_train, X_test, X_train_scaled, X_test_scaled, y_train, y_test, scaler


def train_all_models(labeled_df: pd.DataFrame):
    """
    Returns a dict of {model_name: {"model": fitted_model, "X_test":..., "y_test":..., "scaler":...}}
    Logistic Regression uses scaled features; tree-based models use raw features
    (scaling doesn't matter for trees and keeps feature importances interpretable).

    Phase 11: if imbalanced-learn is available, SMOTE is applied to the Random Forest
    training set as Strategy B. Results of both strategies are logged so the analyst
    can compare them in the Model Evaluation tab.
    """
    X_train, X_test, X_train_s, X_test_s, y_train, y_test, scaler = prepare_train_test(labeled_df)

    # ── Phase 11: class distribution logging ──────────────────────────────
    class_counts = pd.Series(y_train).value_counts()
    print("[train] training class distribution:")
    for cls, cnt in class_counts.sort_index().items():
        pct = cnt / len(y_train) * 100
        print(f"  {cls:10}: {cnt:5d} ({pct:.1f}%)")
    minority_classes = class_counts[class_counts < class_counts.mean()].index.tolist()
    if minority_classes:
        print(f"[train] minority classes (below mean count): {minority_classes}")
        print("[train] class_weight='balanced' active on all models (Strategy A)")
        if _SMOTE_AVAILABLE:
            print("[train] SMOTE available — will apply to Random Forest (Strategy B)")
        else:
            print("[train] imbalanced-learn not installed — SMOTE unavailable. "
                  "Install with: pip install imbalanced-learn>=0.11")

    results = {}

    # Logistic Regression — Strategy A (class_weight="balanced")
    logreg = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=RANDOM_SEED)
    logreg.fit(X_train_s, y_train)
    results["logistic_regression"] = {
        "model": logreg, "X_test": X_test_s, "y_test": y_test, "uses_scaled": True,
    }

    # Decision Tree — Strategy A
    dtree = DecisionTreeClassifier(max_depth=6, class_weight="balanced", random_state=RANDOM_SEED)
    dtree.fit(X_train, y_train)
    results["decision_tree"] = {
        "model": dtree, "X_test": X_test, "y_test": y_test, "uses_scaled": False,
    }

    # Random Forest — Strategy A baseline
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=10, class_weight="balanced", random_state=RANDOM_SEED
    )
    rf.fit(X_train, y_train)
    results["random_forest"] = {
        "model": rf, "X_test": X_test, "y_test": y_test, "uses_scaled": False,
    }

    # ── Phase 11: Random Forest Strategy B — SMOTE oversampling ──────────
    # SMOTE is applied ONLY to the training set. The test set is kept
    # identical to Strategy A so comparisons are fair.
    X_train_smote, y_train_smote, used_smote = _smote_resample(X_train, y_train)
    if used_smote:
        smote_counts = pd.Series(y_train_smote).value_counts()
        print(f"[train] SMOTE resampled training set: {dict(smote_counts.sort_index())}")
        rf_smote = RandomForestClassifier(
            n_estimators=200, max_depth=10, random_state=RANDOM_SEED
            # Note: no class_weight here — SMOTE already balances the classes
        )
        rf_smote.fit(X_train_smote, y_train_smote)
        results["random_forest_smote"] = {
            "model": rf_smote, "X_test": X_test, "y_test": y_test, "uses_scaled": False,
        }
        print("[train] Strategy B (SMOTE) model trained as 'random_forest_smote'")

    # Persist best model + scaler (Strategy A RF remains the default for prediction)
    joblib.dump(logreg, MODELS_DIR / "logistic_regression.joblib")
    joblib.dump(dtree, MODELS_DIR / "decision_tree.joblib")
    joblib.dump(rf, MODELS_DIR / "random_forest.joblib")
    joblib.dump(scaler, MODELS_DIR / "scaler.joblib")
    if used_smote:
        joblib.dump(rf_smote, MODELS_DIR / "random_forest_smote.joblib")

    return results, scaler


if __name__ == "__main__":
    from src.pipeline import db
    from src.pipeline.feature_engineering import build_feature_matrix
    from src.pipeline.labeling import apply_heuristic_labels

    rows = db.fetch_all_as_dicts()
    feats, _cols = build_feature_matrix(rows)
    labeled = apply_heuristic_labels(feats)
    results, scaler = train_all_models(labeled)
    for name in results:
        print(f"Trained {name}")
