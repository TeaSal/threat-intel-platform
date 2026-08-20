"""
Trains and compares three beginner-friendly classifiers on the heuristically
labeled dataset: Logistic Regression, Decision Tree, Random Forest.

No deep learning: at this dataset size (hundreds to low-thousands of rows,
~7 features) a neural network would be both unnecessary and likely to
underperform tree-based methods, so it's deliberately excluded from scope.
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
    "severity_raw", "report_count_norm", "recency_score",
    "source_reliability", "exploited_flag", "is_cve", "is_malicious_ip",
]


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
              f"This is a class-imbalance risk worth flagging in Review 2.")

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
    """
    X_train, X_test, X_train_s, X_test_s, y_train, y_test, scaler = prepare_train_test(labeled_df)

    results = {}

    # Logistic Regression (needs scaled features, benefits from class_weight given imbalance)
    logreg = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=RANDOM_SEED)
    logreg.fit(X_train_s, y_train)
    results["logistic_regression"] = {
        "model": logreg, "X_test": X_test_s, "y_test": y_test, "uses_scaled": True,
    }

    # Decision Tree
    dtree = DecisionTreeClassifier(max_depth=6, class_weight="balanced", random_state=RANDOM_SEED)
    dtree.fit(X_train, y_train)
    results["decision_tree"] = {
        "model": dtree, "X_test": X_test, "y_test": y_test, "uses_scaled": False,
    }

    # Random Forest
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=10, class_weight="balanced", random_state=RANDOM_SEED
    )
    rf.fit(X_train, y_train)
    results["random_forest"] = {
        "model": rf, "X_test": X_test, "y_test": y_test, "uses_scaled": False,
    }

    # Persist models + scaler for the dashboard to reuse
    joblib.dump(logreg, MODELS_DIR / "logistic_regression.joblib")
    joblib.dump(dtree, MODELS_DIR / "decision_tree.joblib")
    joblib.dump(rf, MODELS_DIR / "random_forest.joblib")
    joblib.dump(scaler, MODELS_DIR / "scaler.joblib")

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
