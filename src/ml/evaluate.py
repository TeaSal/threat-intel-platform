"""
Evaluates trained models: accuracy, precision/recall/F1 per class, confusion
matrices, and feature importance (for tree-based models). Saves everything to
reports/ so it can be dropped straight into slides.
"""
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay
)

from src.config import REPORTS_DIR, PRIORITY_LABELS
from src.ml.train import FEATURE_COLS


def evaluate_model(name: str, model, X_test, y_test, labels=PRIORITY_LABELS):
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, labels=labels, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=labels)

    # Save confusion matrix plot
    fig, ax = plt.subplots(figsize=(5, 5))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
    disp.plot(ax=ax, cmap="Blues", colorbar=False)
    ax.set_title(f"Confusion Matrix — {name}")
    plt.tight_layout()
    fig.savefig(REPORTS_DIR / f"confusion_matrix_{name}.png", dpi=150)
    plt.close(fig)

    return {
        "accuracy": acc,
        "classification_report": report,
        "confusion_matrix": cm.tolist(),
        "labels_order": labels,
    }


def save_feature_importance(name: str, model):
    """
    Tree-based models expose feature_importances_ (Gini/entropy-based).
    Logistic Regression exposes coef_ (one row per class). We take the
    mean absolute coefficient across all classes as a proxy for overall
    feature influence — larger absolute coefficient = stronger signal.
    """
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        xlabel = "Importance (Gini)"

    elif hasattr(model, "coef_"):
        # coef_ shape: (n_classes, n_features) for multiclass, (1, n_features) for binary
        importances = np.mean(np.abs(model.coef_), axis=0)
        xlabel = "Mean |Coefficient| across classes"

    else:
        return None

    order = np.argsort(importances)[::-1]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.barh([FEATURE_COLS[i] for i in order][::-1], importances[order][::-1])
    ax.set_title(f"Feature Importance — {name}")
    ax.set_xlabel(xlabel)
    plt.tight_layout()
    fig.savefig(REPORTS_DIR / f"feature_importance_{name}.png", dpi=150)
    plt.close(fig)

    return dict(zip(FEATURE_COLS, importances.tolist()))


def evaluate_all(results: dict) -> dict:
    all_metrics = {}
    for name, r in results.items():
        metrics = evaluate_model(name, r["model"], r["X_test"], r["y_test"])
        fi = save_feature_importance(name, r["model"])
        if fi:
            metrics["feature_importance"] = fi
        all_metrics[name] = metrics
        print(f"[{name}] accuracy={metrics['accuracy']:.3f}")

    with open(REPORTS_DIR / "metrics.json", "w") as f:
        json.dump(all_metrics, f, indent=2)

    return all_metrics


if __name__ == "__main__":
    from src.pipeline import db
    from src.pipeline.feature_engineering import build_feature_matrix
    from src.pipeline.labeling import apply_heuristic_labels
    from src.ml.train import train_all_models

    rows = db.fetch_all_as_dicts()
    feats, _cols = build_feature_matrix(rows)
    labeled = apply_heuristic_labels(feats)
    results, scaler = train_all_models(labeled)
    metrics = evaluate_all(results)
