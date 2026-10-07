"""
Evaluates trained models: accuracy, precision/recall/F1 per class, confusion
matrices, and feature importance (for tree-based models). Saves everything to
reports/ so it can be dropped straight into slides.

Phase 11: evaluate_all() now also produces a per-class F1 comparison table
and saves it to reports/per_class_metrics.json. If the SMOTE model
(random_forest_smote) is present, it is evaluated alongside the baseline so
the analyst can compare Strategy A vs Strategy B on minority-class detection.
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


def save_per_class_f1_chart(all_metrics: dict):
    """
    Phase 11: Save a grouped bar chart comparing per-class F1 scores across
    all evaluated models. Highlights Critical and High classes (minority classes)
    in a distinct colour so class-imbalance impact is immediately visible.
    """
    labels_of_interest = PRIORITY_LABELS   # Low, Medium, High, Critical
    model_names = list(all_metrics.keys())
    x = np.arange(len(labels_of_interest))
    width = 0.8 / max(len(model_names), 1)

    # Colour per class: minority (High/Critical) get warm colours
    class_colors = {
        "Low":      "#6d28d9",
        "Medium":   "#2563eb",
        "High":     "#f97316",
        "Critical": "#ef4444",
    }

    fig, ax = plt.subplots(figsize=(10, 4.5))
    fig.patch.set_facecolor("#0d0d1a")
    ax.set_facecolor("#130d2e")

    for i, model_name in enumerate(model_names):
        cr = all_metrics[model_name].get("classification_report", {})
        f1_scores = [cr.get(lbl, {}).get("f1-score", 0) for lbl in labels_of_interest]
        offset = (i - len(model_names) / 2 + 0.5) * width
        bars = ax.bar(
            x + offset, f1_scores, width=width * 0.9,
            label=model_name.replace("_", " ").title(),
            edgecolor="#1a0a3d", linewidth=0.5,
        )

    # F1 = 0.5 warning line
    ax.axhline(0.5, color="#f87171", linewidth=1, linestyle="--", alpha=0.6,
               label="F1 = 0.5 (warning threshold)")

    ax.set_xticks(x)
    ax.set_xticklabels(labels_of_interest, color="#c4b5fd", fontsize=10)
    ax.set_ylabel("F1-Score", color="#a78bfa", fontsize=9)
    ax.set_ylim(0, 1.1)
    ax.set_title("Per-Class F1 Score Comparison (All Models)", color="#c084fc",
                 fontsize=11, fontweight="bold")
    ax.tick_params(colors="#c4b5fd", labelsize=8)
    ax.spines[:].set_color("#4a1d96")
    ax.legend(facecolor="#1a0a3d", edgecolor="#4a1d96",
              labelcolor="#c4b5fd", fontsize=8)
    plt.tight_layout()
    fig.savefig(REPORTS_DIR / "per_class_f1_comparison.png", dpi=150)
    plt.close(fig)


def evaluate_all(results: dict) -> dict:
    all_metrics = {}
    for name, r in results.items():
        metrics = evaluate_model(name, r["model"], r["X_test"], r["y_test"])
        fi = save_feature_importance(name, r["model"])
        if fi:
            metrics["feature_importance"] = fi
        all_metrics[name] = metrics
        print(f"[{name}] accuracy={metrics['accuracy']:.3f}")

        # Phase 11: print per-class F1 for minority classes
        cr = metrics.get("classification_report", {})
        for cls in ("Critical", "High"):
            if cls in cr:
                f1  = cr[cls].get("f1-score", 0)
                sup = int(cr[cls].get("support", 0))
                flag = "  ⚠ LOW" if f1 < 0.5 else ""
                print(f"  [{name}] {cls} F1={f1:.3f}  support={sup}{flag}")

    # Phase 11: save per-class F1 comparison chart
    save_per_class_f1_chart(all_metrics)

    # Phase 11: SMOTE comparison summary if both strategies present
    if "random_forest" in all_metrics and "random_forest_smote" in all_metrics:
        print("\n[Phase 11] Strategy A vs Strategy B (SMOTE) comparison:")
        for cls in ("Critical", "High", "Medium", "Low"):
            cr_a = all_metrics["random_forest"].get("classification_report", {}).get(cls, {})
            cr_b = all_metrics["random_forest_smote"].get("classification_report", {}).get(cls, {})
            f1_a = cr_a.get("f1-score", 0)
            f1_b = cr_b.get("f1-score", 0)
            delta = f1_b - f1_a
            direction = "↑ SMOTE better" if delta > 0.01 else ("↓ SMOTE worse" if delta < -0.01 else "≈ similar")
            print(f"  {cls:10}: A={f1_a:.3f}  B={f1_b:.3f}  Δ={delta:+.3f}  {direction}")
        print("  Note: improvements on heuristic labels reflect label-learning quality,")
        print("  not real-world analyst agreement. Interpret cautiously.")

    with open(REPORTS_DIR / "metrics.json", "w") as f:
        json.dump(all_metrics, f, indent=2)

    # Phase 11: save per-class metrics separately for dashboard
    per_class = {}
    for model_name, m in all_metrics.items():
        cr = m.get("classification_report", {})
        per_class[model_name] = {
            cls: {
                "precision": round(cr.get(cls, {}).get("precision", 0), 3),
                "recall":    round(cr.get(cls, {}).get("recall",    0), 3),
                "f1":        round(cr.get(cls, {}).get("f1-score",  0), 3),
                "support":   int(cr.get(cls,  {}).get("support",    0)),
            }
            for cls in PRIORITY_LABELS
        }
    with open(REPORTS_DIR / "per_class_metrics.json", "w") as f:
        json.dump(per_class, f, indent=2)

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
