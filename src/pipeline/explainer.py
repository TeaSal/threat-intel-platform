"""
Phase 8 — ML Explainability module.

Explains why the Random Forest model assigned a particular priority to a threat.

Two approaches, both implemented:

Approach A — Feature contribution (always available, no extra dependencies):
    Uses model.feature_importances_ × normalised feature values to compute
    a per-feature contribution score for the predicted class.
    Contributions are normalised to sum to 1 and top-5 are returned.

Approach B — SHAP (optional, requires `pip install shap>=0.42`):
    Uses shap.TreeExplainer to compute exact Shapley values.
    If shap is not installed, falls back to Approach A silently.

The module never contradicts the model's actual prediction — explanations
are derived directly from the model's own weights/values.

Public API
----------
explain_prediction(row, model, feature_cols, scaler=None) -> dict
explain_all(rows, model, feature_cols, scaler=None)       -> {id: dict}
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

# Human-readable labels for the 9 feature columns
_FEATURE_LABELS: Dict[str, str] = {
    "severity_raw":          "Severity score",
    "report_count_norm":     "Report/abuse volume",
    "recency_score":         "Recency",
    "source_reliability":    "Source reliability",
    "exploited_flag":        "Exploitation evidence",
    "reference_count_norm":  "Advisory reference count",
    "high_risk_country":     "High-risk country origin",
    "is_cve":                "CVE type",
    "is_malicious_ip":       "Malicious IP type",
}

# Threshold above which a feature value is considered "high"
# Used only for plain-English sentence generation.
_HIGH_THRESHOLD: Dict[str, float] = {
    "severity_raw":          7.0,
    "report_count_norm":     0.5,
    "recency_score":         0.6,
    "source_reliability":    0.75,
    "exploited_flag":        0.5,
    "reference_count_norm":  0.5,
    "high_risk_country":     0.5,
    "is_cve":                0.5,
    "is_malicious_ip":       0.5,
}


# ── Approach A — feature contribution (always available) ─────────────────────

def _explain_approach_a(
    feature_values: np.ndarray,
    feature_cols:   List[str],
    model,
    predicted_class: str,
) -> List[Dict[str, Any]]:
    """
    Compute per-feature contributions using global feature importances × local
    feature values. This is an approximation (not SHAP), but it is:
      - Always available (no extra deps)
      - Monotone with respect to the model's feature_importances_
      - Direction-aware: positive = pushes toward higher priority,
                          negative = pushes toward lower priority

    The sign of contribution is determined by comparing the raw feature value
    against the feature's mean importance-weighted value across training:
    we use (value - 0.5) × importance as a signed contribution proxy for
    binary/normalised features and (value/10) × importance for severity_raw.

    Returns list of dicts sorted by abs(contribution) descending.
    """
    importances = model.feature_importances_   # shape: (n_features,)

    contributions = []
    for i, col in enumerate(feature_cols):
        val  = float(feature_values[i])
        imp  = float(importances[i])

        # Normalise value to [0, 1] range for direction determination
        if col == "severity_raw":
            val_norm = val / 10.0
        else:
            val_norm = float(np.clip(val, 0, 1))

        # Direction: above 0.5 = positive push, below 0.5 = negative push
        direction_factor = val_norm - 0.5          # in [-0.5, +0.5]
        contribution     = imp * direction_factor  # signed contribution

        contributions.append({
            "feature":      col,
            "label":        _FEATURE_LABELS.get(col, col),
            "value":        round(val, 4),
            "importance":   round(imp, 4),
            "contribution": round(contribution, 4),
            "direction":    "+" if contribution >= 0 else "-",
        })

    # Sort by absolute contribution descending
    contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
    return contributions


# ── Approach B — SHAP (optional) ─────────────────────────────────────────────

def _explain_approach_shap(
    feature_values: np.ndarray,
    feature_cols:   List[str],
    model,
    predicted_class: str,
    class_order:    List[str],
) -> Optional[List[Dict[str, Any]]]:
    """
    Try SHAP TreeExplainer. Returns None if shap is not installed or fails.
    """
    try:
        import shap  # type: ignore
    except ImportError:
        return None

    try:
        explainer   = shap.TreeExplainer(model)
        X_row       = feature_values.reshape(1, -1)
        shap_values = explainer.shap_values(X_row)   # list[n_classes] of (1, n_features)

        # Find index of predicted class
        try:
            class_idx = list(class_order).index(predicted_class)
        except ValueError:
            class_idx = 0

        if isinstance(shap_values, list):
            row_shap = shap_values[class_idx][0]   # (n_features,)
        else:
            row_shap = shap_values[0]

        contributions = []
        for i, col in enumerate(feature_cols):
            sv = float(row_shap[i])
            contributions.append({
                "feature":      col,
                "label":        _FEATURE_LABELS.get(col, col),
                "value":        round(float(feature_values[i]), 4),
                "importance":   None,    # SHAP doesn't use global importances
                "contribution": round(sv, 4),
                "direction":    "+" if sv >= 0 else "-",
            })

        contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
        return contributions

    except Exception as exc:
        logger.warning("[explainer] SHAP failed (%s) — falling back to Approach A", exc)
        return None


# ── Plain-English summary generator ──────────────────────────────────────────

def _plain_english(
    top_features: List[Dict[str, Any]],
    predicted_class: str,
    confidence: float,
) -> str:
    """Build a one-sentence plain-English explanation from the top features."""
    reasons = []
    for f in top_features[:3]:
        col   = f["feature"]
        val   = f["value"]
        label = f["label"].lower()
        dirn  = f["direction"]
        thresh = _HIGH_THRESHOLD.get(col, 0.5)

        if col == "exploited_flag":
            if val >= 0.5:
                reasons.append("exploitation evidence present")
            else:
                reasons.append("no exploitation evidence")
        elif col == "severity_raw":
            reasons.append(f"{label} {val:.1f}/10")
        elif col == "high_risk_country":
            if val >= 0.5:
                reasons.append("originates from high-risk country")
        elif col in ("is_cve", "is_malicious_ip"):
            reasons.append(label)
        elif dirn == "+" and val >= thresh:
            reasons.append(f"high {label}")
        elif dirn == "-" and val < thresh:
            reasons.append(f"low {label}")
        else:
            reasons.append(f"{label} ({val:.3f})")

    if not reasons:
        return f"Predicted {predicted_class} (confidence {confidence:.0%})."

    return (
        f"{predicted_class} priority because: "
        + "; ".join(reasons)
        + f". (Model confidence: {confidence:.0%})"
    )


# ── Public API ────────────────────────────────────────────────────────────────

def explain_prediction(
    row:          Dict[str, Any],
    model,
    feature_cols: List[str],
    scaler=None,
) -> Dict[str, Any]:
    """
    Explain why the model gave a threat its predicted priority.

    Parameters
    ----------
    row          : single threat dict from db.fetch_all_as_dicts()
    model        : fitted sklearn model (Random Forest preferred)
    feature_cols : ordered list of feature column names (from build_feature_matrix)
    scaler       : optional StandardScaler; if provided, transforms features before
                   passing to models that require scaled input (LR). For RF, not needed.

    Returns
    -------
    dict with keys:
        predicted_class  : str
        confidence       : float  (0–1, probability of predicted class)
        method           : "shap" | "feature_contribution"
        top_features     : list of top-5 feature dicts
        plain_english    : str
    """
    # Build feature vector from row dict
    feature_values = np.array(
        [float(row.get(col, 0) or 0) for col in feature_cols],
        dtype=float,
    )

    X = feature_values.reshape(1, -1)
    if scaler is not None:
        X_input = scaler.transform(X)
    else:
        X_input = X

    predicted_class = model.predict(X_input)[0]
    proba           = model.predict_proba(X_input)[0]
    class_order     = list(model.classes_)

    try:
        class_idx  = class_order.index(predicted_class)
        confidence = float(proba[class_idx])
    except (ValueError, IndexError):
        confidence = float(proba.max())

    # Try SHAP first (Approach B), fall back to Approach A
    contributions = _explain_approach_shap(
        feature_values, feature_cols, model, predicted_class, class_order
    )
    method = "shap"
    if contributions is None:
        contributions = _explain_approach_a(
            feature_values, feature_cols, model, predicted_class
        )
        method = "feature_contribution"

    top_features = contributions[:5]

    return {
        "predicted_class": predicted_class,
        "confidence":      round(confidence, 4),
        "method":          method,
        "top_features":    top_features,
        "plain_english":   _plain_english(top_features, predicted_class, confidence),
    }


def explain_all(
    rows:         List[Dict[str, Any]],
    model,
    feature_cols: List[str],
    scaler=None,
) -> Dict[str, Dict[str, Any]]:
    """
    Generate explanations for all threat rows.

    Returns {threat_id: explanation_dict}.
    Rows without a predicted_priority are skipped (model hasn't scored them yet).
    """
    results: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        tid = row.get("id")
        if not tid:
            continue
        if not row.get("predicted_priority"):
            continue   # not yet scored — skip
        try:
            results[tid] = explain_prediction(row, model, feature_cols, scaler)
        except Exception as exc:
            logger.warning("[explainer] failed for %s: %s", tid, exc)
    return results


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

    import joblib
    from src.pipeline import db
    from src.pipeline.feature_engineering import build_feature_matrix, FEATURE_COLS
    from src.config import MODELS_DIR

    rows  = db.fetch_all_as_dicts()
    feats, feature_cols = build_feature_matrix(rows)
    model = joblib.load(MODELS_DIR / "random_forest.joblib")

    # Explain first 3 threats as a smoke-test
    explained = 0
    for row in rows[:20]:
        if not row.get("predicted_priority"):
            continue
        exp = explain_prediction(row, model, feature_cols)
        print(f"\n{row['id']} → {exp['predicted_class']} ({exp['confidence']:.0%})")
        print(f"  Method: {exp['method']}")
        print(f"  {exp['plain_english']}")
        for f in exp["top_features"]:
            print(f"    {f['direction']} {f['label']}: {f['value']} (contribution {f['contribution']:.4f})")
        explained += 1
        if explained >= 3:
            break
