"""
Analyst-facing dashboard. Run with:
    streamlit run src/dashboard/app.py

Reads directly from data/threat_intel.db (the single source of truth also used
by training/evaluation), so it always reflects the latest pipeline run.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import json
import pandas as pd
import streamlit as st

from src.pipeline import db
from src.config import REPORTS_DIR

st.set_page_config(page_title="Threat Intel Priority Dashboard", layout="wide")

st.title("🛡️ AI-Powered Threat Intelligence — Priority Dashboard")
st.caption("Consolidated CVE + malicious-IP intelligence, ranked by ML-predicted priority.")

rows = db.fetch_all_as_dicts()
if not rows:
    st.warning("No data in the database yet. Run `python scripts/run_pipeline.py --synthetic` first.")
    st.stop()

df = pd.DataFrame(rows)

# --- Top summary metrics ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total threats", len(df))
col2.metric("CVEs", int((df["threat_type"] == "cve").sum()))
col3.metric("Malicious IPs", int((df["threat_type"] == "malicious_ip").sum()))
critical_count = int((df["predicted_priority"] == "Critical").sum()) if "predicted_priority" in df else 0
col4.metric("Predicted Critical", critical_count)

st.divider()

# --- Filters ---
with st.sidebar:
    st.header("Filters")
    type_filter = st.multiselect(
        "Threat type", options=sorted(df["threat_type"].dropna().unique()),
        default=list(sorted(df["threat_type"].dropna().unique())),
    )
    priority_options = ["Critical", "High", "Medium", "Low"]
    available_priorities = [p for p in priority_options if p in df.get("predicted_priority", pd.Series()).values]
    priority_filter = st.multiselect(
        "Predicted priority", options=priority_options,
        default=available_priorities or priority_options,
    )
    sort_desc = st.checkbox("Sort highest priority first", value=True)

filtered = df[df["threat_type"].isin(type_filter)]
if "predicted_priority" in filtered.columns:
    filtered = filtered[filtered["predicted_priority"].isin(priority_filter)]

# Rank primarily by priority CATEGORY (Critical > High > Medium > Low), then by the
# model's expected-severity score within that category. Sorting by score alone would
# let a "Low, high-confidence" record outrank a "High, lower-confidence" one.
PRIORITY_RANK = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
if "predicted_priority" in filtered.columns:
    filtered = filtered.copy()
    filtered["_priority_rank"] = filtered["predicted_priority"].map(PRIORITY_RANK).fillna(-1)
    score_col = "predicted_priority_score" if "predicted_priority_score" in filtered.columns else "severity_raw"
    filtered = filtered.sort_values(
        ["_priority_rank", score_col], ascending=[not sort_desc, not sort_desc]
    ).drop(columns="_priority_rank")
else:
    filtered = filtered.sort_values("severity_raw", ascending=not sort_desc)

# --- Main ranked table ---
st.subheader(f"Ranked threats ({len(filtered)})")
display_cols = ["id", "threat_type", "title", "severity_raw", "predicted_priority",
                 "predicted_priority_score", "heuristic_label", "source", "last_seen"]
display_cols = [c for c in display_cols if c in filtered.columns]
st.dataframe(filtered[display_cols], use_container_width=True, height=400)

st.divider()

# --- Drill-down on a single threat ---
st.subheader("Inspect a threat")
selected_id = st.selectbox("Select a threat ID", options=filtered["id"].tolist())
if selected_id:
    record = filtered[filtered["id"] == selected_id].iloc[0]
    left, right = st.columns(2)
    with left:
        st.markdown(f"**{record['title']}**")
        st.write(record.get("description", ""))
        st.write(f"**Source:** {record['source']}")
        st.write(f"**Severity (raw, source scale rescaled to 0-10):** {record['severity_raw']}")
        st.write(f"**Report count:** {record.get('report_count', 'n/a')}")
        st.write(f"**Last seen:** {record.get('last_seen', 'n/a')}")
    with right:
        st.write(f"**Predicted priority:** {record.get('predicted_priority', 'not yet scored')}")
        st.write(f"**Predicted priority score:** {record.get('predicted_priority_score', 'n/a')}")
        st.write(f"**Heuristic label (training target):** {record.get('heuristic_label', 'n/a')}")
        if record.get("extra_json"):
            with st.expander("Raw extra fields"):
                st.json(json.loads(record["extra_json"]))

st.divider()

# --- Model evaluation summary (if available) ---
metrics_path = REPORTS_DIR / "metrics.json"
if metrics_path.exists():
    st.subheader("Model evaluation summary")
    with open(metrics_path) as f:
        metrics = json.load(f)
    cols = st.columns(len(metrics))
    for col, (name, m) in zip(cols, metrics.items()):
        col.metric(name.replace("_", " ").title(), f"{m['accuracy']*100:.1f}% acc")

    for name in metrics:
        cm_path = REPORTS_DIR / f"confusion_matrix_{name}.png"
        if cm_path.exists():
            with st.expander(f"Confusion matrix — {name}"):
                st.image(str(cm_path))
        fi_path = REPORTS_DIR / f"feature_importance_{name}.png"
        if fi_path.exists():
            with st.expander(f"Feature importance — {name}"):
                st.image(str(fi_path))
else:
    st.info("No evaluation metrics found yet — run the training/evaluation step of the pipeline.")

st.divider()
st.caption(
    "⚠️ Priority labels used for training are derived from a documented heuristic "
    "(severity + exploitation signal + report volume + recency + source reliability), "
    "not analyst-verified ground truth. See README.md for details."
)
