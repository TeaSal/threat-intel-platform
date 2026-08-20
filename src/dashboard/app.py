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

# ─────────────────────────────────────────────
#  Page config
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Threat Intel Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
#  Global CSS — purple theme, vibrant fonts, styled tables
# ─────────────────────────────────────────────
st.markdown("""
<style>
/* ── Import font ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

/* ── Base overrides ── */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
}

/* ── Main background ── */
.stApp {
    background: linear-gradient(135deg, #0d0d1a 0%, #130d2e 50%, #0d0d1a 100%);
    color: #e8e0ff;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #1a0d3d 0%, #120929 100%);
    border-right: 1px solid #4a1d96;
}
section[data-testid="stSidebar"] * {
    color: #d4c5f9 !important;
}
section[data-testid="stSidebar"] .stMultiSelect [data-baseweb="tag"] {
    background-color: #6d28d9 !important;
}

/* ── Title ── */
h1 {
    background: linear-gradient(90deg, #a855f7, #7c3aed, #c084fc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    font-size: 2.4rem !important;
    font-weight: 800 !important;
    letter-spacing: -0.5px;
    margin-bottom: 0 !important;
}

/* ── Subheaders ── */
h2, h3 {
    color: #c084fc !important;
    font-weight: 700 !important;
    letter-spacing: -0.3px;
}

/* ── Metric cards ── */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, #1e0a4a 0%, #2d1066 100%);
    border: 1px solid #6d28d9;
    border-radius: 14px;
    padding: 18px 20px !important;
    box-shadow: 0 4px 24px rgba(109, 40, 217, 0.25);
    transition: transform 0.2s, box-shadow 0.2s;
}
[data-testid="stMetric"]:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(168, 85, 247, 0.35);
}
[data-testid="stMetricLabel"] {
    color: #a78bfa !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    text-transform: uppercase;
    letter-spacing: 1px;
}
[data-testid="stMetricValue"] {
    color: #f5f0ff !important;
    font-size: 2rem !important;
    font-weight: 800 !important;
}

/* ── Dataframe / table ── */
[data-testid="stDataFrame"] {
    border: 1px solid #4a1d96 !important;
    border-radius: 12px !important;
    overflow: hidden;
}
[data-testid="stDataFrame"] table {
    font-size: 0.92rem !important;
    font-family: 'Inter', sans-serif !important;
}
[data-testid="stDataFrame"] thead tr th {
    background: #3b0764 !important;
    color: #e9d5ff !important;
    font-weight: 700 !important;
    font-size: 0.82rem !important;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding: 12px 16px !important;
    border-bottom: 2px solid #7c3aed !important;
}
[data-testid="stDataFrame"] tbody tr {
    border-bottom: 1px solid #2d1a4e !important;
}
[data-testid="stDataFrame"] tbody tr:hover {
    background: #1e0a4a !important;
}
[data-testid="stDataFrame"] tbody tr td {
    color: #ddd6fe !important;
    padding: 11px 16px !important;
}

/* ── Divider ── */
hr {
    border-color: #4a1d96 !important;
    opacity: 0.4;
}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #6d28d9, #7c3aed);
    color: white !important;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.88rem;
    padding: 6px 18px;
    transition: all 0.2s;
    box-shadow: 0 2px 10px rgba(109, 40, 217, 0.4);
}
.stButton > button:hover {
    background: linear-gradient(135deg, #7c3aed, #9333ea);
    box-shadow: 0 4px 16px rgba(147, 51, 234, 0.5);
    transform: translateY(-1px);
}
.stButton > button:disabled {
    background: #2d1a4e !important;
    color: #6b5b9e !important;
    box-shadow: none;
    transform: none;
}

/* ── Pagination row ── */
.pagination-container {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 12px 0;
    flex-wrap: wrap;
}
.page-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 36px;
    height: 36px;
    padding: 0 10px;
    border-radius: 8px;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    border: 1px solid #4a1d96;
    background: #1a0a3d;
    color: #c4b5fd;
    transition: all 0.15s;
}
.page-btn:hover { background: #3b0764; color: #f3e8ff; }
.page-btn.active {
    background: linear-gradient(135deg, #7c3aed, #9333ea);
    border-color: #a855f7;
    color: white;
    box-shadow: 0 2px 12px rgba(168, 85, 247, 0.5);
}
.page-btn.disabled { opacity: 0.3; cursor: not-allowed; }

/* ── Priority badges ── */
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.5px;
}
.badge-critical { background: #4c0519; color: #fda4af; border: 1px solid #9f1239; }
.badge-high     { background: #431407; color: #fdba74; border: 1px solid #9a3412; }
.badge-medium   { background: #3b2509; color: #fde68a; border: 1px solid #92400e; }
.badge-low      { background: #052e16; color: #86efac; border: 1px solid #166534; }

/* ── Select box ── */
.stSelectbox label, .stMultiSelect label, .stCheckbox label {
    color: #c4b5fd !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
}

/* ── Expander ── */
details {
    background: #1a0a3d !important;
    border: 1px solid #4a1d96 !important;
    border-radius: 10px !important;
}
summary {
    color: #c084fc !important;
    font-weight: 600 !important;
    padding: 10px 14px !important;
}

/* ── Info / warning boxes ── */
.stAlert {
    border-radius: 10px !important;
    border-left: 4px solid #7c3aed !important;
    background: #1a0a3d !important;
    color: #e9d5ff !important;
}

/* ── Caption ── */
.stCaption, small {
    color: #7c5cbf !important;
}

/* ── Page info text ── */
.page-info {
    color: #9f7aea;
    font-size: 0.85rem;
    font-weight: 500;
    text-align: center;
    margin: 4px 0 8px;
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  Data load
# ─────────────────────────────────────────────
rows = db.fetch_all_as_dicts()
if not rows:
    st.warning("No data in the database yet. Run `python scripts/run_pipeline.py --synthetic` first.")
    st.stop()

df = pd.DataFrame(rows)

# ─────────────────────────────────────────────
#  Header
# ─────────────────────────────────────────────
st.markdown("# 🛡️ Threat Intelligence Dashboard")
st.caption("Consolidated CVE + malicious-IP intelligence, ranked by ML-predicted priority.")

# ─────────────────────────────────────────────
#  Top summary metrics
# ─────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Threats", f"{len(df):,}")
col2.metric("CVEs", f"{int((df['threat_type'] == 'cve').sum()):,}")
col3.metric("Malicious IPs", f"{int((df['threat_type'] == 'malicious_ip').sum()):,}")
critical_count = int((df["predicted_priority"] == "Critical").sum()) if "predicted_priority" in df else 0
col4.metric("Critical Priority", f"{critical_count:,}")

st.divider()

# ─────────────────────────────────────────────
#  Sidebar filters
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔍 Filters")
    st.markdown("---")

    type_filter = st.multiselect(
        "Threat type",
        options=sorted(df["threat_type"].dropna().unique()),
        default=list(sorted(df["threat_type"].dropna().unique())),
    )

    priority_options = ["Critical", "High", "Medium", "Low"]
    available_priorities = (
        [p for p in priority_options if p in df["predicted_priority"].values]
        if "predicted_priority" in df.columns else priority_options
    )
    priority_filter = st.multiselect(
        "Predicted priority",
        options=priority_options,
        default=available_priorities or priority_options,
    )

    sort_desc = st.checkbox("Highest priority first", value=True)

    st.markdown("---")
    rows_per_page = st.select_slider(
        "Rows per page", options=[10, 20, 25, 50], value=25
    )

    st.markdown("---")
    st.markdown(
        "<div style='color:#7c5cbf;font-size:0.75rem;'>Data source: NVD + AbuseIPDB<br>"
        "ML: Logistic Regression · Decision Tree · Random Forest</div>",
        unsafe_allow_html=True,
    )

# ─────────────────────────────────────────────
#  Filter + sort
# ─────────────────────────────────────────────
filtered = df[df["threat_type"].isin(type_filter)].copy()
if "predicted_priority" in filtered.columns:
    filtered = filtered[filtered["predicted_priority"].isin(priority_filter)]

PRIORITY_RANK = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
if "predicted_priority" in filtered.columns:
    filtered["_priority_rank"] = filtered["predicted_priority"].map(PRIORITY_RANK).fillna(-1)
    score_col = "predicted_priority_score" if "predicted_priority_score" in filtered.columns else "severity_raw"
    filtered = filtered.sort_values(
        ["_priority_rank", score_col], ascending=[not sort_desc, not sort_desc]
    ).drop(columns="_priority_rank")
else:
    filtered = filtered.sort_values("severity_raw", ascending=not sort_desc)

filtered = filtered.reset_index(drop=True)

# ─────────────────────────────────────────────
#  Pagination state
# ─────────────────────────────────────────────
total_rows = len(filtered)
total_pages = max(1, -(-total_rows // rows_per_page))  # ceiling division

if "current_page" not in st.session_state:
    st.session_state.current_page = 1

# Reset to page 1 if filters change total pages
if st.session_state.current_page > total_pages:
    st.session_state.current_page = 1

current_page = st.session_state.current_page
start_idx = (current_page - 1) * rows_per_page
end_idx = min(start_idx + rows_per_page, total_rows)
page_df = filtered.iloc[start_idx:end_idx]

# ─────────────────────────────────────────────
#  Ranked table
# ─────────────────────────────────────────────
st.markdown(f"### Ranked Threats &nbsp; <span style='color:#7c5cbf;font-size:0.9rem;font-weight:400;'>({total_rows:,} total)</span>", unsafe_allow_html=True)

display_cols = ["id", "threat_type", "title", "severity_raw", "predicted_priority",
                "predicted_priority_score", "heuristic_label", "source", "last_seen"]
display_cols = [c for c in display_cols if c in page_df.columns]

# Rename columns for display
col_rename = {
    "id": "ID",
    "threat_type": "Type",
    "title": "Title",
    "severity_raw": "Severity",
    "predicted_priority": "ML Priority",
    "predicted_priority_score": "ML Rank Score",
    "heuristic_label": "Heuristic Label",
    "source": "Source",
    "last_seen": "Last Seen",
}
display_df = page_df[display_cols].rename(columns=col_rename)

# Round numeric columns
if "Severity" in display_df.columns:
    display_df["Severity"] = display_df["Severity"].round(2)
if "ML Rank Score" in display_df.columns:
    display_df["ML Rank Score"] = display_df["ML Rank Score"].round(4)

st.dataframe(
    display_df,
    use_container_width=True,
    height=min(42 * rows_per_page + 60, 700),
    hide_index=True,
)

# ─────────────────────────────────────────────
#  Pagination controls (Gmail-style)
# ─────────────────────────────────────────────
st.markdown(
    f"<div class='page-info'>Showing {start_idx + 1}–{end_idx} of {total_rows:,} threats</div>",
    unsafe_allow_html=True,
)

# Build page number buttons using Streamlit columns
MAX_PAGE_BUTTONS = 7  # max numbered buttons to show
half = MAX_PAGE_BUTTONS // 2

if total_pages <= MAX_PAGE_BUTTONS:
    page_numbers = list(range(1, total_pages + 1))
else:
    if current_page <= half + 1:
        page_numbers = list(range(1, MAX_PAGE_BUTTONS + 1))
    elif current_page >= total_pages - half:
        page_numbers = list(range(total_pages - MAX_PAGE_BUTTONS + 1, total_pages + 1))
    else:
        page_numbers = list(range(current_page - half, current_page + half + 1))

# How many columns: Prev + page buttons + Next
n_cols = len(page_numbers) + 2
nav_cols = st.columns([1] * n_cols, gap="small")

# Previous button
with nav_cols[0]:
    if st.button("← Prev", disabled=(current_page == 1), key="prev_btn"):
        st.session_state.current_page -= 1
        st.rerun()

# Numbered page buttons
for i, pg in enumerate(page_numbers):
    with nav_cols[i + 1]:
        label = f"**{pg}**" if pg == current_page else str(pg)
        btn_type = "primary" if pg == current_page else "secondary"
        if st.button(label, key=f"page_{pg}", type=btn_type):
            st.session_state.current_page = pg
            st.rerun()

# Next button
with nav_cols[-1]:
    if st.button("Next →", disabled=(current_page == total_pages), key="next_btn"):
        st.session_state.current_page += 1
        st.rerun()

st.divider()

# ─────────────────────────────────────────────
#  Drill-down on a single threat
# ─────────────────────────────────────────────
st.markdown("### 🔎 Inspect a Threat")
selected_id = st.selectbox(
    "Select a threat ID",
    options=filtered["id"].tolist(),
    format_func=lambda x: f"{x[:60]}..." if len(str(x)) > 60 else x,
)
if selected_id:
    record = filtered[filtered["id"] == selected_id].iloc[0]
    left, right = st.columns(2)

    priority_colors = {
        "Critical": "#fda4af", "High": "#fdba74",
        "Medium": "#fde68a",   "Low": "#86efac",
    }
    priority_val = record.get("predicted_priority", "—")
    priority_color = priority_colors.get(priority_val, "#c4b5fd")

    with left:
        st.markdown(f"<h4 style='color:#e9d5ff;margin-bottom:8px;'>{record['title']}</h4>", unsafe_allow_html=True)
        st.markdown(f"<p style='color:#c4b5fd;font-size:0.9rem;'>{record.get('description', '—')}</p>", unsafe_allow_html=True)
        st.markdown(f"**Source:** `{record['source']}`")
        st.markdown(f"**Severity (0–10):** `{record['severity_raw']}`")
        st.markdown(f"**Report count:** `{record.get('report_count', 'n/a')}`")
        st.markdown(f"**Last seen:** `{record.get('last_seen', 'n/a')}`")

    with right:
        st.markdown(
            f"**Predicted priority:** <span style='color:{priority_color};font-weight:700;font-size:1.1rem;'>{priority_val}</span>",
            unsafe_allow_html=True,
        )
        st.markdown(f"**Priority score:** `{round(record.get('predicted_priority_score', 0) or 0, 4)}`")
        st.markdown(f"**Heuristic label:** `{record.get('heuristic_label', 'n/a')}`")
        if record.get("extra_json"):
            with st.expander("Raw extra fields"):
                try:
                    st.json(json.loads(record["extra_json"]))
                except Exception:
                    st.text(record["extra_json"])

st.divider()

# ─────────────────────────────────────────────
#  Model evaluation summary
# ─────────────────────────────────────────────
metrics_path = REPORTS_DIR / "metrics.json"
if metrics_path.exists():
    st.markdown("### 🤖 Model Evaluation")
    with open(metrics_path) as f:
        metrics = json.load(f)

    cols = st.columns(len(metrics))
    for col, (name, m) in zip(cols, metrics.items()):
        col.metric(
            name.replace("_", " ").title(),
            f"{m['accuracy'] * 100:.1f}%",
            help="Accuracy on held-out test set"
        )

    for name in metrics:
        cm_path = REPORTS_DIR / f"confusion_matrix_{name}.png"
        fi_path = REPORTS_DIR / f"feature_importance_{name}.png"
        if cm_path.exists() or fi_path.exists():
            with st.expander(f"📊 {name.replace('_', ' ').title()} — charts"):
                c1, c2 = st.columns(2)
                if cm_path.exists():
                    c1.image(str(cm_path), caption="Confusion Matrix")
                if fi_path.exists():
                    c2.image(str(fi_path), caption="Feature Importance")
else:
    st.info("No evaluation metrics found yet — run the training/evaluation step of the pipeline.")

st.divider()
st.caption(
    "⚠️ Priority labels used for training are derived from a documented heuristic "
    "(severity · exploitation signal · report volume · recency · source reliability · CWE risk · advisory breadth), "
    "not analyst-verified ground truth. See README.md for details."
)
