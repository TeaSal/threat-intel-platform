"""
Analyst-facing dashboard. Run with:
    streamlit run src/dashboard/app.py

Reads directly from data/threat_intel.db (the single source of truth also used
by training/evaluation), so it always reflects the latest pipeline run.

Post-Review-2 additions:
  - Tab layout: Threats | Clusters | Model Evaluation
  - Clusters tab: summary table, bar chart, notable-cluster alerts, member drill-down
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import json
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
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

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    gap: 6px;
    background: transparent !important;
    border-bottom: 1px solid #4a1d96 !important;
    padding-bottom: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    background: #1a0a3d !important;
    border: 1px solid #4a1d96 !important;
    border-bottom: none !important;
    border-radius: 8px 8px 0 0 !important;
    color: #a78bfa !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
    padding: 8px 20px !important;
    transition: all 0.2s !important;
}
.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, #3b0764, #4c1d96) !important;
    color: #f3e8ff !important;
    border-color: #7c3aed !important;
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

# Load analyst feedback and merge analyst_label into main df for the ranked table
_all_feedback = _fetch_all_feedback()
if _all_feedback:
    _fb_df = pd.DataFrame(_all_feedback)[["threat_id", "analyst_label"]]
    df = df.merge(_fb_df, left_on="id", right_on="threat_id", how="left").drop(columns="threat_id")
else:
    df["analyst_label"] = None

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
#  Sidebar filters  (apply to Threats tab only)
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
#  Tab layout
# ─────────────────────────────────────────────
from src.pipeline.db import (
    fetch_alerts as _fetch_alerts,
    fetch_unacknowledged_alert_count as _unack_count,
    update_alert_status as _update_alert_status,
)
from src.pipeline.db import (
    fetch_feedback_for_threat as _fetch_feedback,
    upsert_analyst_feedback as _upsert_feedback,
    ANALYST_LABEL_OPTIONS as _ANALYST_LABEL_OPTIONS,
    fetch_analyst_feedback as _fetch_all_feedback,
)

_unack = _unack_count()
_alerts_label = f"🚨 Alerts ({_unack})" if _unack > 0 else "🚨 Alerts"

tab_threats, tab_clusters, tab_mitre, tab_monitor, tab_alerts, tab_settings, tab_models = st.tabs([
    "🔒 Threats",
    "🔗 Clusters",
    "🧩 MITRE ATT&CK",
    "📡 Monitoring",
    _alerts_label,
    "⚙️ Settings",
    "🤖 Model Evaluation",
])

# ══════════════════════════════════════════════
#  TAB 1 — THREATS  (original content, unchanged)
# ══════════════════════════════════════════════
with tab_threats:

    # ── Filter + sort ──────────────────────────────────────────────────────
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

    # ── Pagination state ───────────────────────────────────────────────────
    total_rows = len(filtered)
    total_pages = max(1, -(-total_rows // rows_per_page))

    if "current_page" not in st.session_state:
        st.session_state.current_page = 1
    if st.session_state.current_page > total_pages:
        st.session_state.current_page = 1

    current_page = st.session_state.current_page
    start_idx = (current_page - 1) * rows_per_page
    end_idx = min(start_idx + rows_per_page, total_rows)
    page_df = filtered.iloc[start_idx:end_idx]

    # ── Ranked table ───────────────────────────────────────────────────────
    st.markdown(
        f"### Ranked Threats &nbsp; "
        f"<span style='color:#7c5cbf;font-size:0.9rem;font-weight:400;'>({total_rows:,} total)</span>",
        unsafe_allow_html=True,
    )

    display_cols = [
        "id", "threat_type", "title", "severity_raw", "predicted_priority",
        "predicted_priority_score", "context_adjusted_score", "heuristic_label", "analyst_label",
        "cluster_id", "source", "last_seen",
    ]
    display_cols = [c for c in display_cols if c in page_df.columns]

    col_rename = {
        "id": "ID",
        "threat_type": "Type",
        "title": "Title",
        "severity_raw": "Severity",
        "predicted_priority": "ML Priority",
        "predicted_priority_score": "ML Rank Score",
        "context_adjusted_score": "Ctx Score",
        "heuristic_label": "Heuristic Label",
        "analyst_label": "Analyst Label",
        "cluster_id": "Cluster",
        "source": "Source",
        "last_seen": "Last Seen",
    }
    display_df = page_df[display_cols].rename(columns=col_rename)

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

    # ── Pagination controls ────────────────────────────────────────────────
    st.markdown(
        f"<div class='page-info'>Showing {start_idx + 1}–{end_idx} of {total_rows:,} threats</div>",
        unsafe_allow_html=True,
    )

    MAX_PAGE_BUTTONS = 7
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

    n_cols = len(page_numbers) + 2
    nav_cols = st.columns([1] * n_cols, gap="small")

    with nav_cols[0]:
        if st.button("← Prev", disabled=(current_page == 1), key="prev_btn"):
            st.session_state.current_page -= 1
            st.rerun()

    for i, pg in enumerate(page_numbers):
        with nav_cols[i + 1]:
            label = f"**{pg}**" if pg == current_page else str(pg)
            btn_type = "primary" if pg == current_page else "secondary"
            if st.button(label, key=f"page_{pg}", type=btn_type):
                st.session_state.current_page = pg
                st.rerun()

    with nav_cols[-1]:
        if st.button("Next →", disabled=(current_page == total_pages), key="next_btn"):
            st.session_state.current_page += 1
            st.rerun()

    st.divider()

    # ── Drill-down on a single threat ──────────────────────────────────────
    st.markdown("### 🔎 Threat Details")
    selected_id = st.selectbox(
        "Select a threat ID to inspect",
        options=filtered["id"].tolist(),
        format_func=lambda x: f"{x[:70]}..." if len(str(x)) > 70 else x,
    )
    if selected_id:
        record = filtered[filtered["id"] == selected_id].iloc[0]

        priority_colors = {
            "Critical": "#fda4af", "High": "#fdba74",
            "Medium":   "#fde68a", "Low":  "#86efac",
        }
        priority_bg = {
            "Critical": "#4c0519", "High": "#431407",
            "Medium":   "#3b2509", "Low":  "#052e16",
        }
        priority_border = {
            "Critical": "#9f1239", "High": "#9a3412",
            "Medium":   "#92400e", "Low":  "#166534",
        }
        priority_val   = record.get("predicted_priority", "—")
        p_color  = priority_colors.get(priority_val, "#c4b5fd")
        p_bg     = priority_bg.get(priority_val,     "#1a0a3d")
        p_border = priority_border.get(priority_val, "#4a1d96")

        # ── Header banner ──────────────────────────────────────────────────
        threat_type = record.get("threat_type", "")
        type_icon   = "🛡️" if threat_type == "cve" else "🌐" if threat_type == "malicious_ip" else "⚠️"
        st.markdown(
            f"""
<div style='background:linear-gradient(135deg,#1e0a4a,#2d1066);
            border:1px solid #6d28d9;border-radius:14px;
            padding:18px 22px;margin-bottom:18px;'>
  <div style='display:flex;align-items:center;gap:12px;flex-wrap:wrap;'>
    <span style='font-size:1.6rem;'>{type_icon}</span>
    <span style='color:#e9d5ff;font-size:1.25rem;font-weight:800;'>{record['title']}</span>
    <span style='background:{p_bg};color:{p_color};border:1px solid {p_border};
                 border-radius:20px;padding:3px 12px;font-size:0.8rem;font-weight:700;'>
      {priority_val}
    </span>
    <span style='background:#1a0a3d;color:#a78bfa;border:1px solid #4a1d96;
                 border-radius:20px;padding:3px 12px;font-size:0.78rem;'>
      {threat_type.replace("_", " ").title()}
    </span>
  </div>
</div>""",
            unsafe_allow_html=True,
        )

        # ── Metric strip ───────────────────────────────────────────────────
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Severity", f"{record['severity_raw']}/10")
        m2.metric("ML Priority",    priority_val)
        m3.metric("Rank Score",     f"{round(record.get('predicted_priority_score', 0) or 0, 3)}")
        m4.metric("Report Count",   record.get("report_count", "—"))
        clid = record.get("cluster_id")
        m5.metric("Cluster",        int(clid) if pd.notna(clid) else "—")

        st.markdown("")

        # ── Two-column detail + raw fields ────────────────────────────────
        detail_col, raw_col = st.columns([3, 2])

        with detail_col:
            st.markdown("##### 📋 Record Details")
            st.markdown(f"**ID:** `{record['id']}`")
            st.markdown(f"**Source:** `{record.get('source', '—')}`")
            st.markdown(f"**Source reliability:** `{record.get('source_reliability', '—')}`")
            st.markdown(f"**First seen:** `{record.get('first_seen', '—')}`")
            st.markdown(f"**Last seen:** `{record.get('last_seen', '—')}`")
            st.markdown(f"**Heuristic label:** `{record.get('heuristic_label', '—')}`")
            exploited = bool(int(record.get("exploited_flag") or 0))
            exp_color = "#fda4af" if exploited else "#86efac"
            exp_text  = "YES — exploitation evidence present" if exploited else "No exploitation evidence in current data"
            st.markdown(
                f"**Exploitation flag:** <span style='color:{exp_color};font-weight:600;'>{exp_text}</span>",
                unsafe_allow_html=True,
            )
            if record.get("description"):
                st.markdown("**Raw description:**")
                st.markdown(
                    f"<div style='background:#130d2e;border-left:3px solid #6d28d9;"
                    f"border-radius:4px;padding:10px 14px;color:#c4b5fd;"
                    f"font-size:0.88rem;line-height:1.6;'>"
                    f"{record['description']}</div>",
                    unsafe_allow_html=True,
                )

        with raw_col:
            st.markdown("##### 🔬 Extra Fields")
            if record.get("extra_json"):
                try:
                    extra_data = json.loads(record["extra_json"]) if isinstance(record["extra_json"], str) else record["extra_json"]
                    for k, v in extra_data.items():
                        if v is not None and v != "" and v != "unknown":
                            st.markdown(f"**{k.replace('_', ' ').title()}:** `{v}`")
                except Exception:
                    st.text(record["extra_json"])
            else:
                st.caption("No extra fields available.")

        st.divider()

        # ── AI-generated Threat Summary ────────────────────────────────────
        st.markdown("##### 🧠 AI-Generated Threat Summary")
        st.caption(
            "Deterministic template-based analysis — fully reproducible, offline-capable, "
            "and grounded strictly in the structured data fields above. Not an LLM."
        )

        ai_summary = record.get("ai_summary", "")

        if not ai_summary:
            # Generate on-the-fly if the pipeline hasn't written one yet
            from src.pipeline.summarizer import generate_summary
            ai_summary = generate_summary(dict(record))

        # Render each section as a styled card
        sections = [s.strip() for s in ai_summary.split("\n\n") if s.strip()]
        section_icons = {
            "What this threat is":   "📌",
            "Why it matters":        "⚡",
            "Severity":              "🎯",
            "Exploitation status":   "💥",
            "Relevant indicators":   "📊",
            "Priority assigned":     "🏷️",
            "Analyst recommendation":"💡",
        }

        for section in sections:
            # Extract the bold header (text between ** and **)
            header = ""
            if section.startswith("**"):
                end = section.find("**", 2)
                if end > 2:
                    header = section[2:end].rstrip(":")
            icon = next((v for k, v in section_icons.items() if k.lower() in header.lower()), "•")

            is_rec = "recommendation" in header.lower()
            bg_color  = "#1c0a38" if not is_rec else "#0a2218"
            border_c  = "#4a1d96" if not is_rec else "#166534"
            hdr_color = "#c084fc" if not is_rec else "#86efac"

            body_html = (
                section
                .replace("**" + header + ":**\n", "")
                .replace("**" + header + ":**",    "")
                .replace("**" + header + "**\n",   "")
                .replace("\n- ", "<br>• ")
                .replace("\n",   "<br>")
            )
            # Bold inline **text**
            import re as _re
            body_html = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", body_html)

            st.markdown(
                f"""
<div style='background:{bg_color};border:1px solid {border_c};border-left:4px solid {border_c};
            border-radius:10px;padding:14px 18px;margin-bottom:10px;'>
  <div style='color:{hdr_color};font-weight:700;font-size:0.92rem;margin-bottom:6px;'>
    {icon} {header}
  </div>
  <div style='color:#c4b5fd;font-size:0.88rem;line-height:1.65;'>
    {body_html}
  </div>
</div>""",
                unsafe_allow_html=True,
            )

        st.divider()

        # ── Phase 8: Why this priority? ────────────────────────────────────
        st.markdown("##### 🔍 Why This Priority?")
        st.caption(
            "Feature contribution analysis — shows which input signals most influenced "
            "the ML model's priority assignment. Derived from the Random Forest's own "
            "feature importances, not a post-hoc approximation."
        )

        explanation_json_raw = record.get("explanation_json")
        exp_data = None
        if explanation_json_raw:
            try:
                exp_data = json.loads(explanation_json_raw) if isinstance(explanation_json_raw, str) else explanation_json_raw
            except (ValueError, TypeError):
                exp_data = None

        if not exp_data:
            # Generate on-the-fly if pipeline hasn't written it yet
            try:
                import joblib as _joblib
                from src.pipeline.explainer import explain_prediction as _explain_pred
                from src.pipeline.feature_engineering import build_feature_matrix as _build_feat
                from src.config import MODELS_DIR as _MODELS_DIR
                _model = _joblib.load(_MODELS_DIR / "random_forest.joblib")
                _feats, _fcols = _build_feat([dict(record)])
                if not _feats.empty:
                    _row_dict = _feats.iloc[0].to_dict()
                    _row_dict.update({k: v for k, v in dict(record).items() if k not in _row_dict})
                    exp_data = _explain_pred(_row_dict, _model, _fcols)
            except Exception:
                exp_data = None

        if not exp_data:
            st.markdown(
                "<div style='background:#1a0a3d;border:1px solid #4a1d96;border-radius:8px;"
                "padding:12px 16px;color:#7c5cbf;font-size:0.86rem;'>"
                "Explanation not available yet. Re-run the pipeline to generate explanations."
                "</div>",
                unsafe_allow_html=True,
            )
        else:
            # Plain-English summary
            plain = exp_data.get("plain_english", "")
            method_label = "SHAP" if exp_data.get("method") == "shap" else "Feature Contribution"
            confidence = exp_data.get("confidence", 0)

            st.markdown(
                f"<div style='background:#0a2218;border:1px solid #166534;border-left:4px solid #166534;"
                f"border-radius:8px;padding:12px 16px;margin-bottom:12px;'>"
                f"<span style='color:#86efac;font-weight:700;font-size:0.9rem;'>💡 </span>"
                f"<span style='color:#d1fae5;font-size:0.9rem;'>{plain}</span>"
                f"<span style='color:#5b21b6;font-size:0.76rem;margin-left:10px;'>[{method_label}]</span>"
                f"</div>",
                unsafe_allow_html=True,
            )

            # Horizontal bar chart of top-5 feature contributions
            top_feats = exp_data.get("top_features", [])
            if top_feats:
                feat_labels = [f["label"] for f in top_feats]
                feat_contribs = [f["contribution"] for f in top_feats]
                feat_values   = [f["value"]        for f in top_feats]
                bar_colors    = [
                    "#86efac" if c >= 0 else "#fda4af"
                    for c in feat_contribs
                ]

                fig_exp, ax_exp = plt.subplots(figsize=(7, max(2.2, len(top_feats) * 0.55)))
                fig_exp.patch.set_facecolor("#0d0d1a")
                ax_exp.set_facecolor("#130d2e")
                bars = ax_exp.barh(
                    feat_labels[::-1], [abs(c) for c in feat_contribs[::-1]],
                    color=bar_colors[::-1], edgecolor="#4a1d96", linewidth=0.7,
                )
                ax_exp.set_xlabel("Contribution (absolute)", color="#a78bfa", fontsize=8)
                ax_exp.set_title(
                    f"Top Feature Contributions → {exp_data.get('predicted_class','?')}",
                    color="#c084fc", fontsize=10, fontweight="bold",
                )
                ax_exp.tick_params(colors="#c4b5fd", labelsize=8)
                ax_exp.spines[:].set_color("#4a1d96")
                # Annotate each bar with the actual feature value
                for bar, val, contrib in zip(bars, feat_values[::-1], feat_contribs[::-1]):
                    sign = "+" if contrib >= 0 else "−"
                    ax_exp.text(
                        bar.get_width() + 0.001,
                        bar.get_y() + bar.get_height() / 2,
                        f"{sign}  val={val:.3f}",
                        va="center", color="#c4b5fd", fontsize=7.5,
                    )
                plt.tight_layout(pad=0.4)
                st.pyplot(fig_exp, use_container_width=True)
                plt.close(fig_exp)

                # Feature table
                tbl_rows = ""
                for f in top_feats:
                    dirn_col = "#86efac" if f["direction"] == "+" else "#fda4af"
                    tbl_rows += (
                        f"<tr>"
                        f"<td style='color:#c4b5fd;'>{f['label']}</td>"
                        f"<td style='text-align:right;'>{f['value']:.4f}</td>"
                        f"<td style='text-align:right;color:{dirn_col};font-weight:700;'>"
                        f"{f['direction']}{abs(f['contribution']):.4f}</td>"
                        f"</tr>"
                    )
                st.markdown(
                    "<div style='margin-top:8px;'>"
                    "<table style='width:100%;border-collapse:collapse;font-size:0.82rem;'>"
                    "<thead><tr>"
                    "<th style='color:#a78bfa;font-weight:700;text-align:left;padding:4px 8px;"
                    "border-bottom:1px solid #4a1d96;'>Feature</th>"
                    "<th style='color:#a78bfa;font-weight:700;text-align:right;padding:4px 8px;"
                    "border-bottom:1px solid #4a1d96;'>Value</th>"
                    "<th style='color:#a78bfa;font-weight:700;text-align:right;padding:4px 8px;"
                    "border-bottom:1px solid #4a1d96;'>Contribution</th>"
                    "</tr></thead>"
                    f"<tbody>{tbl_rows}</tbody></table></div>",
                    unsafe_allow_html=True,
                )

        st.divider()

        # ── MITRE ATT&CK mappings for this specific threat ─────────────────
        st.markdown("##### 🧩 MITRE ATT&CK Associations")

        from src.pipeline.db import fetch_mitre_for_threat as _fetch_mitre
        threat_mitre = _fetch_mitre(selected_id)

        CONF_STYLES = {
            "High":   ("#052e16", "#86efac", "#166534"),
            "Medium": ("#3b2509", "#fde68a", "#92400e"),
            "Low":    ("#431407", "#fdba74", "#9a3412"),
        }

        if not threat_mitre:
            st.markdown(
                "<div style='background:#1a0a3d;border:1px solid #4a1d96;border-radius:8px;"
                "padding:12px 16px;color:#7c5cbf;font-size:0.86rem;'>"
                "No MITRE ATT&CK mappings available for this threat. "
                "This may occur when the CVE has no CWE assignment and the description "
                "does not contain recognisable technique keywords, or when this is a "
                "malicious IP record with no additional context signals."
                "</div>",
                unsafe_allow_html=True,
            )
        else:
            st.caption(
                f"{len(threat_mitre)} technique(s) inferred. "
                "Confidence reflects the strength of the evidence: "
                "High = CWE-based · Medium = keyword-based · Low = type-level inference."
            )
            for m in threat_mitre:
                conf = m.get("confidence", "Low")
                mbg, mfg, mborder = CONF_STYLES.get(conf, CONF_STYLES["Low"])
                tech_id   = m["technique_id"]
                tech_url  = (
                    "https://attack.mitre.org/techniques/"
                    + tech_id.replace(".", "/")
                )
                st.markdown(
                    f"""
<div style='background:{mbg};border:1px solid {mborder};border-left:4px solid {mborder};
            border-radius:8px;padding:12px 16px;margin-bottom:8px;'>
  <div style='display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;'>
    <div>
      <span style='background:{mborder}55;color:{mfg};border-radius:10px;
                   padding:2px 8px;font-size:0.72rem;font-weight:700;
                   letter-spacing:0.5px;'>{conf.upper()}</span>
      <span style='color:#e9d5ff;font-weight:700;font-size:0.95rem;margin-left:8px;'>
        {tech_id}
      </span>
      <span style='color:#c4b5fd;font-size:0.9rem;margin-left:4px;'>
        — {m['technique_name']}
      </span>
      <div style='color:#a78bfa;font-size:0.82rem;margin-top:3px;'>
        Tactic: <b>{m['tactic']}</b>
      </div>
    </div>
    <a href='{tech_url}' target='_blank'
       style='background:#2d1066;color:#c084fc;border:1px solid #6d28d9;
              border-radius:6px;padding:3px 10px;font-size:0.76rem;
              text-decoration:none;font-weight:600;white-space:nowrap;'>
      ATT&amp;CK ↗
    </a>
  </div>
  <div style='color:#9f7aea;font-size:0.8rem;margin-top:6px;
              border-top:1px solid {mborder};padding-top:6px;'>
    <b>Basis:</b> {m.get('basis', '—')}
  </div>
</div>""",
                    unsafe_allow_html=True,
                )

    st.divider()

    # ── Phase 9: Analyst Feedback ──────────────────────────────────────────
    if selected_id:
        st.markdown("### 🏷️ Analyst Feedback")
        st.caption(
            "Validate or correct the ML prediction. Analyst labels are stored separately "
            "and never overwrite the heuristic or ML labels. All three labels are shown "
            "side-by-side so discrepancies are immediately visible."
        )

        _record = filtered[filtered["id"] == selected_id].iloc[0]
        _heuristic  = _record.get("heuristic_label",    "—")
        _ml_pred    = _record.get("predicted_priority",  "—")
        _existing_fb = _fetch_feedback(selected_id)
        _current_analyst_label = _existing_fb["analyst_label"] if _existing_fb else None

        LABEL_COLORS = {
            "Critical":           "#fda4af", "High":     "#fdba74",
            "Medium":             "#fde68a", "Low":      "#86efac",
            "Confirmed_Critical": "#fda4af", "Confirmed_High":   "#fdba74",
            "Confirmed_Medium":   "#fde68a", "Confirmed_Low":    "#86efac",
            "False_Positive":     "#93c5fd", "Needs_Review":     "#d8b4fe",
        }
        LABEL_BG = {
            "Critical":           "#4c0519", "High":     "#431407",
            "Medium":             "#3b2509", "Low":      "#052e16",
            "Confirmed_Critical": "#4c0519", "Confirmed_High":   "#431407",
            "Confirmed_Medium":   "#3b2509", "Confirmed_Low":    "#052e16",
            "False_Positive":     "#0c1a4a", "Needs_Review":     "#2e1065",
        }

        def _label_chip(label, title):
            fg = LABEL_COLORS.get(str(label) if label else "", "#c4b5fd")
            bg = LABEL_BG.get(str(label) if label else "", "#1a0a3d")
            disp = label if label else "—"
            return (
                f"<div style='text-align:center;'>"
                f"<div style='color:#7c5cbf;font-size:0.72rem;font-weight:600;"
                f"text-transform:uppercase;letter-spacing:0.8px;margin-bottom:6px;'>{title}</div>"
                f"<span style='background:{bg};color:{fg};border:1px solid {fg}44;"
                f"border-radius:20px;padding:4px 14px;font-size:0.82rem;font-weight:700;'>"
                f"{disp}</span></div>"
            )

        chip_cols = st.columns(3)
        chip_cols[0].markdown(_label_chip(_heuristic,  "Heuristic Label"),         unsafe_allow_html=True)
        chip_cols[1].markdown(_label_chip(_ml_pred,    "ML Predicted"),            unsafe_allow_html=True)
        chip_cols[2].markdown(_label_chip(_current_analyst_label, "Analyst Validated"), unsafe_allow_html=True)

        st.markdown("")

        with st.form(key=f"feedback_form_{selected_id}", clear_on_submit=False):
            fc1, fc2, fc3 = st.columns([2, 3, 1.2])
            _default_idx = (
                _ANALYST_LABEL_OPTIONS.index(_current_analyst_label)
                if _current_analyst_label and _current_analyst_label in _ANALYST_LABEL_OPTIONS
                else 0
            )
            chosen_label = fc1.selectbox(
                "Analyst Label", options=_ANALYST_LABEL_OPTIONS,
                index=_default_idx, key=f"al_label_{selected_id}",
                help="Select your validated priority assessment for this threat.",
            )
            chosen_notes = fc2.text_input(
                "Notes (optional)",
                value=_existing_fb["feedback_notes"] if _existing_fb and _existing_fb.get("feedback_notes") else "",
                key=f"al_notes_{selected_id}",
                placeholder="e.g. Confirmed via internal vuln scan, false positive — internal host",
            )
            fc3.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
            submitted = fc3.form_submit_button("✅ Submit", type="primary")
            if submitted:
                _upsert_feedback(
                    threat_id=selected_id,
                    analyst_label=chosen_label,
                    notes=chosen_notes,
                    analyst_id="analyst_1",
                )
                st.success(f"Feedback saved: **{chosen_label}** for `{selected_id[:60]}`")
                st.rerun()

        if _existing_fb:
            _ts_upd = str(_existing_fb.get("updated_at", ""))[:19].replace("T", " ")
            st.markdown(
                f"<div style='background:#1a0a3d;border:1px solid #4a1d96;"
                f"border-radius:8px;padding:10px 16px;margin-top:6px;"
                f"font-size:0.82rem;color:#9f7aea;'>"
                f"Last updated: <b style='color:#c4b5fd;'>{_ts_upd}</b> "
                f"by <b style='color:#c4b5fd;'>{_existing_fb.get('analyst_id','—')}</b>"
                + (f"<br>Notes: <span style='color:#c4b5fd;'>{_existing_fb.get('feedback_notes','')}</span>"
                   if _existing_fb.get("feedback_notes") else "")
                + "</div>",
                unsafe_allow_html=True,
            )

    st.divider()
    st.caption(
        "⚠️ Priority labels used for training are derived from a documented heuristic "
        "(severity · exploitation signal · report volume · recency · source reliability · CWE risk · advisory breadth), "
        "not analyst-verified ground truth. See README.md for details."
    )


# ══════════════════════════════════════════════
#  TAB 2 — CLUSTERS  (Phase 1 — redesigned)
# ══════════════════════════════════════════════
with tab_clusters:

    # ── Helper: generate NLP cluster summary ──────────────────────────────
    def _cluster_nlp_summary(cid: int, g: pd.DataFrame, avg_sev: float,
                              pct_exp: float, dominant: str, types_str: str,
                              sources_str: str, n_critical: int, n_high: int) -> str:
        """
        Builds a deterministic, template-based analyst summary that explains:
        - what kind of threats are in this cluster
        - why they were grouped together (shared feature profile)
        - why they may be concerning
        - severity assessment
        This is rule-based NLP, not an LLM — fully reproducible and offline.
        """
        n = len(g)
        lines = []

        # ── What kind of threats ──
        has_cve = "cve" in types_str
        has_ip  = "malicious_ip" in types_str
        if has_cve and has_ip:
            kind = "a mixed group of CVEs and malicious IP addresses"
        elif has_cve:
            kind = "CVE vulnerabilities"
        else:
            kind = "malicious IP addresses"

        lines.append(
            f"This cluster groups **{n} {kind}** that share a similar "
            f"threat profile across severity, exploitation status, reporting volume, "
            f"recency, and source reliability."
        )

        # ── Why grouped together (feature explanation) ──
        clustering_reasons = []
        if avg_sev >= 8.5:
            clustering_reasons.append("uniformly very high severity scores (≥ 8.5/10)")
        elif avg_sev >= 6.5:
            clustering_reasons.append("consistently elevated severity scores (≥ 6.5/10)")
        elif avg_sev >= 4.0:
            clustering_reasons.append("moderate severity scores (4–6.5/10)")
        else:
            clustering_reasons.append("relatively low severity scores (< 4/10)")

        if pct_exp >= 80:
            clustering_reasons.append("nearly all members carry active exploitation evidence")
        elif pct_exp >= 30:
            clustering_reasons.append(f"a significant portion ({pct_exp:.0f}%) have exploitation indicators")
        elif pct_exp == 0:
            clustering_reasons.append("no members carry exploitation evidence in the available data")

        if "abuseipdb" in sources_str and "nvd" not in sources_str:
            clustering_reasons.append(
                "all originate from AbuseIPDB, indicating community-reported abuse activity"
            )
        elif "nvd" in sources_str and "abuseipdb" not in sources_str:
            clustering_reasons.append(
                "all originate from NVD, reflecting formally catalogued software vulnerabilities"
            )
        else:
            clustering_reasons.append(
                "members span both NVD and AbuseIPDB, combining vulnerability and abuse-IP intelligence"
            )

        lines.append(
            "**Why grouped together:** The K-Means algorithm placed these threats in the same "
            "cluster because they scored similarly on: "
            + "; ".join(clustering_reasons) + "."
        )

        # ── Why concerning / malicious ──
        concern_lines = []
        if has_ip:
            concern_lines.append(
                "The malicious IPs in this cluster have been independently reported to AbuseIPDB "
                "with a confidence score above the platform threshold (≥ 50%), indicating "
                "repeated abusive behaviour such as scanning, brute-force attacks, or spam."
            )
        if has_cve:
            concern_lines.append(
                "The CVEs represent formally catalogued software vulnerabilities with assigned "
                "CVSS base scores. High CVSS scores indicate that exploitation could lead to "
                "significant impact such as remote code execution, privilege escalation, or "
                "data exposure."
            )
        if pct_exp > 0:
            concern_lines.append(
                f"Exploitation evidence is present for {pct_exp:.0f}% of this cluster's members, "
                "meaning public exploit code or active exploitation has been observed — "
                "these are not merely theoretical risks."
            )
        lines.append("**Why they may be concerning:** " + " ".join(concern_lines))

        # ── Severity assessment ──
        if avg_sev >= 9.0:
            sev_verdict = (
                f"**Severity assessment:** CRITICAL — average severity {avg_sev:.1f}/10. "
                "This cluster warrants immediate analyst attention. Threats at this severity "
                "level typically allow unauthenticated remote exploitation with critical impact."
            )
        elif avg_sev >= 7.0:
            sev_verdict = (
                f"**Severity assessment:** HIGH — average severity {avg_sev:.1f}/10. "
                "These threats represent a significant risk. Analyst review and prompt "
                "remediation or blocking is recommended."
            )
        elif avg_sev >= 4.5:
            sev_verdict = (
                f"**Severity assessment:** MEDIUM — average severity {avg_sev:.1f}/10. "
                "These threats require attention but may be lower priority than Critical/High "
                "clusters. Standard patch and monitoring processes apply."
            )
        else:
            sev_verdict = (
                f"**Severity assessment:** LOW — average severity {avg_sev:.1f}/10. "
                "These threats pose a limited immediate risk based on available data. "
                "Continue routine monitoring."
            )
        lines.append(sev_verdict)

        # ── Priority breakdown ──
        if n_critical > 0 or n_high > 0:
            lines.append(
                f"**Priority breakdown:** {n_critical} Critical · {n_high} High "
                f"· {n - n_critical - n_high} Medium/Low threats in this cluster."
            )

        # ── Analyst recommendation ──
        if avg_sev >= 8.5 or pct_exp >= 50:
            rec = (
                "Analyst recommendation: **Escalate immediately.** Cross-reference with your "
                "organisation's asset inventory to confirm exposure. Consider emergency patching "
                "or IP blocking for confirmed matches."
            )
        elif avg_sev >= 6.5 or n_high >= 5:
            rec = (
                "Analyst recommendation: **Review within 24–48 hours.** Verify whether affected "
                "software or IP ranges are present in your environment and prioritise accordingly."
            )
        else:
            rec = (
                "Analyst recommendation: **Track and monitor.** Add to the watch list and "
                "reassess if severity or exploitation status changes in the next pipeline run."
            )
        lines.append(rec)

        return "\n\n".join(lines)


    # ── Severity colour helpers ────────────────────────────────────────────
    def _sev_color(avg_sev: float) -> str:
        if avg_sev >= 9.0:   return "#ef4444"   # red   — critical
        if avg_sev >= 7.0:   return "#f97316"   # orange — high
        if avg_sev >= 4.5:   return "#eab308"   # yellow — medium
        return "#22c55e"                          # green  — low

    def _sev_label(avg_sev: float) -> str:
        if avg_sev >= 9.0:  return "CRITICAL"
        if avg_sev >= 7.0:  return "HIGH"
        if avg_sev >= 4.5:  return "MEDIUM"
        return "LOW"

    def _priority_donut(g: pd.DataFrame, cid: int):
        """Small donut chart showing priority breakdown for one cluster."""
        if "predicted_priority" not in g.columns:
            return None
        counts = g["predicted_priority"].value_counts()
        labels_order = ["Critical", "High", "Medium", "Low"]
        colors_map = {
            "Critical": "#ef4444", "High": "#f97316",
            "Medium":   "#eab308", "Low":  "#22c55e",
        }
        present = [l for l in labels_order if l in counts]
        vals    = [counts[l] for l in present]
        cols    = [colors_map[l] for l in present]

        fig, ax = plt.subplots(figsize=(2.8, 2.8))
        fig.patch.set_facecolor("#1a0a3d")
        ax.set_facecolor("#1a0a3d")
        wedges, _ = ax.pie(
            vals, labels=None, colors=cols,
            startangle=90, counterclock=False,
            wedgeprops={"width": 0.55, "edgecolor": "#1a0a3d", "linewidth": 2},
        )
        total = sum(vals)
        ax.text(0, 0, str(total), ha="center", va="center",
                color="#e9d5ff", fontsize=13, fontweight="bold")
        ax.set_title(f"C{cid}", color="#c084fc", fontsize=9, fontweight="bold", pad=4)
        plt.tight_layout(pad=0.3)
        return fig

    # ─────────────────────────────────────────────────────────────────────
    st.markdown("### 🔗 Threat Clusters")

    # Explanation box
    st.markdown("""
<div style='background:#1a0a3d;border:1px solid #4a1d96;border-radius:10px;
            padding:14px 18px;margin-bottom:16px;font-size:0.88rem;color:#c4b5fd;'>
<b style='color:#a855f7'>How clustering works</b><br>
Threats are grouped using <b>K-Means</b> on 7 features:
<code>severity</code>, <code>exploited_flag</code>, <code>recency_score</code>,
<code>report_count</code>, <code>source_reliability</code>, <code>is_cve</code>,
<code>is_malicious_ip</code> — enriched with a lightweight TF-IDF text signal
from titles/descriptions (weighted 30%). The number of clusters <b>k</b> is chosen
automatically (k = 3–8) by maximising the <em>silhouette score</em>.<br><br>
<b style='color:#a855f7'>Effect of reducing k:</b>
Fewer clusters → each cluster becomes broader and less specific, mixing threats that are
only loosely similar. This reduces the analyst's ability to distinguish
high-severity CVEs from medium-risk IPs, for example.
A lower k is <em>not advised</em> unless the dataset is very small (< 50 threats);
the auto-selection already finds the statistically optimal value.<br><br>
<b style='color:#f87171'>⚠️ Important:</b>
A cluster reflects <em>statistical similarity in measurable features</em>, not a confirmed
real-world campaign. Treat cluster membership as an investigative starting point,
not a definitive attribution.
</div>
""", unsafe_allow_html=True)

    # Check if clustering has been run
    has_clusters = (
        "cluster_id" in df.columns
        and df["cluster_id"].notna().any()
    )

    if not has_clusters:
        st.info(
            "No cluster data found. Re-run the pipeline to generate clusters:\n\n"
            "```\npython scripts/run_pipeline.py --retrain\n```"
        )
    else:
        cluster_df = df[df["cluster_id"].notna()].copy()
        cluster_df["cluster_id"] = cluster_df["cluster_id"].astype(int)

        # ── Build per-cluster stats ────────────────────────────────────────
        cluster_stats = {}
        for cid in sorted(cluster_df["cluster_id"].unique()):
            g = cluster_df[cluster_df["cluster_id"] == cid]
            n_critical = int((g["predicted_priority"] == "Critical").sum()) if "predicted_priority" in g.columns else 0
            n_high     = int((g["predicted_priority"] == "High").sum())     if "predicted_priority" in g.columns else 0
            dominant   = g["predicted_priority"].value_counts().index[0]    if "predicted_priority" in g.columns and len(g) > 0 else "—"
            types_d    = g["threat_type"].value_counts().to_dict()           if "threat_type" in g.columns else {}
            sources_d  = g["source"].value_counts().to_dict()                if "source"      in g.columns else {}
            types_str  = ", ".join(f"{t}({c})" for t, c in types_d.items())
            sources_str= ", ".join(f"{s}({c})" for s, c in sources_d.items())
            avg_sev    = round(float(g["severity_raw"].mean()), 2)
            pct_exp    = round(float(g["exploited_flag"].mean()) * 100, 1) if "exploited_flag" in g.columns else 0.0
            is_notable = avg_sev >= 7.0 or pct_exp >= 20.0 or n_critical >= 3

            cluster_stats[cid] = dict(
                g=g, n=len(g), avg_sev=avg_sev, pct_exp=pct_exp,
                dominant=dominant, types_str=types_str, sources_str=sources_str,
                n_critical=n_critical, n_high=n_high, is_notable=is_notable,
            )

        # Sort clusters: notable first, then by avg_sev desc
        sorted_cids = sorted(
            cluster_stats.keys(),
            key=lambda c: (not cluster_stats[c]["is_notable"], -cluster_stats[c]["avg_sev"])
        )

        # ── Visualisation row: donut charts side-by-side ──────────────────
        st.markdown("#### Priority Distribution per Cluster")
        donut_cols = st.columns(len(sorted_cids))
        for col, cid in zip(donut_cols, sorted_cids):
            cs = cluster_stats[cid]
            fig = _priority_donut(cs["g"], cid)
            if fig:
                col.pyplot(fig, use_container_width=True)
                plt.close(fig)
            sev_col = _sev_color(cs["avg_sev"])
            col.markdown(
                f"<div style='text-align:center;font-size:0.75rem;color:{sev_col};"
                f"font-weight:700;margin-top:-8px;'>"
                f"{_sev_label(cs['avg_sev'])} · {cs['avg_sev']}/10</div>",
                unsafe_allow_html=True,
            )

        st.divider()

        # ── Severity bar chart ─────────────────────────────────────────────
        st.markdown("#### Cluster Size & Severity")
        fig2, axes = plt.subplots(1, 2, figsize=(11, 3.6))
        fig2.patch.set_facecolor("#0d0d1a")
        bar_colors = [_sev_color(cluster_stats[c]["avg_sev"]) for c in sorted_cids]
        x_labels   = [f"Cluster {c}" for c in sorted_cids]
        avg_sevs   = [cluster_stats[c]["avg_sev"] for c in sorted_cids]
        sizes      = [cluster_stats[c]["n"]       for c in sorted_cids]

        for ax, vals, title, ylabel, fmt in [
            (axes[0], avg_sevs, "Avg Severity per Cluster", "Severity (0–10)", "{:.1f}"),
            (axes[1], sizes,    "Cluster Size (# Threats)", "# Threats",       "{}"),
        ]:
            ax.set_facecolor("#130d2e")
            bars = ax.bar(x_labels, vals, color=bar_colors, edgecolor="#4a1d96", linewidth=0.8)
            ax.set_title(title, color="#c084fc", fontsize=10, fontweight="bold")
            ax.set_ylabel(ylabel, color="#a78bfa", fontsize=8)
            ax.tick_params(colors="#c4b5fd", labelsize=8)
            ax.spines[:].set_color("#4a1d96")
            if ylabel == "Severity (0–10)":
                ax.set_ylim(0, 10.8)
            for bar, val in zip(bars, vals):
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + (0.15 if isinstance(val, float) else 1),
                    fmt.format(val), ha="center", va="bottom",
                    color="#e9d5ff", fontsize=8, fontweight="bold",
                )
        plt.tight_layout()
        st.pyplot(fig2, use_container_width=True)
        plt.close(fig2)

        st.divider()

        # ── Clickable cluster cards ────────────────────────────────────────
        st.markdown("#### Cluster Details")
        st.caption("Click a cluster card to expand its full analysis, including an NLP-generated analyst summary and member threats.")

        for cid in sorted_cids:
            cs = cluster_stats[cid]
            sev_col   = _sev_color(cs["avg_sev"])
            sev_label = _sev_label(cs["avg_sev"])
            notable_badge = (
                "<span style='background:#7f1d1d;color:#fca5a5;border:1px solid #ef4444;"
                "border-radius:12px;padding:2px 8px;font-size:0.72rem;font-weight:700;"
                "margin-left:8px;'>⚠ NOTABLE</span>"
                if cs["is_notable"] else ""
            )
            exp_badge = (
                f"<span style='background:#1c1917;color:#fb923c;border:1px solid #f97316;"
                f"border-radius:12px;padding:2px 8px;font-size:0.72rem;font-weight:700;"
                f"margin-left:6px;'>{cs['pct_exp']:.0f}% exploited</span>"
                if cs["pct_exp"] > 0 else ""
            )

            card_header = (
                f"<span style='color:{sev_col};font-weight:800;font-size:1.05rem;'>"
                f"Cluster {cid}</span>"
                f"<span style='color:#7c5cbf;font-size:0.88rem;margin-left:10px;'>"
                f"{cs['n']} threats</span>"
                f"<span style='background:{sev_col}22;color:{sev_col};border:1px solid {sev_col}55;"
                f"border-radius:12px;padding:2px 9px;font-size:0.75rem;font-weight:700;"
                f"margin-left:8px;'>{sev_label} · {cs['avg_sev']}/10</span>"
                f"{notable_badge}{exp_badge}"
            )

            with st.expander(f"Cluster {cid}  —  {sev_label} severity · {cs['n']} threats"
                             + ("  ⚠ NOTABLE" if cs["is_notable"] else ""), expanded=cs["is_notable"]):

                st.markdown(card_header, unsafe_allow_html=True)
                st.markdown("")

                # Stats row
                stat_c1, stat_c2, stat_c3, stat_c4 = st.columns(4)
                stat_c1.metric("Avg Severity", f"{cs['avg_sev']}/10")
                stat_c2.metric("% Exploited",  f"{cs['pct_exp']:.0f}%")
                stat_c3.metric("Critical",     cs["n_critical"])
                stat_c4.metric("High",         cs["n_high"])

                st.markdown("")
                ic1, ic2 = st.columns(2)
                ic1.markdown(f"**Threat types:** `{cs['types_str']}`")
                ic2.markdown(f"**Sources:** `{cs['sources_str']}`")
                ic1.markdown(f"**Dominant priority:** `{cs['dominant']}`")

                st.divider()

                # NLP analyst summary
                st.markdown("##### 🧠 Analyst Summary")
                summary_text = _cluster_nlp_summary(
                    cid, cs["g"], cs["avg_sev"], cs["pct_exp"],
                    cs["dominant"], cs["types_str"], cs["sources_str"],
                    cs["n_critical"], cs["n_high"],
                )
                st.markdown(summary_text)

                st.divider()

                # Member threats — hidden by default inside a nested expander
                with st.expander(f"🔍 View all {cs['n']} member threats", expanded=False):
                    members = cs["g"].copy()
                    if "predicted_priority" in members.columns:
                        members["_rank"] = members["predicted_priority"].map(
                            {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
                        ).fillna(0)
                        members = members.sort_values(
                            ["_rank", "severity_raw"], ascending=[False, False]
                        ).drop(columns="_rank")

                    m_cols = ["id", "threat_type", "title", "severity_raw",
                              "predicted_priority", "exploited_flag", "source", "last_seen"]
                    m_cols = [c for c in m_cols if c in members.columns]
                    m_rename = {
                        "id": "ID", "threat_type": "Type", "title": "Title",
                        "severity_raw": "Severity", "predicted_priority": "ML Priority",
                        "exploited_flag": "Exploited", "source": "Source", "last_seen": "Last Seen",
                    }
                    m_df = members[m_cols].rename(columns=m_rename)
                    if "Severity" in m_df.columns:
                        m_df["Severity"] = m_df["Severity"].round(2)
                    st.dataframe(m_df, use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════
#  TAB 3 — MITRE ATT&CK  (Phase 3)
# ══════════════════════════════════════════════
with tab_mitre:

    st.markdown("### 🧩 MITRE ATT&CK Mappings")
    st.markdown("""
<div style='background:#1a0a3d;border:1px solid #4a1d96;border-radius:10px;
            padding:14px 18px;margin-bottom:16px;font-size:0.88rem;color:#c4b5fd;'>
<b style='color:#a855f7'>How mappings are inferred</b><br>
Mappings are produced by three evidence tiers, applied conservatively:
<ul style='margin:6px 0 0 0;padding-left:18px;'>
  <li><b style='color:#86efac'>High confidence</b> — CWE weakness class has a documented,
      well-established relationship to an ATT&amp;CK technique
      (e.g. CWE-89 SQL Injection → T1190 Exploit Public-Facing Application).</li>
  <li><b style='color:#fde68a'>Medium confidence</b> — CVE description text contains specific
      technical keywords that strongly indicate a technique
      (e.g. "remote code execution" → T1203).</li>
  <li><b style='color:#fdba74'>Low confidence</b> — Threat type or IP metadata provides only
      a broad tactic-level inference (malicious IPs → Reconnaissance / Initial Access).</li>
</ul>
<br>
<b style='color:#f87171'>⚠️ Important limitations:</b>
These are <em>inferred</em> mappings from limited structured fields, not analyst-verified
ATT&amp;CK assignments. A single CVE may enable multiple techniques not captured here.
IP records lack the protocol/payload context needed for precise technique-level mapping.
Treat all mappings as investigative starting points.
</div>
""", unsafe_allow_html=True)

    # Load all mappings from DB
    from src.pipeline.db import fetch_all_mitre_mappings, fetch_mitre_for_threat

    all_mitre = fetch_all_mitre_mappings()

    if not all_mitre:
        st.info(
            "No MITRE mappings found yet. Re-run the pipeline to generate them:\n\n"
            "```\npython scripts/run_pipeline.py --retrain\n```"
        )
    else:
        mitre_df = pd.DataFrame(all_mitre)

        # ── Summary metrics ────────────────────────────────────────────────
        total_maps   = len(mitre_df)
        n_threats    = mitre_df["threat_id"].nunique()
        n_techniques = mitre_df["technique_id"].nunique()
        n_tactics    = mitre_df["tactic"].nunique()
        n_high       = int((mitre_df["confidence"] == "High").sum())
        n_medium     = int((mitre_df["confidence"] == "Medium").sum())
        n_low        = int((mitre_df["confidence"] == "Low").sum())

        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("Total Mappings",   f"{total_maps:,}")
        mc2.metric("Threats Covered",  f"{n_threats:,}")
        mc3.metric("Unique Techniques",f"{n_techniques:,}")
        mc4.metric("Unique Tactics",   f"{n_tactics:,}")

        cc1, cc2, cc3 = st.columns(3)
        cc1.metric("High Confidence",   f"{n_high:,}",   help="CWE-based mappings")
        cc2.metric("Medium Confidence", f"{n_medium:,}", help="Keyword-based mappings")
        cc3.metric("Low Confidence",    f"{n_low:,}",    help="Threat-type inference")

        st.divider()

        # ── Tactic distribution chart ──────────────────────────────────────
        st.markdown("#### Tactic Distribution")

        tactic_counts = (
            mitre_df.groupby("tactic")
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=True)
        )

        TACTIC_COLORS = {
            "Reconnaissance":        "#7c3aed",
            "Initial Access":        "#dc2626",
            "Execution":             "#ea580c",
            "Persistence":           "#ca8a04",
            "Privilege Escalation":  "#16a34a",
            "Defense Evasion":       "#0891b2",
            "Credential Access":     "#9333ea",
            "Discovery":             "#2563eb",
            "Lateral Movement":      "#db2777",
            "Collection":            "#059669",
            "Command and Control":   "#d97706",
            "Exfiltration":          "#be123c",
            "Impact":                "#b45309",
        }

        bar_colors = [
            TACTIC_COLORS.get(t, "#6d28d9")
            for t in tactic_counts["tactic"].tolist()
        ]

        fig_t, ax_t = plt.subplots(figsize=(10, max(3, len(tactic_counts) * 0.55)))
        fig_t.patch.set_facecolor("#0d0d1a")
        ax_t.set_facecolor("#130d2e")
        bars = ax_t.barh(
            tactic_counts["tactic"], tactic_counts["count"],
            color=bar_colors, edgecolor="#4a1d96", linewidth=0.6,
        )
        ax_t.set_xlabel("Number of Mappings", color="#a78bfa", fontsize=9)
        ax_t.set_title("ATT&CK Tactic Coverage", color="#c084fc",
                        fontsize=11, fontweight="bold")
        ax_t.tick_params(colors="#c4b5fd", labelsize=8)
        ax_t.spines[:].set_color("#4a1d96")
        for bar, val in zip(bars, tactic_counts["count"].tolist()):
            ax_t.text(val + 0.3, bar.get_y() + bar.get_height() / 2,
                      str(val), va="center", color="#e9d5ff", fontsize=8)
        plt.tight_layout()
        st.pyplot(fig_t, use_container_width=True)
        plt.close(fig_t)

        st.divider()

        # ── Top techniques table ───────────────────────────────────────────
        st.markdown("#### Most Common Techniques")

        tech_summary = (
            mitre_df.groupby(["technique_id", "technique_name", "tactic"])
            .agg(
                count=("threat_id", "count"),
                high=("confidence", lambda x: (x == "High").sum()),
                medium=("confidence", lambda x: (x == "Medium").sum()),
                low=("confidence", lambda x: (x == "Low").sum()),
            )
            .reset_index()
            .sort_values("count", ascending=False)
            .head(15)
        )
        tech_summary.columns = [
            "Technique ID", "Technique Name", "Tactic",
            "# Threats", "High", "Medium", "Low"
        ]
        st.dataframe(tech_summary, use_container_width=True, hide_index=True)

        st.divider()

        # ── Per-threat MITRE lookup ────────────────────────────────────────
        st.markdown("#### Inspect Mappings for a Threat")

        # Only show threats that have at least one mapping
        mapped_ids = sorted(mitre_df["threat_id"].unique().tolist())
        if not mapped_ids:
            st.info("No mapped threats found.")
        else:
            selected_mitre_id = st.selectbox(
                "Select a threat ID",
                options=mapped_ids,
                format_func=lambda x: f"{x[:70]}..." if len(str(x)) > 70 else x,
                key="mitre_threat_select",
            )
            threat_mappings = fetch_mitre_for_threat(selected_mitre_id)

            if not threat_mappings:
                st.info("No MITRE mappings available for this threat.")
            else:
                CONF_COLORS = {
                    "High":   ("#052e16", "#86efac", "#166534"),   # bg, text, border
                    "Medium": ("#3b2509", "#fde68a", "#92400e"),
                    "Low":    ("#431407", "#fdba74", "#9a3412"),
                }

                # Show threat context from main df
                threat_row = df[df["id"] == selected_mitre_id]
                if not threat_row.empty:
                    tr = threat_row.iloc[0]
                    pv = tr.get("predicted_priority", "—")
                    pc = {"Critical": "#fda4af", "High": "#fdba74",
                          "Medium": "#fde68a", "Low": "#86efac"}.get(pv, "#c4b5fd")
                    st.markdown(
                        f"<div style='background:#1e0a4a;border:1px solid #6d28d9;"
                        f"border-radius:10px;padding:12px 16px;margin-bottom:12px;'>"
                        f"<span style='color:#e9d5ff;font-weight:700;'>{tr['title']}</span>"
                        f"&nbsp;&nbsp;<span style='color:{pc};font-size:0.82rem;"
                        f"font-weight:600;'>Priority: {pv}</span>"
                        f"&nbsp;&nbsp;<span style='color:#7c5cbf;font-size:0.8rem;'>"
                        f"Severity: {tr['severity_raw']}/10 · Source: {tr['source']}</span>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

                st.markdown(
                    f"**{len(threat_mappings)} MITRE ATT&CK technique(s) inferred** "
                    f"for this threat:"
                )

                for m in threat_mappings:
                    conf = m.get("confidence", "Low")
                    bg, fg, border = CONF_COLORS.get(conf, CONF_COLORS["Low"])
                    mitre_url = (
                        f"https://attack.mitre.org/techniques/"
                        f"{m['technique_id'].replace('.', '/')}"
                    )
                    st.markdown(
                        f"""
<div style='background:{bg};border:1px solid {border};border-left:4px solid {border};
            border-radius:10px;padding:14px 18px;margin-bottom:10px;'>
  <div style='display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap;'>
    <div style='flex:1;min-width:200px;'>
      <div style='color:{fg};font-size:0.82rem;font-weight:700;
                  letter-spacing:0.5px;margin-bottom:4px;'>
        {conf.upper()} CONFIDENCE
      </div>
      <div style='color:#e9d5ff;font-weight:700;font-size:1rem;'>
        {m['technique_id']} — {m['technique_name']}
      </div>
      <div style='color:#a78bfa;font-size:0.84rem;margin-top:2px;'>
        Tactic: <b>{m['tactic']}</b>
      </div>
    </div>
    <div>
      <a href='{mitre_url}' target='_blank'
         style='background:#2d1066;color:#c084fc;border:1px solid #6d28d9;
                border-radius:6px;padding:4px 12px;font-size:0.78rem;
                text-decoration:none;font-weight:600;'>
        View on ATT&CK ↗
      </a>
    </div>
  </div>
  <div style='color:#9f7aea;font-size:0.82rem;margin-top:8px;
              border-top:1px solid {border};padding-top:8px;'>
    <b>Basis:</b> {m.get('basis', '—')}
  </div>
</div>""",
                        unsafe_allow_html=True,
                    )


# ══════════════════════════════════════════════
#  TAB 4 — MONITORING  (Phase 4)
# ══════════════════════════════════════════════
with tab_monitor:
    from src.pipeline.db import (
        fetch_pipeline_runs,
        fetch_threat_history,
        fetch_threat_history_for_id,
    )

    st.markdown("### 📡 Continuous Monitoring")
    st.markdown("""
<div style='background:#1a0a3d;border:1px solid #4a1d96;border-radius:10px;
            padding:14px 18px;margin-bottom:16px;font-size:0.88rem;color:#c4b5fd;'>
<b style='color:#a855f7'>How monitoring works</b><br>
Every pipeline run snapshots the current priority of each threat before and after
re-scoring. New threats, escalations (priority went up) and reductions (priority
went down) are recorded in a persistent audit log. This tab lets analysts track
how the threat landscape changes across runs without manual database inspection.
<br><br>
To simulate a new run: <code>python scripts/run_pipeline.py --retrain</code>
or <code>--synthetic</code> / <code>--live</code>.
</div>
""", unsafe_allow_html=True)

    runs     = fetch_pipeline_runs(limit=50)
    history  = fetch_threat_history(limit=1000)
    runs_df  = pd.DataFrame(runs)    if runs    else pd.DataFrame()
    hist_df  = pd.DataFrame(history) if history else pd.DataFrame()

    has_runs    = not runs_df.empty
    has_history = not hist_df.empty

    # ── Top-level run metrics ──────────────────────────────────────────────
    if has_runs:
        latest = runs_df.iloc[0]   # newest run first
        rm1, rm2, rm3, rm4, rm5 = st.columns(5)
        rm1.metric("Total Runs",      len(runs_df))
        rm2.metric("Latest New",      int(latest.get("new_threats",     0)))
        rm3.metric("Latest Escalated",int(latest.get("updated_threats", 0)))
        rm4.metric("Total Threats",   int(latest.get("total_threats",   0)))
        rm5.metric("Last Duration",   f"{latest.get('duration_secs', 0):.1f}s")
    else:
        st.info(
            "No pipeline run history yet. Run the pipeline to start collecting monitoring data:\n\n"
            "```\npython scripts/run_pipeline.py --retrain\n```"
        )

    if has_runs:
        st.divider()

        # ── Run history table ──────────────────────────────────────────────
        st.markdown("#### Pipeline Run History")

        run_display = runs_df[[
            c for c in [
                "run_id", "run_at", "mode", "total_threats",
                "new_threats", "updated_threats", "unchanged_threats",
                "n_critical", "n_high", "n_medium", "n_low",
                "duration_secs", "notes",
            ] if c in runs_df.columns
        ]].copy()

        run_rename = {
            "run_id": "Run #", "run_at": "Timestamp", "mode": "Mode",
            "total_threats": "Total", "new_threats": "New",
            "updated_threats": "Changed", "unchanged_threats": "Unchanged",
            "n_critical": "Critical", "n_high": "High",
            "n_medium": "Medium", "n_low": "Low",
            "duration_secs": "Duration (s)", "notes": "Notes",
        }
        run_display = run_display.rename(columns=run_rename)
        if "Timestamp" in run_display.columns:
            # Trim to readable format
            run_display["Timestamp"] = run_display["Timestamp"].str[:19].str.replace("T", " ")
        if "Duration (s)" in run_display.columns:
            run_display["Duration (s)"] = run_display["Duration (s)"].round(1)

        st.dataframe(run_display, use_container_width=True, hide_index=True)

        # ── New threats per run bar chart ──────────────────────────────────
        if len(runs_df) >= 2 and "new_threats" in runs_df.columns:
            st.markdown("#### New Threats per Run")
            plot_runs = runs_df.sort_values("run_id").tail(20)
            x_labels  = [f"Run {int(r)}" for r in plot_runs["run_id"]]
            new_vals  = plot_runs["new_threats"].fillna(0).astype(int).tolist()
            chg_vals  = plot_runs["updated_threats"].fillna(0).astype(int).tolist()

            fig_r, ax_r = plt.subplots(figsize=(min(10, len(x_labels) + 2), 3.5))
            fig_r.patch.set_facecolor("#0d0d1a")
            ax_r.set_facecolor("#130d2e")
            x_pos = range(len(x_labels))
            w = 0.38
            ax_r.bar([x - w/2 for x in x_pos], new_vals,
                     width=w, color="#7c3aed", label="New", edgecolor="#4a1d96", linewidth=0.6)
            ax_r.bar([x + w/2 for x in x_pos], chg_vals,
                     width=w, color="#f97316", label="Priority changed", edgecolor="#4a1d96", linewidth=0.6)
            ax_r.set_xticks(list(x_pos))
            ax_r.set_xticklabels(x_labels, rotation=30, ha="right", fontsize=8, color="#c4b5fd")
            ax_r.set_ylabel("Threats", color="#a78bfa", fontsize=9)
            ax_r.set_title("New & Changed Threats per Run", color="#c084fc",
                           fontsize=10, fontweight="bold")
            ax_r.tick_params(colors="#c4b5fd", labelsize=8)
            ax_r.spines[:].set_color("#4a1d96")
            ax_r.legend(facecolor="#1a0a3d", edgecolor="#4a1d96",
                        labelcolor="#c4b5fd", fontsize=8)
            plt.tight_layout()
            st.pyplot(fig_r, use_container_width=True)
            plt.close(fig_r)

    if has_history:
        st.divider()

        # ── Threat activity feed ───────────────────────────────────────────
        st.markdown("#### Threat Activity Feed")
        st.caption("Most recent priority changes and new threats, across all runs.")

        CHANGE_COLORS = {
            "new":       ("#052e16", "#86efac", "#166534", "🆕 NEW"),
            "escalated": ("#4c0519", "#fda4af", "#9f1239", "⬆ ESCALATED"),
            "reduced":   ("#0c1a4a", "#93c5fd", "#1d4ed8", "⬇ REDUCED"),
        }

        # Filter controls
        fc1, fc2 = st.columns([2, 2])
        change_filter = fc1.multiselect(
            "Change type",
            options=["new", "escalated", "reduced"],
            default=["new", "escalated", "reduced"],
            key="monitor_change_filter",
        )
        feed_limit = fc2.select_slider(
            "Show last N events", options=[25, 50, 100, 250], value=50,
            key="monitor_feed_limit",
        )

        filtered_hist = hist_df[hist_df["change_type"].isin(change_filter)].head(feed_limit)

        if filtered_hist.empty:
            st.info("No events matching the current filter.")
        else:
            for _, ev in filtered_hist.iterrows():
                ct = ev.get("change_type", "")
                bg, fg, border, badge = CHANGE_COLORS.get(
                    ct, ("#1a0a3d", "#c4b5fd", "#4a1d96", ct.upper())
                )
                tid       = ev.get("threat_id", "")
                title     = ev.get("title") or tid
                src       = ev.get("source", "")
                sev       = ev.get("severity_raw", "")
                prev_p    = ev.get("previous_priority") or "—"
                new_p     = ev.get("new_priority") or "—"
                run_at    = str(ev.get("run_at", ""))[:19].replace("T", " ")
                run_id    = ev.get("run_id", "")

                p_arrow = ""
                if ct == "escalated":
                    p_arrow = f"<span style='color:#fda4af;'>{prev_p} → <b>{new_p}</b></span>"
                elif ct == "reduced":
                    p_arrow = f"<span style='color:#93c5fd;'>{prev_p} → <b>{new_p}</b></span>"
                else:
                    p_arrow = f"<span style='color:#86efac;'>Priority: <b>{new_p}</b></span>"

                sev_str = f" · Sev {float(sev):.1f}/10" if sev != "" else ""

                st.markdown(
                    f"""
<div style='background:{bg};border:1px solid {border};border-left:4px solid {border};
            border-radius:8px;padding:10px 16px;margin-bottom:6px;
            display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap;'>
  <span style='background:{border};color:{fg};border-radius:10px;
               padding:2px 8px;font-size:0.7rem;font-weight:700;
               letter-spacing:0.5px;white-space:nowrap;'>{badge}</span>
  <div style='flex:1;min-width:200px;'>
    <span style='color:#e9d5ff;font-weight:600;font-size:0.9rem;'>{title[:70]}</span>
    <div style='color:#9f7aea;font-size:0.8rem;margin-top:2px;'>
      {p_arrow}
      <span style='color:#7c5cbf;margin-left:8px;'>
        {src}{sev_str} · Run #{run_id} · {run_at}
      </span>
    </div>
  </div>
</div>""",
                    unsafe_allow_html=True,
                )

        st.divider()

        # ── Per-threat history lookup ──────────────────────────────────────
        st.markdown("#### Threat History Lookup")
        st.caption("Track how a specific threat's priority has changed over time.")

        threat_ids_with_history = sorted(hist_df["threat_id"].unique().tolist())
        if threat_ids_with_history:
            sel_hist_id = st.selectbox(
                "Select a threat",
                options=threat_ids_with_history,
                format_func=lambda x: f"{x[:70]}..." if len(str(x)) > 70 else x,
                key="monitor_threat_select",
            )
            threat_hist = fetch_threat_history_for_id(sel_hist_id)
            if threat_hist:
                th_df = pd.DataFrame(threat_hist)[[
                    "run_id", "run_at", "change_type",
                    "previous_priority", "new_priority",
                    "previous_score",   "new_score",
                ]]
                th_df = th_df.rename(columns={
                    "run_id": "Run #", "run_at": "Timestamp",
                    "change_type": "Change", "previous_priority": "Previous Priority",
                    "new_priority": "New Priority", "previous_score": "Prev Score",
                    "new_score": "New Score",
                })
                if "Timestamp" in th_df.columns:
                    th_df["Timestamp"] = th_df["Timestamp"].str[:19].str.replace("T", " ")
                for sc in ("Prev Score", "New Score"):
                    if sc in th_df.columns:
                        th_df[sc] = th_df[sc].apply(
                            lambda v: round(float(v), 4) if v is not None else "—"
                        )
                st.dataframe(th_df, use_container_width=True, hide_index=True)

                # Mini timeline chart if multiple history entries
                if len(threat_hist) >= 2:
                    scores = [
                        float(r["new_score"]) if r.get("new_score") is not None else None
                        for r in threat_hist
                    ]
                    run_labels = [f"Run {r['run_id']}" for r in threat_hist]
                    valid = [(lbl, s) for lbl, s in zip(run_labels, scores) if s is not None]
                    if len(valid) >= 2:
                        lbl_v, sc_v = zip(*valid)
                        fig_h, ax_h = plt.subplots(figsize=(min(8, len(valid) + 1), 2.8))
                        fig_h.patch.set_facecolor("#0d0d1a")
                        ax_h.set_facecolor("#130d2e")
                        ax_h.plot(lbl_v, sc_v, color="#a855f7", linewidth=2,
                                  marker="o", markersize=6, markerfacecolor="#c084fc")
                        ax_h.set_ylim(0, 1.05)
                        ax_h.set_ylabel("Priority Score", color="#a78bfa", fontsize=9)
                        ax_h.set_title(
                            f"Priority Score History — {sel_hist_id[:40]}",
                            color="#c084fc", fontsize=9, fontweight="bold",
                        )
                        ax_h.tick_params(colors="#c4b5fd", labelsize=8)
                        ax_h.spines[:].set_color("#4a1d96")
                        plt.xticks(rotation=20, ha="right")
                        plt.tight_layout()
                        st.pyplot(fig_h, use_container_width=True)
                        plt.close(fig_h)


    # ── Phase 6: Reports ──────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 📄 Generate Intelligence Report")
    st.markdown("""
<div style='background:#1a0a3d;border:1px solid #4a1d96;border-radius:10px;
            padding:14px 18px;margin-bottom:16px;font-size:0.88rem;color:#c4b5fd;'>
<b style='color:#a855f7'>About reports</b><br>
Generates a self-contained HTML file with embedded charts covering the full threat
landscape — executive summary, priority breakdown, top threats, priority changes,
cluster summary, MITRE ATT&CK coverage, alerts, and a full threat appendix.<br><br>
Reports are reproducible from the DB alone (no external API calls).
Each report is saved to <code>reports/</code> with a timestamp filename.
</div>
""", unsafe_allow_html=True)

    from src.pipeline.reporter import generate_html_report as _gen_report
    from src.pipeline.db import fetch_all_mitre_mappings as _fetch_all_mitre
    from src.pipeline.db import fetch_alerts as _fetch_alerts_report
    import datetime as _dt

    # ── Date-range / run scope selector ───────────────────────────────────
    report_run_filter = None
    if has_runs and len(runs_df) > 1:
        run_ids_available = sorted(runs_df["run_id"].tolist())
        rr1, rr2 = st.columns(2)
        scope_mode = rr1.radio(
            "Report scope",
            options=["All runs", "Select specific runs"],
            horizontal=True,
            key="report_scope_mode",
        )
        if scope_mode == "Select specific runs":
            selected_run_ids = rr2.multiselect(
                "Include runs",
                options=run_ids_available,
                default=run_ids_available[-3:] if len(run_ids_available) >= 3
                        else run_ids_available,
                key="report_run_select",
            )
            if selected_run_ids:
                report_run_filter = set(selected_run_ids)

    # ── Generate button ────────────────────────────────────────────────────
    gen_col, _ = st.columns([2, 6])
    if gen_col.button("📄 Generate Report", key="gen_report_btn", type="primary"):
        with st.spinner("Building report — this may take a few seconds..."):
            _r_rows    = db.fetch_all_as_dicts()
            _r_runs    = db.fetch_pipeline_runs(limit=50)
            _r_history = db.fetch_threat_history(limit=2000)
            _r_mitre   = _fetch_all_mitre()
            _r_alerts  = _fetch_alerts_report(limit=500)

            _html = _gen_report(
                rows=_r_rows,
                runs=_r_runs,
                history=_r_history,
                mitre=_r_mitre,
                alerts=_r_alerts,
                run_filter_ids=report_run_filter,
            )

            # Save to reports/ directory
            _ts        = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            _out_path  = REPORTS_DIR / f"threat_report_{_ts}.html"
            _out_path.write_text(_html, encoding="utf-8")

            # Store in session state for download button
            st.session_state["last_report_html"]     = _html
            st.session_state["last_report_filename"]  = f"threat_report_{_ts}.html"
            st.session_state["last_report_timestamp"] = _ts
            st.session_state["last_report_path"]      = str(_out_path)

        st.success(f"Report generated and saved to `{_out_path.name}`")

    # ── Download button (shown after generation) ───────────────────────────
    if "last_report_html" in st.session_state:
        dl_col1, dl_col2, _ = st.columns([2.5, 2.5, 3])
        dl_col1.download_button(
            label="⬇ Download HTML Report",
            data=st.session_state["last_report_html"].encode("utf-8"),
            file_name=st.session_state["last_report_filename"],
            mime="text/html",
            key="download_report_btn",
        )
        dl_col2.markdown(
            f"<div style='color:#9f7aea;font-size:0.82rem;padding-top:8px;'>"
            f"Generated: {st.session_state['last_report_timestamp']}</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"<div style='color:#5b21b6;font-size:0.78rem;margin-top:4px;'>"
            f"Saved to: <code>{st.session_state['last_report_path']}</code></div>",
            unsafe_allow_html=True,
        )

    # ── Saved reports list ─────────────────────────────────────────────────
    st.markdown("#### Saved Reports")
    saved_reports = sorted(REPORTS_DIR.glob("threat_report_*.html"), reverse=True)
    if not saved_reports:
        st.caption("No saved reports yet — click 'Generate Report' above.")
    else:
        st.caption(f"{len(saved_reports)} report(s) saved in `reports/`")
        for rpt in saved_reports[:10]:
            size_kb = rpt.stat().st_size / 1024
            # Parse timestamp from filename for display
            stem_parts = rpt.stem.replace("threat_report_", "")
            try:
                rpt_dt = _dt.datetime.strptime(stem_parts, "%Y%m%d_%H%M%S")
                rpt_label = rpt_dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                rpt_label = stem_parts

            rc1, rc2, rc3 = st.columns([3, 1.5, 2])
            rc1.markdown(
                f"<span style='color:#c4b5fd;font-size:0.88rem;'>{rpt.name}</span>",
                unsafe_allow_html=True,
            )
            rc2.markdown(
                f"<span style='color:#7c5cbf;font-size:0.82rem;'>{size_kb:.0f} KB</span>",
                unsafe_allow_html=True,
            )
            # Offer re-download of saved file
            rc3.download_button(
                label="⬇ Download",
                data=rpt.read_bytes(),
                file_name=rpt.name,
                mime="text/html",
                key=f"dl_saved_{rpt.name}",
            )


# ══════════════════════════════════════════════
#  TAB 5 — ALERTS  (Phase 5)
# ══════════════════════════════════════════════
with tab_alerts:

    # Reload alert counts live (session_state changes on button clicks)
    all_alerts = _fetch_alerts(limit=500)
    alerts_df  = pd.DataFrame(all_alerts) if all_alerts else pd.DataFrame()

    st.markdown("### 🚨 Analyst Alerts")
    st.markdown("""
<div style='background:#1a0a3d;border:1px solid #4a1d96;border-radius:10px;
            padding:14px 18px;margin-bottom:16px;font-size:0.88rem;color:#c4b5fd;'>
<b style='color:#a855f7'>How alerts work</b><br>
Alerts are generated automatically after each pipeline run. They surface events
that warrant analyst attention without requiring manual review of every threat.
<ul style='margin:6px 0 0 0;padding-left:18px;'>
  <li><b style='color:#fda4af'>new_critical</b> — a brand-new Critical threat appeared</li>
  <li><b style='color:#fdba74'>new_high</b> — a brand-new High threat appeared</li>
  <li><b style='color:#fda4af'>priority_escalated</b> — an existing threat escalated to Critical or High</li>
  <li><b style='color:#fdba74'>exploit_appeared</b> — exploitation evidence newly flagged on a known threat</li>
  <li><b style='color:#fde68a'>notable_cluster</b> — a cluster crossed a notable severity/exploitation threshold</li>
  <li><b style='color:#fde68a'>spike</b> — new threat count exceeded 2× the rolling run average</li>
</ul>
<br>
Alerts are <b>dashboard-only</b> — no external emails or webhooks are sent.
</div>
""", unsafe_allow_html=True)

    if alerts_df.empty:
        st.info(
            "No alerts yet. Run the pipeline to generate alerts:\n\n"
            "```\npython scripts/run_pipeline.py --retrain\n```"
        )
    else:
        # ── Summary metrics ────────────────────────────────────────────────
        n_new   = int((alerts_df["status"] == "new").sum())
        n_ack   = int((alerts_df["status"] == "acknowledged").sum())
        n_dis   = int((alerts_df["status"] == "dismissed").sum())
        n_crit_al = int((alerts_df["severity"] == "critical").sum())
        n_high_al = int((alerts_df["severity"] == "high").sum())
        n_warn_al = int((alerts_df["severity"] == "warning").sum())

        am1, am2, am3, am4, am5, am6 = st.columns(6)
        am1.metric("🔴 Unacknowledged", n_new)
        am2.metric("✅ Acknowledged",   n_ack)
        am3.metric("🚫 Dismissed",      n_dis)
        am4.metric("Critical",          n_crit_al)
        am5.metric("High",              n_high_al)
        am6.metric("Warning",           n_warn_al)

        st.divider()

        # ── Filter controls ────────────────────────────────────────────────
        af1, af2, af3 = st.columns([2, 2, 2])
        sev_filter = af1.multiselect(
            "Severity",
            options=["critical", "high", "warning", "info"],
            default=["critical", "high", "warning", "info"],
            key="alert_sev_filter",
        )
        status_filter = af2.multiselect(
            "Status",
            options=["new", "acknowledged", "dismissed"],
            default=["new", "acknowledged"],
            key="alert_status_filter",
        )
        type_opts = sorted(alerts_df["alert_type"].unique().tolist())
        type_filter_al = af3.multiselect(
            "Alert type",
            options=type_opts,
            default=type_opts,
            key="alert_type_filter",
        )

        # ── Bulk actions ───────────────────────────────────────────────────
        ba1, ba2, _ = st.columns([2, 2, 4])
        if ba1.button("✅ Acknowledge all new", key="ack_all_btn"):
            new_ids = alerts_df[alerts_df["status"] == "new"]["alert_id"].tolist()
            for aid in new_ids:
                _update_alert_status(int(aid), "acknowledged")
            st.rerun()
        if ba2.button("🚫 Dismiss all acknowledged", key="dis_all_btn"):
            ack_ids = alerts_df[alerts_df["status"] == "acknowledged"]["alert_id"].tolist()
            for aid in ack_ids:
                _update_alert_status(int(aid), "dismissed")
            st.rerun()

        st.divider()

        # ── Apply filters ──────────────────────────────────────────────────
        vis = alerts_df[
            alerts_df["severity"].isin(sev_filter) &
            alerts_df["status"].isin(status_filter) &
            alerts_df["alert_type"].isin(type_filter_al)
        ].copy()

        if vis.empty:
            st.info("No alerts match the current filters.")
        else:
            st.markdown(
                f"<div style='color:#9f7aea;font-size:0.85rem;margin-bottom:10px;'>"
                f"Showing {len(vis)} alert(s)</div>",
                unsafe_allow_html=True,
            )

            # Colour palettes per severity
            SEV_STYLE = {
                "critical": {
                    "bg":     "#2d0a0a",
                    "border": "#9f1239",
                    "text":   "#fda4af",
                    "badge_bg": "#4c0519",
                    "icon":   "🔴",
                },
                "high": {
                    "bg":     "#2d1407",
                    "border": "#9a3412",
                    "text":   "#fdba74",
                    "badge_bg": "#431407",
                    "icon":   "🟠",
                },
                "warning": {
                    "bg":     "#2d2509",
                    "border": "#92400e",
                    "text":   "#fde68a",
                    "badge_bg": "#3b2509",
                    "icon":   "🟡",
                },
                "info": {
                    "bg":     "#0d1a2d",
                    "border": "#1d4ed8",
                    "text":   "#93c5fd",
                    "badge_bg": "#0c1a4a",
                    "icon":   "🔵",
                },
            }

            STATUS_LABEL = {
                "new":          ("🔔 NEW",          "#9f1239", "#fda4af"),
                "acknowledged": ("✅ ACKNOWLEDGED", "#166534", "#86efac"),
                "dismissed":    ("🚫 DISMISSED",    "#374151", "#9ca3af"),
            }

            TYPE_LABEL = {
                "new_critical":       "New Critical",
                "new_high":           "New High",
                "priority_escalated": "Escalated",
                "exploit_appeared":   "Exploit Appeared",
                "notable_cluster":    "Notable Cluster",
                "spike":              "Spike",
            }

            for _, alert in vis.iterrows():
                sev      = alert.get("severity", "info")
                status   = alert.get("status",   "new")
                atype    = alert.get("alert_type", "")
                msg      = alert.get("message",    "")
                alert_id = int(alert.get("alert_id", 0))
                tid      = alert.get("threat_id") or ""
                run_id_a = alert.get("run_id", "")
                created  = str(alert.get("created_at", ""))[:19].replace("T", " ")

                sty = SEV_STYLE.get(sev, SEV_STYLE["info"])
                slabel, sbg, sfg = STATUS_LABEL.get(
                    status, ("UNKNOWN", "#374151", "#9ca3af")
                )
                type_display = TYPE_LABEL.get(atype, atype.replace("_", " ").title())

                # Dimmed styling for dismissed alerts
                opacity = "0.45" if status == "dismissed" else "1"
                new_border_extra = (
                    f"box-shadow:0 0 0 2px {sty['border']}55;" if status == "new" else ""
                )

                st.markdown(
                    f"""
<div style='background:{sty["bg"]};border:1px solid {sty["border"]};
            border-left:4px solid {sty["border"]};border-radius:10px;
            padding:14px 18px;margin-bottom:8px;opacity:{opacity};
            {new_border_extra}'>
  <div style='display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap;'>
    <span style='font-size:1.3rem;'>{sty["icon"]}</span>
    <div style='flex:1;min-width:250px;'>
      <div style='display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px;'>
        <span style='background:{sty["badge_bg"]};color:{sty["text"]};
                     border:1px solid {sty["border"]};border-radius:12px;
                     padding:2px 10px;font-size:0.72rem;font-weight:700;
                     letter-spacing:0.5px;'>{sev.upper()}</span>
        <span style='background:#1a0a3d;color:#a78bfa;border:1px solid #4a1d96;
                     border-radius:12px;padding:2px 10px;font-size:0.72rem;
                     font-weight:600;'>{type_display}</span>
        <span style='background:{sbg};color:{sfg};border-radius:10px;
                     padding:2px 8px;font-size:0.7rem;font-weight:700;'>{slabel}</span>
      </div>
      <div style='color:#e9d5ff;font-size:0.9rem;line-height:1.5;'>{msg}</div>
      <div style='color:#7c5cbf;font-size:0.78rem;margin-top:6px;'>
        {"Threat: <code style='color:#a78bfa;'>" + tid[:60] + "</code> &nbsp;·&nbsp; " if tid else ""}
        Run #{run_id_a} &nbsp;·&nbsp; {created}
      </div>
    </div>
  </div>
</div>""",
                    unsafe_allow_html=True,
                )

                # Action buttons — only show for non-dismissed
                if status != "dismissed":
                    btn_col1, btn_col2, _ = st.columns([1.4, 1.4, 7])
                    if status == "new":
                        if btn_col1.button(
                            "✅ Acknowledge", key=f"ack_{alert_id}",
                        ):
                            _update_alert_status(alert_id, "acknowledged")
                            st.rerun()
                    if btn_col2.button(
                        "🚫 Dismiss", key=f"dis_{alert_id}",
                    ):
                        _update_alert_status(alert_id, "dismissed")
                        st.rerun()

        st.divider()
        st.caption(
            "Alerts are generated automatically by the pipeline and stored in the local SQLite database. "
            "No external notifications are sent. Re-run the pipeline to refresh alert data."
        )


# ══════════════════════════════════════════════
#  TAB 6 — SETTINGS / ORG CONTEXT  (Phase 10)
# ══════════════════════════════════════════════
with tab_settings:
    from src.config_org import load_org_context, save_org_context, org_context_configured
    from src.pipeline.context_scorer import apply_context_score

    st.markdown("### ⚙️ Settings — Organisational Context")
    st.markdown("""
<div style='background:#1a0a3d;border:1px solid #4a1d96;border-radius:10px;
            padding:14px 18px;margin-bottom:16px;font-size:0.88rem;color:#c4b5fd;'>
<b style='color:#a855f7'>What is Organisational Context?</b><br>
Configure your organisation's asset environment so threat priority can be
contextualised against what actually matters to you. The platform will apply
small score boosts to threats that match your high-value assets or exposure profile.
<br><br>
<b>Important:</b> This produces a <em>context-adjusted score</em> for display only.
It never overwrites the ML prediction or retrains the model.
The org context is stored in <code>org_context.json</code> (not committed to git).
After saving, re-run the pipeline to apply context scores:
<code>python scripts/run_pipeline.py --retrain</code>
</div>
""", unsafe_allow_html=True)

    current_ctx = load_org_context()
    configured  = org_context_configured()

    if configured:
        st.success(f"Org context configured for: **{current_ctx.get('org_name', 'unnamed')}**")
    else:
        st.info("No org context configured yet. Fill in the form below and click Save.")

    st.markdown("#### Organisation Profile")

    with st.form("org_context_form"):
        org_name = st.text_input(
            "Organisation name",
            value=current_ctx.get("org_name", ""),
            placeholder="e.g. Acme Corp",
        )
        high_value_raw = st.text_input(
            "High-value asset keywords (comma-separated)",
            value=", ".join(current_ctx.get("high_value_assets", [])),
            placeholder="e.g. Apache, Microsoft, OpenSSL, Cisco",
            help="CVEs mentioning these vendors/products will receive a score boost.",
        )
        internet_exposed = st.checkbox(
            "Internet-exposed environment",
            value=bool(current_ctx.get("internet_exposed", False)),
            help="Tick if your systems are directly reachable from the internet. "
                 "High/Critical threats receive an additional boost.",
        )
        criticality_options = ["low", "medium", "high", "critical"]
        criticality = st.selectbox(
            "Organisation criticality",
            options=criticality_options,
            index=criticality_options.index(
                current_ctx.get("criticality", "medium")
            ),
            help="How critical is your organisation? Higher criticality applies a "
                 "global score boost to all threats.",
        )
        ignored_sources_raw = st.text_input(
            "Ignored sources (comma-separated, leave blank for none)",
            value=", ".join(current_ctx.get("ignored_sources", [])),
            placeholder="e.g. greynoise",
            help="Threats from these sources will be suppressed (context score = 0).",
        )

        saved = st.form_submit_button("💾 Save Configuration")

    if saved:
        new_ctx = {
            "org_name":          org_name.strip(),
            "high_value_assets": [a.strip() for a in high_value_raw.split(",") if a.strip()],
            "internet_exposed":  internet_exposed,
            "criticality":       criticality,
            "ignored_sources":   [s.strip() for s in ignored_sources_raw.split(",") if s.strip()],
        }
        save_org_context(new_ctx)
        st.success(
            "Configuration saved to `org_context.json`. "
            "Re-run the pipeline (`--retrain`) to apply context scores to all threats."
        )
        st.rerun()

    # ── Context score preview ──────────────────────────────────────────────
    if configured and not saved:
        st.divider()
        st.markdown("#### Live Context Score Preview")
        st.caption(
            "Shows how the current configuration adjusts scores for a sample of threats. "
            "Context-adjusted scores are for analyst guidance only — they do not change "
            "ML predictions or retraining labels."
        )

        preview_rows = df.head(20).to_dict(orient="records")
        ctx = load_org_context()
        preview_data = []
        for row in preview_rows:
            adj_score, reasons = apply_context_score(row, ctx)
            base = round(float(row.get("predicted_priority_score") or 0), 4)
            adj  = round(adj_score, 4) if adj_score is not None else base
            diff = round(adj - base, 4) if adj_score is not None else 0
            preview_data.append({
                "ID":             str(row.get("id", ""))[:35],
                "ML Priority":    row.get("predicted_priority", "—"),
                "Base Score":     base,
                "Context Score":  adj,
                "Boost":          f"+{diff:.4f}" if diff > 0 else str(diff),
                "Reason":         reasons[0] if reasons else "—",
            })
        st.dataframe(pd.DataFrame(preview_data), use_container_width=True, hide_index=True)

        # Context score column in the main threats df (if column exists)
        if "context_adjusted_score" in df.columns and df["context_adjusted_score"].notna().any():
            st.divider()
            n_boosted = int((df["context_adjusted_score"].fillna(0) >
                             df["predicted_priority_score"].fillna(0)).sum())
            n_suppressed = int((df["context_adjusted_score"] == 0).sum())
            cb1, cb2, cb3 = st.columns(3)
            cb1.metric("Threats with context score", int(df["context_adjusted_score"].notna().sum()))
            cb2.metric("Received boost",             n_boosted)
            cb3.metric("Suppressed (ignored source)", n_suppressed)


# ══════════════════════════════════════════════
#  TAB 7 — MODEL EVALUATION  (original content)
# ══════════════════════════════════════════════
with tab_models:
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
                help="Accuracy on held-out test set",
            )

        # ── Phase 11: Per-class F1 scores ─────────────────────────────────
        per_class_path = REPORTS_DIR / "per_class_metrics.json"
        f1_chart_path  = REPORTS_DIR / "per_class_f1_comparison.png"

        if per_class_path.exists():
            st.divider()
            st.markdown("#### Per-Class Precision / Recall / F1")
            st.caption(
                "F1 scores reflect how well the model learns the heuristic labels — "
                "not real-world analyst agreement. Low F1 on Critical/High indicates "
                "class imbalance impact. Values below 0.50 are flagged."
            )
            with open(per_class_path) as f:
                per_class = json.load(f)

            for model_name, class_data in per_class.items():
                with st.expander(
                    f"📈 {model_name.replace('_', ' ').title()} — per-class metrics",
                    expanded=(model_name == "random_forest"),
                ):
                    pc_rows = []
                    for cls in ["Critical", "High", "Medium", "Low"]:
                        cd = class_data.get(cls, {})
                        f1  = cd.get("f1", 0)
                        flag = "⚠️" if f1 < 0.5 else "✅"
                        pc_rows.append({
                            "Class":     cls,
                            "Precision": cd.get("precision", 0),
                            "Recall":    cd.get("recall",    0),
                            "F1-Score":  f1,
                            "Support":   cd.get("support",   0),
                            "Status":    flag,
                        })
                    pc_df = pd.DataFrame(pc_rows)
                    st.dataframe(pc_df, use_container_width=True, hide_index=True)

                    # Strategy A vs B note for RF SMOTE
                    if model_name == "random_forest_smote":
                        st.markdown(
                            "<div style='background:#052e16;border:1px solid #166534;"
                            "border-radius:8px;padding:10px 14px;color:#86efac;"
                            "font-size:0.85rem;'>"
                            "⚗️ <b>Strategy B (SMOTE)</b> — trained with synthetic minority "
                            "oversampling. Compare Critical/High F1 with the baseline "
                            "Random Forest to assess whether SMOTE improves minority-class "
                            "detection on these heuristic labels."
                            "</div>",
                            unsafe_allow_html=True,
                        )

        if f1_chart_path.exists():
            st.divider()
            st.markdown("#### F1 Comparison Chart")
            st.image(str(f1_chart_path), caption="Per-class F1 across all models (Phase 11)")

        st.divider()

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
