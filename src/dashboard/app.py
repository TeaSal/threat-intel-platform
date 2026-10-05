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
tab_threats, tab_clusters, tab_mitre, tab_models = st.tabs([
    "🔒 Threats",
    "🔗 Clusters",
    "🧩 MITRE ATT&CK",
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
        "predicted_priority_score", "heuristic_label", "cluster_id", "source", "last_seen",
    ]
    display_cols = [c for c in display_cols if c in page_df.columns]

    col_rename = {
        "id": "ID",
        "threat_type": "Type",
        "title": "Title",
        "severity_raw": "Severity",
        "predicted_priority": "ML Priority",
        "predicted_priority_score": "ML Rank Score",
        "heuristic_label": "Heuristic Label",
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
#  TAB 4 — MODEL EVALUATION  (original content)
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
