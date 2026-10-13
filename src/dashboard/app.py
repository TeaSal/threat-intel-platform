"""
Threat Intelligence Dashboard — Botanical Editorial Design
Run with: streamlit run src/dashboard/app.py
"""
import sys, json, re
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import streamlit as st
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.pipeline import db
from src.pipeline.db import (
    fetch_analyst_feedback   as _fetch_all_feedback,
    fetch_alerts             as _fetch_alerts,
    fetch_unacknowledged_alert_count as _unack_count,
    update_alert_status      as _update_alert_status,
    fetch_feedback_for_threat as _fetch_feedback,
    upsert_analyst_feedback  as _upsert_feedback,
    ANALYST_LABEL_OPTIONS    as _ANALYST_LABEL_OPTIONS,
    fetch_pipeline_runs,
    fetch_threat_history,
    fetch_all_mitre_mappings,
    fetch_mitre_for_threat,
)
from src.config import REPORTS_DIR

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatIntel Platform",
    page_icon="🌿",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Design System CSS — Botanical Editorial ───────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,400;1,9..144,400&family=Inter:wght@400;500;600&display=swap');

/* ── Reset & base ── */
html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }

/* ── Canvas ── */
.stApp { background: #eef2e3 !important; color: #043f2e !important; }
.main .block-container { padding: 2rem 2.5rem 3rem !important; max-width: 1200px; margin: 0 auto; }

/* ── Hide Streamlit chrome ── */
#MainMenu, footer, header { visibility: hidden; }
[data-testid="collapsedControl"] { display: none; }

/* ── Headings — Fraunces serif ── */
h1, h2, h3 {
    font-family: 'Fraunces', Georgia, serif !important;
    color: #043f2e !important;
    font-weight: 400 !important;
    letter-spacing: -0.03em !important;
}
h1 { font-size: 2.8rem !important; line-height: 1.0 !important; margin-bottom: 0.25rem !important; }
h2 { font-size: 2rem !important; line-height: 1.1 !important; }
h3 { font-size: 1.4rem !important; line-height: 1.15 !important; }

/* ── Eyebrow labels ── */
.eyebrow {
    font-family: 'Inter', sans-serif;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #043f2e;
    margin-bottom: 6px;
    display: block;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    gap: 0 !important;
    background: #fcfcfc !important;
    border-bottom: 1.5px solid #000 !important;
    padding: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    border: none !important;
    border-bottom: 2px solid transparent !important;
    border-radius: 0 !important;
    color: #242423 !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    font-size: 0.85rem !important;
    padding: 10px 20px !important;
    transition: all 0.15s !important;
    margin-bottom: -1.5px !important;
}
.stTabs [data-baseweb="tab"]:hover { color: #043f2e !important; }
.stTabs [aria-selected="true"] {
    color: #043f2e !important;
    font-weight: 600 !important;
    border-bottom: 2.5px solid #c8f169 !important;
    background: transparent !important;
}

/* ── KPI stat cards ── */
[data-testid="stMetric"] {
    background: #043f2e !important;
    border-radius: 16px !important;
    padding: 20px 22px !important;
    border: none !important;
    box-shadow: none !important;
}
[data-testid="stMetricLabel"] {
    font-family: 'Inter', sans-serif !important;
    font-size: 10px !important;
    font-weight: 600 !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
    color: #c8f169 !important;
}
[data-testid="stMetricValue"] {
    font-family: 'Inter', sans-serif !important;
    font-size: 2rem !important;
    font-weight: 400 !important;
    color: #fcfcfc !important;
    letter-spacing: -0.02em !important;
}
[data-testid="stMetricDelta"] { color: #c8f169 !important; }

/* ── Buttons ── */
.stButton > button {
    background: #c8f169 !important;
    color: #000 !important;
    border: none !important;
    border-radius: 4px !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    font-size: 0.85rem !important;
    padding: 7px 18px !important;
    transition: background 0.15s !important;
    box-shadow: none !important;
}
.stButton > button:hover { background: #2a6f2b !important; color: #fcfcfc !important; }
.stButton > button:disabled {
    background: #d4d9c8 !important;
    color: #777 !important;
}
/* Ghost button variant via class */
.ghost-btn > button {
    background: transparent !important;
    color: #043f2e !important;
    border: 1px solid #000 !important;
}
.ghost-btn > button:hover { background: #043f2e !important; color: #fcfcfc !important; }

/* ── Cards ── */
.card {
    background: #fcfcfc;
    border-radius: 16px;
    padding: 20px 24px;
    margin-bottom: 12px;
}
.card-sage {
    background: #eef2e3;
    border-radius: 16px;
    padding: 20px 24px;
    margin-bottom: 12px;
}
.card-forest {
    background: #043f2e;
    border-radius: 16px;
    padding: 20px 24px;
    margin-bottom: 12px;
    color: #fcfcfc;
}

/* ── Priority pill badges ── */
.pill {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 9999px;
    font-family: 'Inter', sans-serif;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
.pill-critical { background: #fef2f2; color: #991b1b; border: 1px solid #fca5a5; }
.pill-high     { background: #fff7ed; color: #9a3412; border: 1px solid #fdba74; }
.pill-medium   { background: #fefce8; color: #854d0e; border: 1px solid #fde047; }
.pill-low      { background: #f0fdf4; color: #166534; border: 1px solid #86efac; }
.pill-chartreuse { background: #c8f169; color: #000; border: none; }

/* ── Alert cards ── */
.alert-critical { border-left: 4px solid #dc2626; background: #fff5f5; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }
.alert-high     { border-left: 4px solid #ea580c; background: #fff8f0; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }
.alert-warning  { border-left: 4px solid #ca8a04; background: #fffdf0; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }
.alert-info     { border-left: 4px solid #043f2e; background: #f0f7f0; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }

/* ── Threat row cards ── */
.threat-row {
    background: #fcfcfc;
    border-radius: 12px;
    padding: 14px 18px;
    margin-bottom: 8px;
    border: 1px solid #e8edd9;
    transition: border-color 0.15s;
}
.threat-row:hover { border-color: #c8f169; }
.threat-row-critical { border-left: 4px solid #dc2626 !important; }
.threat-row-high     { border-left: 4px solid #ea580c !important; }
.threat-row-medium   { border-left: 4px solid #ca8a04 !important; }
.threat-row-low      { border-left: 4px solid #16a34a !important; }

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: #fcfcfc !important;
    border-right: 1px solid #e8edd9 !important;
}
section[data-testid="stSidebar"] * { color: #043f2e !important; }
section[data-testid="stSidebar"] .stMultiSelect [data-baseweb="tag"] {
    background: #c8f169 !important;
    color: #000 !important;
}

/* ── Inputs ── */
.stSelectbox > div > div, .stMultiSelect > div > div, .stTextInput > div > div {
    border-radius: 4px !important;
    border: 1px solid #000 !important;
    background: #fcfcfc !important;
    color: #043f2e !important;
}
.stSelectbox label, .stMultiSelect label, .stTextInput label,
.stCheckbox label, .stRadio label, .stSlider label, .stTextArea label {
    color: #043f2e !important;
    font-weight: 500 !important;
    font-size: 0.85rem !important;
}

/* ── Expander ── */
details {
    background: #fcfcfc !important;
    border: 1px solid #e8edd9 !important;
    border-radius: 12px !important;
}
summary {
    color: #043f2e !important;
    font-weight: 600 !important;
    font-size: 0.9rem !important;
    padding: 12px 16px !important;
}
summary:hover { background: #eef2e3 !important; }

/* ── Divider ── */
hr { border-color: #e8edd9 !important; opacity: 1 !important; margin: 24px 0 !important; }

/* ── Dataframe ── */
[data-testid="stDataFrame"] {
    border: 1px solid #e8edd9 !important;
    border-radius: 12px !important;
}
[data-testid="stDataFrame"] thead tr th {
    background: #043f2e !important;
    color: #fcfcfc !important;
    font-weight: 600 !important;
    font-size: 0.78rem !important;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 10px 14px !important;
}
[data-testid="stDataFrame"] tbody tr:hover { background: #eef2e3 !important; }
[data-testid="stDataFrame"] tbody tr td { color: #242423 !important; padding: 9px 14px !important; }

/* ── Info/warning/success boxes ── */
.stAlert { border-radius: 8px !important; border-left: 4px solid #c8f169 !important; background: #f6faed !important; color: #043f2e !important; }

/* ── Caption ── */
.stCaption, small { color: #6b7c6a !important; font-size: 0.78rem !important; }

/* ── Pagination info ── */
.page-info { color: #6b7c6a; font-size: 0.82rem; text-align: center; margin: 6px 0; }

/* ── Activity dot ── */
.dot-new      { width:8px;height:8px;border-radius:50%;background:#16a34a;display:inline-block;margin-right:6px; }
.dot-escalate { width:8px;height:8px;border-radius:50%;background:#dc2626;display:inline-block;margin-right:6px; }
.dot-reduced  { width:8px;height:8px;border-radius:50%;background:#2563eb;display:inline-block;margin-right:6px; }
</style>
""", unsafe_allow_html=True)

# ── Data loading ──────────────────────────────────────────────────────────────
rows = db.fetch_all_as_dicts()
if not rows:
    st.markdown("""
<div style='background:#fcfcfc;border-radius:16px;padding:48px;text-align:center;margin:60px auto;max-width:500px;border:1px solid #e8edd9;'>
  <div style='font-family:Fraunces,serif;font-size:2rem;color:#043f2e;margin-bottom:12px;'>No data yet</div>
  <div style='color:#6b7c6a;margin-bottom:20px;'>Run the pipeline to start collecting threat intelligence.</div>
  <code style='background:#eef2e3;padding:8px 16px;border-radius:4px;font-size:0.9rem;'>
    python scripts/run_pipeline.py --synthetic
  </code>
</div>""", unsafe_allow_html=True)
    st.stop()

df = pd.DataFrame(rows)

# Merge analyst feedback
_all_feedback = _fetch_all_feedback()
if _all_feedback:
    _fb_df = pd.DataFrame(_all_feedback)[["threat_id", "analyst_label"]]
    df = df.merge(_fb_df, left_on="id", right_on="threat_id", how="left").drop(columns="threat_id")
else:
    df["analyst_label"] = None

# Pre-compute priority counts
_prio_counts = df["predicted_priority"].value_counts() if "predicted_priority" in df.columns else {}
_n_critical  = int(_prio_counts.get("Critical", 0))
_n_high      = int(_prio_counts.get("High", 0))
_n_medium    = int(_prio_counts.get("Medium", 0))
_n_low       = int(_prio_counts.get("Low", 0))
_n_cves      = int((df["threat_type"] == "cve").sum())
_n_ips       = int((df["threat_type"] == "malicious_ip").sum())
_n_exploited = int(df["exploited_flag"].fillna(0).astype(int).sum())

# Alert counts
_unack = _unack_count()
_alerts_label = f"🚨  Alerts  {_unack} new" if _unack > 0 else "🚨  Alerts"

# ── Top nav bar ───────────────────────────────────────────────────────────────
st.markdown(f"""
<div style='background:#fcfcfc;border-bottom:1px solid #e8edd9;padding:12px 0 10px;
            margin-bottom:28px;display:flex;align-items:center;gap:32px;'>
  <span style='font-family:Fraunces,Georgia,serif;font-size:1.15rem;
               font-weight:400;color:#043f2e;letter-spacing:-0.02em;'>
    🌿 ThreatIntel
  </span>
  {'<span style="background:#c8f169;color:#000;border-radius:9999px;padding:3px 10px;font-size:11px;font-weight:600;">⚠ ' + str(_unack) + ' unread alerts</span>' if _unack > 0 else ''}
</div>
""", unsafe_allow_html=True)

# ── Tab layout ────────────────────────────────────────────────────────────────
tab_home, tab_threats, tab_clusters, tab_mitre, tab_monitor, tab_alerts, tab_settings, tab_models = st.tabs([
    "🏠  Overview",
    "🔒  Threats",
    "🔗  Clusters",
    "🧩  MITRE ATT&CK",
    "📡  Monitoring",
    _alerts_label,
    "⚙️  Settings",
    "📊  Model Evaluation",
])

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 1 — HOME / OVERVIEW
# ═════════════════════════════════════════════════════════════════════════════
with tab_home:
    # ── Hero headline ──────────────────────────────────────────────────────
    runs = fetch_pipeline_runs(limit=1)
    last_run_at = runs[0]["run_at"][:19].replace("T", " ") if runs else "—"
    last_mode   = runs[0]["mode"]  if runs else "—"

    st.markdown(f"""
<div style='margin-bottom:32px;'>
  <span class='eyebrow'>Threat Intelligence Platform</span>
  <div style='font-family:Fraunces,Georgia,serif;font-size:2.6rem;font-weight:400;
              color:#043f2e;letter-spacing:-0.03em;line-height:1.0;margin-bottom:8px;'>
    {len(df):,} threats ranked,<br>ready for triage.
  </div>
  <div style='color:#6b7c6a;font-size:0.85rem;'>
    Last pipeline run: <strong style='color:#043f2e;'>{last_run_at}</strong>
    &nbsp;·&nbsp; Mode: <strong style='color:#043f2e;'>{last_mode}</strong>
    &nbsp;·&nbsp; Sources: NVD · AbuseIPDB
  </div>
</div>
""", unsafe_allow_html=True)

    # ── KPI row ────────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Critical",     _n_critical)
    c2.metric("High",         _n_high)
    c3.metric("Medium",       _n_medium)
    c4.metric("CVEs",         _n_cves)
    c5.metric("Malicious IPs",_n_ips)
    c6.metric("Exploited",    _n_exploited)

    st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)

    left_col, right_col = st.columns([3, 2], gap="large")

    with left_col:
        # ── Active alerts strip (max 5) ────────────────────────────────────
        new_alerts = _fetch_alerts(status_filter="new", limit=5)
        if new_alerts:
            st.markdown("<span class='eyebrow'>Active Alerts</span>", unsafe_allow_html=True)
            ALERT_STYLE = {
                "critical": ("alert-critical", "🔴"),
                "high":     ("alert-high",     "🟠"),
                "warning":  ("alert-warning",  "🟡"),
                "info":     ("alert-info",      "🟢"),
            }
            for al in new_alerts:
                sev   = al.get("severity", "info").lower()
                cls, dot = ALERT_STYLE.get(sev, ("alert-info", "•"))
                msg   = al.get("message", "")
                atype = al.get("alert_type", "").replace("_", " ").title()
                tid   = str(al.get("threat_id") or "")
                tid   = "" if tid in ("nan", "None") else tid
                st.markdown(
                    f"<div class='{cls}'>"
                    f"<div style='display:flex;justify-content:space-between;align-items:flex-start;'>"
                    f"<div>"
                    f"<span style='font-size:11px;font-weight:700;text-transform:uppercase;"
                    f"letter-spacing:0.06em;color:#6b7c6a;'>{dot} {atype}</span>"
                    f"<div style='font-size:0.88rem;color:#043f2e;margin-top:3px;'>{msg[:120]}</div>"
                    f"{'<div style=\"font-size:0.75rem;color:#6b7c6a;margin-top:3px;\">ID: ' + tid[:40] + '</div>' if tid else ''}"
                    f"</div>"
                    f"</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
            if _unack > 5:
                st.markdown(
                    f"<div style='text-align:right;font-size:0.8rem;color:#6b7c6a;margin-top:4px;'>"
                    f"+ {_unack - 5} more unread alerts — see Alerts tab</div>",
                    unsafe_allow_html=True,
                )
            st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
        else:
            st.markdown(
                "<div class='card' style='text-align:center;color:#6b7c6a;padding:28px;'>"
                "✅ No unread alerts — threat landscape is stable.</div>",
                unsafe_allow_html=True,
            )
            st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

        # ── Top 10 threats by score ────────────────────────────────────────
        st.markdown("<span class='eyebrow'>Top Priority Threats</span>", unsafe_allow_html=True)
        PRIORITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        top_df = df.copy()
        if "predicted_priority" in top_df.columns:
            top_df["_r"] = top_df["predicted_priority"].map(PRIORITY_RANK).fillna(0)
            sc = "predicted_priority_score" if "predicted_priority_score" in top_df.columns else "severity_raw"
            top_df = top_df.sort_values(["_r", sc], ascending=[False, False]).head(10)

        P_COLOR = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#16a34a"}
        P_BG    = {"Critical": "#fef2f2", "High": "#fff7ed", "Medium": "#fefce8", "Low": "#f0fdf4"}
        P_LEFT  = {"Critical": "threat-row-critical", "High": "threat-row-high",
                   "Medium":   "threat-row-medium",   "Low":  "threat-row-low"}

        for _, row in top_df.iterrows():
            pv   = row.get("predicted_priority", "—")
            pc   = P_COLOR.get(pv, "#043f2e")
            pb   = P_BG.get(pv,    "#fcfcfc")
            pcls = P_LEFT.get(pv,  "")
            sev  = row.get("severity_raw", 0)
            tid  = str(row.get("id", ""))
            ttl  = str(row.get("title", tid))[:60]
            src  = row.get("source", "")
            exp  = bool(int(row.get("exploited_flag") or 0))
            exp_tag = ("<span style='background:#fef2f2;color:#991b1b;border-radius:9999px;"
                       "padding:1px 7px;font-size:10px;font-weight:600;margin-left:6px;'>EXPLOIT</span>"
                       if exp else "")
            st.markdown(
                f"<div class='threat-row {pcls}'>"
                f"<div style='display:flex;justify-content:space-between;align-items:center;gap:12px;'>"
                f"<div style='flex:1;min-width:0;'>"
                f"<div style='font-size:0.88rem;font-weight:500;color:#043f2e;"
                f"white-space:nowrap;overflow:hidden;text-overflow:ellipsis;'>"
                f"{ttl}{exp_tag}</div>"
                f"<div style='font-size:0.75rem;color:#6b7c6a;margin-top:2px;'>"
                f"{src} · Sev {sev}/10</div>"
                f"</div>"
                f"<span class='pill' style='background:{pb};color:{pc};border:1px solid {pc}44;"
                f"white-space:nowrap;'>{pv}</span>"
                f"</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

    with right_col:
        # ── Priority donut ─────────────────────────────────────────────────
        st.markdown("<span class='eyebrow'>Priority Distribution</span>", unsafe_allow_html=True)

        labels_o = ["Critical", "High", "Medium", "Low"]
        values_o = [_n_critical, _n_high, _n_medium, _n_low]
        colors_o = ["#dc2626", "#ea580c", "#ca8a04", "#16a34a"]
        nonzero  = [(l, v, c) for l, v, c in zip(labels_o, values_o, colors_o) if v > 0]

        if nonzero:
            lbls, vals, cols = zip(*nonzero)
            fig_d, ax_d = plt.subplots(figsize=(4, 4))
            fig_d.patch.set_facecolor("#eef2e3")
            ax_d.set_facecolor("#eef2e3")
            wedges, _ = ax_d.pie(
                vals, colors=cols, startangle=90, counterclock=False,
                wedgeprops={"width": 0.52, "edgecolor": "#eef2e3", "linewidth": 3},
            )
            ax_d.text(0, 0, f"{sum(vals):,}", ha="center", va="center",
                      fontsize=18, fontweight="600", color="#043f2e")
            ax_d.legend(
                wedges, [f"{l}  {v:,}" for l, v in zip(lbls, vals)],
                loc="lower center", bbox_to_anchor=(0.5, -0.12),
                ncol=2, frameon=False, fontsize=9,
                labelcolor="#043f2e",
            )
            plt.tight_layout()
            st.pyplot(fig_d, use_container_width=True)
            plt.close(fig_d)

        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

        # ── Source split ───────────────────────────────────────────────────
        st.markdown("<span class='eyebrow'>Source Breakdown</span>", unsafe_allow_html=True)
        src_counts = df["source"].value_counts()
        total_src  = src_counts.sum()
        for src_name, cnt in src_counts.items():
            pct = cnt / total_src * 100
            st.markdown(
                f"<div style='margin-bottom:8px;'>"
                f"<div style='display:flex;justify-content:space-between;"
                f"font-size:0.82rem;color:#043f2e;margin-bottom:3px;'>"
                f"<span style='font-weight:500;'>{src_name}</span>"
                f"<span style='color:#6b7c6a;'>{cnt:,}  ({pct:.0f}%)</span></div>"
                f"<div style='background:#e8edd9;border-radius:9999px;height:5px;'>"
                f"<div style='background:#043f2e;width:{pct:.0f}%;height:5px;"
                f"border-radius:9999px;'></div></div>"
                f"</div>",
                unsafe_allow_html=True,
            )

        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

        # ── Recent activity feed ───────────────────────────────────────────
        st.markdown("<span class='eyebrow'>Recent Activity</span>", unsafe_allow_html=True)
        hist = fetch_threat_history(limit=8)
        if hist:
            DOT = {"new": "dot-new", "escalated": "dot-escalate", "reduced": "dot-reduced"}
            for h in hist[:6]:
                ct    = h.get("change_type", "")
                dotcls= DOT.get(ct, "dot-new")
                hid   = str(h.get("threat_id", ""))[:28]
                prev  = h.get("previous_priority") or "—"
                new_p = h.get("new_priority") or "—"
                ts    = str(h.get("run_at", ""))[:16].replace("T", " ")
                arrow = f"{prev} → {new_p}" if ct != "new" else f"New · {new_p}"
                st.markdown(
                    f"<div style='display:flex;align-items:flex-start;gap:8px;"
                    f"padding:7px 0;border-bottom:1px solid #e8edd9;'>"
                    f"<span class='{dotcls}' style='margin-top:5px;flex-shrink:0;'></span>"
                    f"<div><div style='font-size:0.82rem;color:#043f2e;font-weight:500;'>{hid}</div>"
                    f"<div style='font-size:0.75rem;color:#6b7c6a;'>{arrow} · {ts}</div>"
                    f"</div></div>",
                    unsafe_allow_html=True,
                )
        else:
            st.caption("No activity history yet. Run the pipeline twice to see changes.")

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    st.markdown(
        "<div style='text-align:center;font-size:0.75rem;color:#6b7c6a;padding-top:12px;"
        "border-top:1px solid #e8edd9;'>⚠ Priority labels are heuristic — not analyst-verified ground truth</div>",
        unsafe_allow_html=True,
    )

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 2 — THREATS (expandable cards)
# ═════════════════════════════════════════════════════════════════════════════
with tab_threats:

    # ── Sidebar-style filters inline ──────────────────────────────────────
    st.markdown("<span class='eyebrow'>Filter & Sort</span>", unsafe_allow_html=True)
    fc1, fc2, fc3, fc4 = st.columns([2, 2, 1, 1])

    with fc1:
        type_opts = sorted(df["threat_type"].dropna().unique().tolist())
        type_filter = st.multiselect("Type", options=type_opts, default=type_opts, label_visibility="collapsed",
                                     placeholder="All types")
    with fc2:
        prio_opts = ["Critical", "High", "Medium", "Low"]
        avail_p   = [p for p in prio_opts if p in df.get("predicted_priority", pd.Series()).values] or prio_opts
        prio_filter = st.multiselect("Priority", options=prio_opts, default=avail_p, label_visibility="collapsed",
                                     placeholder="All priorities")
    with fc3:
        src_opts = ["All"] + sorted(df["source"].dropna().unique().tolist())
        src_filter = st.selectbox("Source", options=src_opts, label_visibility="collapsed")
    with fc4:
        show_exploited = st.checkbox("Exploited only", value=False)

    # Apply filters
    filtered = df.copy()
    if type_filter:
        filtered = filtered[filtered["threat_type"].isin(type_filter)]
    if prio_filter and "predicted_priority" in filtered.columns:
        filtered = filtered[filtered["predicted_priority"].isin(prio_filter)]
    if src_filter != "All":
        filtered = filtered[filtered["source"] == src_filter]
    if show_exploited:
        filtered = filtered[filtered["exploited_flag"].fillna(0).astype(int) == 1]

    # Sort
    if "predicted_priority" in filtered.columns:
        filtered["_r"] = filtered["predicted_priority"].map(PRIORITY_RANK).fillna(0)
        sc = "predicted_priority_score" if "predicted_priority_score" in filtered.columns else "severity_raw"
        filtered = filtered.sort_values(["_r", sc], ascending=[False, False]).drop(columns="_r")
    filtered = filtered.reset_index(drop=True)

    total_rows = len(filtered)
    st.markdown(
        f"<div style='font-size:0.85rem;color:#6b7c6a;margin:8px 0 16px;'>"
        f"Showing <strong style='color:#043f2e;'>{total_rows:,}</strong> threats</div>",
        unsafe_allow_html=True,
    )

    # Pagination
    PAGE_SZ = 20
    total_pages = max(1, -(-total_rows // PAGE_SZ))
    if "t_page" not in st.session_state:
        st.session_state.t_page = 1
    if st.session_state.t_page > total_pages:
        st.session_state.t_page = 1

    start_i = (st.session_state.t_page - 1) * PAGE_SZ
    end_i   = min(start_i + PAGE_SZ, total_rows)
    page_df = filtered.iloc[start_i:end_i]

    # ── Threat cards ──────────────────────────────────────────────────────
    for _, row in page_df.iterrows():
        pv   = str(row.get("predicted_priority", "—"))
        pc   = P_COLOR.get(pv, "#043f2e")
        pb   = P_BG.get(pv,    "#fcfcfc")
        pcls = P_LEFT.get(pv,  "")
        sev  = row.get("severity_raw", 0)
        tid  = str(row.get("id", ""))
        ttl  = str(row.get("title", tid))
        src  = str(row.get("source", ""))
        ttype= str(row.get("threat_type", "")).replace("_", " ").title()
        exp  = bool(int(row.get("exploited_flag") or 0))
        cid  = row.get("cluster_id")
        clid = f"C{int(cid)}" if pd.notna(cid) else "—"
        score= round(float(row.get("predicted_priority_score") or 0), 3)
        analyst_lbl = row.get("analyst_label")

        exp_tag = (" · <span style='color:#991b1b;font-weight:600;font-size:10px;'>EXPLOIT</span>" if exp else "")

        with st.expander(
            f"{ttl[:65]}{'...' if len(ttl)>65 else ''}  ·  {pv}  ·  Sev {sev}/10{' · ⚡ EXPLOIT' if exp else ''}",
            expanded=False,
        ):
            # Header strip inside expander
            st.markdown(
                f"<div style='display:flex;flex-wrap:wrap;gap:8px;align-items:center;"
                f"padding:10px 0 14px;border-bottom:1px solid #e8edd9;margin-bottom:14px;'>"
                f"<span class='pill' style='background:{pb};color:{pc};border:1px solid {pc}44;'>{pv}</span>"
                f"<span class='pill' style='background:#eef2e3;color:#043f2e;border:none;'>{ttype}</span>"
                f"<span class='pill' style='background:#eef2e3;color:#043f2e;border:none;'>Cluster {clid}</span>"
                f"<span class='pill' style='background:#eef2e3;color:#043f2e;border:none;'>{src}</span>"
                f"{'<span class=\"pill\" style=\"background:#fef2f2;color:#991b1b;border:none;\">⚡ Exploit evidence</span>' if exp else ''}"
                f"{'<span class=\"pill pill-chartreuse\">✓ ' + str(analyst_lbl).replace('_',' ') + '</span>' if analyst_lbl and str(analyst_lbl) not in ('None','nan') else ''}"
                f"</div>",
                unsafe_allow_html=True,
            )

            d1, d2, d3 = st.columns(3)
            d1.metric("Severity", f"{sev}/10")
            d2.metric("ML Score",  score)
            d3.metric("Reports",   row.get("report_count", "—"))

            st.markdown("")

            # Description
            desc = str(row.get("description") or "")
            if desc:
                st.markdown(
                    f"<div style='background:#eef2e3;border-radius:8px;padding:12px 14px;"
                    f"font-size:0.86rem;color:#043f2e;line-height:1.6;margin-bottom:12px;'>"
                    f"{desc[:400]}{'...' if len(desc)>400 else ''}</div>",
                    unsafe_allow_html=True,
                )

            # AI Summary (collapsible)
            ai_sum = str(row.get("ai_summary") or "")
            if ai_sum and ai_sum not in ("None", "nan"):
                with st.expander("🧠 Analyst Summary", expanded=False):
                    sections = [s.strip() for s in ai_sum.split("\n\n") if s.strip()]
                    for sec in sections:
                        header = ""
                        if sec.startswith("**"):
                            end = sec.find("**", 2)
                            if end > 2:
                                header = sec[2:end].rstrip(":")
                        is_rec = "recommendation" in header.lower()
                        bc = "#f0fdf4" if is_rec else "#fcfcfc"
                        hc = "#166534" if is_rec else "#043f2e"
                        body = (
                            sec
                            .replace(f"**{header}:**\n", "")
                            .replace(f"**{header}:**", "")
                            .replace("\n- ", "<br>• ")
                            .replace("\n", "<br>")
                        )
                        body = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", body)
                        st.markdown(
                            f"<div style='background:{bc};border-left:3px solid {'#16a34a' if is_rec else '#c8f169'};"
                            f"border-radius:6px;padding:10px 14px;margin-bottom:8px;'>"
                            f"<div style='font-size:11px;font-weight:700;text-transform:uppercase;"
                            f"letter-spacing:0.06em;color:{hc};margin-bottom:4px;'>{header}</div>"
                            f"<div style='font-size:0.85rem;color:#242423;line-height:1.6;'>{body}</div>"
                            f"</div>",
                            unsafe_allow_html=True,
                        )

            # MITRE mappings (collapsible)
            mitre_maps = fetch_mitre_for_threat(tid)
            if mitre_maps:
                with st.expander(f"🧩 MITRE ATT&CK  ({len(mitre_maps)} technique{'s' if len(mitre_maps)>1 else ''})", expanded=False):
                    CONF_C = {"High": "#16a34a", "Medium": "#ca8a04", "Low": "#6b7c6a"}
                    for m in mitre_maps:
                        conf    = m.get("confidence", "Low")
                        tact    = m.get("tactic", "")
                        tech_id = m.get("technique_id", "")
                        tech_nm = m.get("technique_name", "")
                        basis   = m.get("basis", "")
                        url     = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"
                        cc      = CONF_C.get(conf, "#6b7c6a")
                        st.markdown(
                            f"<div style='border:1px solid #e8edd9;border-radius:8px;"
                            f"padding:10px 14px;margin-bottom:6px;'>"
                            f"<div style='display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px;'>"
                            f"<div><span style='font-size:11px;font-weight:700;color:{cc};"
                            f"text-transform:uppercase;letter-spacing:0.06em;'>{conf}</span>"
                            f"&nbsp;&nbsp;<strong style='color:#043f2e;'>{tech_id}</strong>"
                            f" — {tech_nm}"
                            f"<div style='font-size:0.75rem;color:#6b7c6a;margin-top:2px;'>"
                            f"Tactic: {tact}</div></div>"
                            f"<a href='{url}' target='_blank' style='font-size:11px;color:#043f2e;"
                            f"border:1px solid #043f2e;border-radius:4px;padding:3px 8px;"
                            f"text-decoration:none;white-space:nowrap;font-weight:500;'>"
                            f"ATT&CK ↗</a></div>"
                            f"<div style='font-size:0.75rem;color:#6b7c6a;margin-top:6px;"
                            f"padding-top:6px;border-top:1px solid #f0f0f0;'>{basis[:100]}</div>"
                            f"</div>",
                            unsafe_allow_html=True,
                        )

            # Analyst feedback (collapsible)
            with st.expander("✍️ Analyst Feedback", expanded=False):
                existing_fb = _fetch_feedback(tid)
                curr_lbl    = existing_fb.get("analyst_label") if existing_fb else None
                curr_notes  = existing_fb.get("feedback_notes") if existing_fb else ""

                if curr_lbl:
                    st.markdown(
                        f"<div style='background:#f0fdf4;border-left:3px solid #16a34a;"
                        f"border-radius:6px;padding:8px 12px;margin-bottom:10px;"
                        f"font-size:0.85rem;color:#166534;'>"
                        f"✓ Current label: <strong>{curr_lbl.replace('_',' ')}</strong>"
                        f"{'  ·  ' + curr_notes if curr_notes else ''}"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

                fb_key = f"fb_{tid[:20]}"
                sel_lbl = st.selectbox(
                    "Assign label",
                    options=["— no change —"] + list(_ANALYST_LABEL_OPTIONS),
                    index=0,
                    key=f"sel_{fb_key}",
                )
                notes = st.text_input("Notes (optional)", value=curr_notes or "", key=f"notes_{fb_key}")
                if st.button("Save Feedback", key=f"save_{fb_key}") and sel_lbl != "— no change —":
                    _upsert_feedback(tid, sel_lbl, notes, "analyst")
                    st.success("Feedback saved.")
                    st.rerun()

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 3 — CLUSTERS
# ═════════════════════════════════════════════════════════════════════════════
with tab_clusters:

    def _cluster_nlp_summary(g, avg_sev, pct_exp, dominant, types_str, sources_str, n_critical, n_high):
        n = len(g)
        has_cve = "cve" in types_str
        has_ip  = "malicious_ip" in types_str
        kind = ("CVEs and malicious IPs" if has_cve and has_ip
                else "CVE vulnerabilities" if has_cve
                else "malicious IP addresses")
        lines = [f"**What:** {n} {kind} sharing a similar profile across severity, exploitation, recency, and source."]
        reasons = []
        if avg_sev >= 8.5:   reasons.append(f"uniformly very high severity ({avg_sev:.1f}/10)")
        elif avg_sev >= 6.5: reasons.append(f"elevated severity ({avg_sev:.1f}/10)")
        else:                reasons.append(f"moderate–low severity ({avg_sev:.1f}/10)")
        if pct_exp >= 80:    reasons.append(f"nearly all exploited ({pct_exp:.0f}%)")
        elif pct_exp >= 20:  reasons.append(f"{pct_exp:.0f}% carry exploitation evidence")
        else:                reasons.append("no exploitation evidence found")
        if "abuseipdb" in sources_str and "nvd" not in sources_str:
            reasons.append("all from AbuseIPDB — community-reported abuse")
        elif "nvd" in sources_str and "abuseipdb" not in sources_str:
            reasons.append("all from NVD — formally catalogued vulnerabilities")
        lines.append("**Why grouped:** " + "; ".join(reasons) + ".")
        if avg_sev >= 9.0:   verdict = "CRITICAL — immediate analyst attention required."
        elif avg_sev >= 7.0: verdict = "HIGH — prompt review recommended."
        elif avg_sev >= 4.5: verdict = "MEDIUM — standard patching cycle."
        else:                verdict = "LOW — routine monitoring."
        lines.append(f"**Severity verdict:** {verdict}")
        if n_critical or n_high:
            lines.append(f"**Priority breakdown:** {n_critical} Critical · {n_high} High · {n - n_critical - n_high} Medium/Low")
        return "\n\n".join(lines)

    st.markdown("<span class='eyebrow'>Threat Clusters</span>", unsafe_allow_html=True)
    st.markdown("""
<div style='background:#fcfcfc;border-radius:12px;padding:14px 18px;
            border:1px solid #e8edd9;margin-bottom:20px;font-size:0.85rem;color:#6b7c6a;'>
<strong style='color:#043f2e;'>How it works:</strong>
K-Means clustering on 7 features (severity, exploitation, recency, report count, source reliability, is_cve, is_malicious_ip)
+ TF-IDF text signal (30% weight). K auto-selected by silhouette score (k=3–8).
A cluster reflects <em>statistical similarity</em>, not a confirmed campaign.
</div>
""", unsafe_allow_html=True)

    has_clusters = "cluster_id" in df.columns and df["cluster_id"].notna().any()
    if not has_clusters:
        st.info("No cluster data. Re-run: `python scripts/run_pipeline.py --retrain`")
    else:
        cluster_df = df[df["cluster_id"].notna()].copy()
        cluster_df["cluster_id"] = cluster_df["cluster_id"].astype(int)

        cluster_stats = {}
        for cid in sorted(cluster_df["cluster_id"].unique()):
            g = cluster_df[cluster_df["cluster_id"] == cid]
            n_crit = int((g["predicted_priority"] == "Critical").sum()) if "predicted_priority" in g.columns else 0
            n_hi   = int((g["predicted_priority"] == "High").sum())     if "predicted_priority" in g.columns else 0
            dom    = g["predicted_priority"].value_counts().index[0]    if "predicted_priority" in g.columns and len(g) > 0 else "—"
            types_d  = g["threat_type"].value_counts().to_dict()  if "threat_type" in g.columns else {}
            sources_d= g["source"].value_counts().to_dict()        if "source"      in g.columns else {}
            types_s  = ", ".join(f"{t}({c})" for t, c in types_d.items())
            srcs_s   = ", ".join(f"{s}({c})" for s, c in sources_d.items())
            avg_sev  = round(float(g["severity_raw"].mean()), 2)
            pct_exp  = round(float(g["exploited_flag"].fillna(0).mean()) * 100, 1)
            notable  = avg_sev >= 7.0 or pct_exp >= 20.0 or n_crit >= 3
            cluster_stats[cid] = dict(g=g, n=len(g), avg_sev=avg_sev, pct_exp=pct_exp,
                                       types_str=types_s, sources_str=srcs_s,
                                       n_critical=n_crit, n_high=n_hi,
                                       dominant=dom, notable=notable)

        sorted_cids = sorted(cluster_stats, key=lambda c: (not cluster_stats[c]["notable"], -cluster_stats[c]["avg_sev"]))

        # Donut row
        donut_cols = st.columns(len(sorted_cids))
        for col, cid in zip(donut_cols, sorted_cids):
            cs = cluster_stats[cid]
            fig_dn, ax_dn = plt.subplots(figsize=(2.5, 2.5))
            fig_dn.patch.set_facecolor("#eef2e3")
            ax_dn.set_facecolor("#eef2e3")
            p_counts = cs["g"]["predicted_priority"].value_counts() if "predicted_priority" in cs["g"].columns else {}
            lo = ["Critical","High","Medium","Low"]
            cm = {"Critical":"#dc2626","High":"#ea580c","Medium":"#ca8a04","Low":"#16a34a"}
            pres = [(l, int(p_counts.get(l,0))) for l in lo if p_counts.get(l,0) > 0]
            if pres:
                lv, vv = zip(*pres)
                cv = [cm[l] for l in lv]
                ax_dn.pie(vv, colors=cv, startangle=90, counterclock=False,
                           wedgeprops={"width":0.5,"edgecolor":"#eef2e3","linewidth":2})
            ax_dn.text(0, 0, str(cs["n"]), ha="center", va="center",
                       fontsize=12, fontweight="600", color="#043f2e")
            ax_dn.set_title(f"C{cid}", color="#043f2e", fontsize=9, fontweight="600", pad=3)
            plt.tight_layout(pad=0.2)
            col.pyplot(fig_dn, use_container_width=True)
            plt.close(fig_dn)
            sv_lbl = "CRITICAL" if cs["avg_sev"]>=9 else "HIGH" if cs["avg_sev"]>=7 else "MEDIUM" if cs["avg_sev"]>=4.5 else "LOW"
            sv_col = "#dc2626" if sv_lbl=="CRITICAL" else "#ea580c" if sv_lbl=="HIGH" else "#ca8a04" if sv_lbl=="MEDIUM" else "#16a34a"
            col.markdown(f"<div style='text-align:center;font-size:10px;font-weight:700;color:{sv_col};margin-top:-8px;'>{sv_lbl} · {cs['avg_sev']}/10</div>", unsafe_allow_html=True)

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        for cid in sorted_cids:
            cs = cluster_stats[cid]
            sv_lbl = "CRITICAL" if cs["avg_sev"]>=9 else "HIGH" if cs["avg_sev"]>=7 else "MEDIUM" if cs["avg_sev"]>=4.5 else "LOW"
            notable_tag = "  ⚠ NOTABLE" if cs["notable"] else ""
            with st.expander(
                f"Cluster {cid}  ·  {sv_lbl}  ·  {cs['n']} threats{notable_tag}",
                expanded=cs["notable"],
            ):
                s1, s2, s3, s4 = st.columns(4)
                s1.metric("Avg Severity", f"{cs['avg_sev']}/10")
                s2.metric("% Exploited",  f"{cs['pct_exp']:.0f}%")
                s3.metric("Critical",     cs["n_critical"])
                s4.metric("High",         cs["n_high"])
                ic1, ic2 = st.columns(2)
                ic1.markdown(f"**Types:** `{cs['types_str']}`")
                ic2.markdown(f"**Sources:** `{cs['sources_str']}`")
                st.divider()
                st.markdown("**Analyst Summary**")
                summary_text = _cluster_nlp_summary(
                    cs["g"], cs["avg_sev"], cs["pct_exp"],
                    cs["dominant"], cs["types_str"], cs["sources_str"],
                    cs["n_critical"], cs["n_high"],
                )
                for line in summary_text.split("\n\n"):
                    hdr = ""
                    if line.startswith("**"):
                        e = line.find("**", 2)
                        if e > 2:
                            hdr = line[2:e]
                    body = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>",
                                  line.replace(f"**{hdr}:**", "").replace(f"**{hdr}**", "").strip())
                    st.markdown(
                        f"<div style='background:#eef2e3;border-left:3px solid #c8f169;"
                        f"border-radius:6px;padding:8px 12px;margin-bottom:6px;"
                        f"font-size:0.85rem;color:#043f2e;'>"
                        f"{'<strong>' + hdr + ':</strong> ' if hdr else ''}{body}</div>",
                        unsafe_allow_html=True,
                    )
                with st.expander(f"View {cs['n']} member threats", expanded=False):
                    members = cs["g"].copy()
                    if "predicted_priority" in members.columns:
                        members["_r"] = members["predicted_priority"].map(PRIORITY_RANK).fillna(0)
                        members = members.sort_values(["_r","severity_raw"], ascending=[False,False]).drop(columns="_r")
                    mc = ["id","threat_type","title","severity_raw","predicted_priority","exploited_flag","source","last_seen"]
                    mc = [c for c in mc if c in members.columns]
                    mr = {"id":"ID","threat_type":"Type","title":"Title","severity_raw":"Severity",
                          "predicted_priority":"Priority","exploited_flag":"Exploited","source":"Source","last_seen":"Last Seen"}
                    mdf = members[mc].rename(columns=mr)
                    if "Severity" in mdf.columns:
                        mdf["Severity"] = mdf["Severity"].round(2)
                    st.dataframe(mdf, use_container_width=True, hide_index=True)

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 4 — MITRE ATT&CK
# ═════════════════════════════════════════════════════════════════════════════
with tab_mitre:
    st.markdown("<span class='eyebrow'>MITRE ATT&CK Mappings</span>", unsafe_allow_html=True)
    st.markdown("""
<div style='background:#fcfcfc;border-radius:12px;padding:14px 18px;border:1px solid #e8edd9;
            margin-bottom:20px;font-size:0.85rem;color:#6b7c6a;'>
<strong style='color:#043f2e;'>Confidence tiers:</strong>
<span style='color:#16a34a;font-weight:600;'>High</span> = CWE-documented relationship ·
<span style='color:#ca8a04;font-weight:600;'>Medium</span> = keyword inference ·
<span style='color:#6b7c6a;font-weight:600;'>Low</span> = threat-type inference.
Mappings are investigative starting points — not analyst-verified ATT&CK assignments.
</div>
""", unsafe_allow_html=True)

    all_mitre = fetch_all_mitre_mappings()
    if not all_mitre:
        st.info("No MITRE mappings found. Re-run: `python scripts/run_pipeline.py --retrain`")
    else:
        mdf = pd.DataFrame(all_mitre)
        n_high_m  = int((mdf["confidence"] == "High").sum())
        n_med_m   = int((mdf["confidence"] == "Medium").sum())
        n_low_m   = int((mdf["confidence"] == "Low").sum())

        mm1, mm2, mm3, mm4 = st.columns(4)
        mm1.metric("Total Mappings",    len(mdf))
        mm2.metric("Threats Covered",   mdf["threat_id"].nunique())
        mm3.metric("Unique Techniques", mdf["technique_id"].nunique())
        mm4.metric("High Confidence",   n_high_m)

        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

        mc1, mc2 = st.columns([3, 2], gap="large")
        with mc1:
            st.markdown("<span class='eyebrow'>Tactic Distribution</span>", unsafe_allow_html=True)
            tactic_counts = mdf.groupby("tactic").size().reset_index(name="count").sort_values("count", ascending=True)
            TACTIC_COLORS_M = {
                "Reconnaissance":"#043f2e","Initial Access":"#dc2626","Execution":"#ea580c",
                "Persistence":"#ca8a04","Privilege Escalation":"#16a34a","Defense Evasion":"#0891b2",
                "Credential Access":"#9333ea","Discovery":"#2563eb","Lateral Movement":"#db2777",
                "Collection":"#059669","Command and Control":"#d97706","Exfiltration":"#be123c","Impact":"#b45309",
            }
            bar_cols_m = [TACTIC_COLORS_M.get(t, "#043f2e") for t in tactic_counts["tactic"]]
            fig_t, ax_t = plt.subplots(figsize=(7, max(3, len(tactic_counts) * 0.5)))
            fig_t.patch.set_facecolor("#eef2e3")
            ax_t.set_facecolor("#fcfcfc")
            bars_t = ax_t.barh(tactic_counts["tactic"], tactic_counts["count"],
                                color=bar_cols_m, edgecolor="#e8edd9", linewidth=0.6)
            ax_t.set_xlabel("Mappings", color="#6b7c6a", fontsize=8)
            ax_t.set_title("ATT&CK Tactic Coverage", color="#043f2e", fontsize=10, fontweight="600")
            ax_t.tick_params(colors="#6b7c6a", labelsize=8)
            ax_t.spines[:].set_color("#e8edd9")
            for bar, val in zip(bars_t, tactic_counts["count"]):
                ax_t.text(val + 0.3, bar.get_y() + bar.get_height()/2, str(val),
                           va="center", color="#043f2e", fontsize=7.5)
            plt.tight_layout()
            st.pyplot(fig_t, use_container_width=True)
            plt.close(fig_t)

        with mc2:
            st.markdown("<span class='eyebrow'>Top Techniques</span>", unsafe_allow_html=True)
            tech_top = (mdf.groupby(["technique_id","technique_name"])
                        .size().reset_index(name="count")
                        .sort_values("count", ascending=False).head(8))
            for _, tr in tech_top.iterrows():
                st.markdown(
                    f"<div style='display:flex;justify-content:space-between;align-items:center;"
                    f"padding:7px 0;border-bottom:1px solid #e8edd9;'>"
                    f"<div><div style='font-size:0.82rem;font-weight:500;color:#043f2e;'>"
                    f"{tr['technique_id']}</div>"
                    f"<div style='font-size:0.75rem;color:#6b7c6a;'>{str(tr['technique_name'])[:35]}</div></div>"
                    f"<span class='pill pill-chartreuse'>{tr['count']}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

        st.divider()
        st.markdown("<span class='eyebrow'>Per-Threat Lookup</span>", unsafe_allow_html=True)
        mapped_ids = sorted(mdf["threat_id"].unique().tolist())
        sel_mitre = st.selectbox("Select a threat ID",
                                  options=mapped_ids,
                                  format_func=lambda x: f"{x[:65]}..." if len(str(x)) > 65 else x,
                                  key="mitre_select")
        if sel_mitre:
            t_maps = fetch_mitre_for_threat(sel_mitre)
            t_row  = df[df["id"] == sel_mitre]
            if not t_row.empty:
                tr = t_row.iloc[0]
                pv = tr.get("predicted_priority","—")
                pc = P_COLOR.get(pv, "#043f2e")
                p_bg_val = P_BG.get(pv, "#fcfcfc")
                st.markdown(
                    f"<div style='background:#fcfcfc;border-radius:10px;padding:12px 16px;"
                    f"border:1px solid #e8edd9;margin-bottom:12px;display:flex;"
                    f"align-items:center;gap:12px;flex-wrap:wrap;'>"
                    f"<span style='font-weight:600;color:#043f2e;'>{tr['title']}</span>"
                    f"<span class='pill' style='background:{p_bg_val};color:{pc};border:1px solid {pc}44;'>{pv}</span>"
                    f"<span style='color:#6b7c6a;font-size:0.82rem;'>Severity {tr['severity_raw']}/10 · {tr['source']}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
            CONF_C2 = {"High":"#16a34a","Medium":"#ca8a04","Low":"#6b7c6a"}
            for m in t_maps:
                conf  = m.get("confidence","Low")
                cc    = CONF_C2.get(conf, "#6b7c6a")
                t_id  = m.get("technique_id","")
                t_nm  = m.get("technique_name","")
                tact  = m.get("tactic","")
                basis = m.get("basis","")
                url   = f"https://attack.mitre.org/techniques/{t_id.replace('.','/')}"
                st.markdown(
                    f"<div style='background:#fcfcfc;border:1px solid #e8edd9;"
                    f"border-left:4px solid {cc};border-radius:8px;"
                    f"padding:12px 16px;margin-bottom:8px;'>"
                    f"<div style='display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap;'>"
                    f"<div><span style='font-size:10px;font-weight:700;color:{cc};"
                    f"text-transform:uppercase;letter-spacing:0.06em;'>{conf}</span>"
                    f"&nbsp;&nbsp;<strong style='color:#043f2e;'>{t_id}</strong> — {t_nm}"
                    f"<div style='font-size:0.75rem;color:#6b7c6a;margin-top:3px;'>Tactic: {tact}</div></div>"
                    f"<a href='{url}' target='_blank' style='font-size:11px;color:#043f2e;"
                    f"border:1px solid #043f2e;border-radius:4px;padding:3px 10px;"
                    f"text-decoration:none;font-weight:500;white-space:nowrap;'>ATT&CK ↗</a>"
                    f"</div>"
                    f"<div style='font-size:0.75rem;color:#6b7c6a;margin-top:7px;"
                    f"padding-top:7px;border-top:1px solid #f0f0f0;'>{basis[:120]}</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 5 — MONITORING
# ═════════════════════════════════════════════════════════════════════════════
with tab_monitor:
    st.markdown("<span class='eyebrow'>Continuous Monitoring</span>", unsafe_allow_html=True)
    runs_all = fetch_pipeline_runs(limit=50)
    hist_all = fetch_threat_history(limit=500)
    runs_df2 = pd.DataFrame(runs_all)  if runs_all  else pd.DataFrame()
    hist_df2 = pd.DataFrame(hist_all)  if hist_all  else pd.DataFrame()

    if not runs_df2.empty:
        lat = runs_df2.iloc[0]
        pm1, pm2, pm3, pm4, pm5 = st.columns(5)
        pm1.metric("Total Runs",     len(runs_df2))
        pm2.metric("Latest New",     int(lat.get("new_threats",     0)))
        pm3.metric("Latest Changed", int(lat.get("updated_threats", 0)))
        pm4.metric("Total Threats",  int(lat.get("total_threats",   0)))
        pm5.metric("Last Duration",  f"{lat.get('duration_secs',0):.1f}s")

        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

        mon_l, mon_r = st.columns([3, 2], gap="large")
        with mon_l:
            # Run history
            st.markdown("<span class='eyebrow'>Run History</span>", unsafe_allow_html=True)
            run_disp = runs_df2[
                [c for c in ["run_id","run_at","mode","total_threats","new_threats",
                              "updated_threats","n_critical","n_high","duration_secs","notes"]
                 if c in runs_df2.columns]
            ].copy()
            rn = {"run_id":"Run #","run_at":"Timestamp","mode":"Mode","total_threats":"Total",
                  "new_threats":"New","updated_threats":"Changed","n_critical":"Critical",
                  "n_high":"High","duration_secs":"Duration (s)","notes":"Notes"}
            run_disp = run_disp.rename(columns=rn)
            if "Timestamp" in run_disp.columns:
                run_disp["Timestamp"] = run_disp["Timestamp"].str[:19].str.replace("T"," ")
            if "Duration (s)" in run_disp.columns:
                run_disp["Duration (s)"] = run_disp["Duration (s)"].round(1)
            st.dataframe(run_disp, use_container_width=True, hide_index=True)

            # Bar chart
            if len(runs_df2) >= 2 and "new_threats" in runs_df2.columns:
                st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
                st.markdown("<span class='eyebrow'>New & Changed per Run</span>", unsafe_allow_html=True)
                plot_r = runs_df2.sort_values("run_id").tail(15)
                xlbls  = [f"Run {int(r)}" for r in plot_r["run_id"]]
                new_v  = plot_r["new_threats"].fillna(0).astype(int).tolist()
                chg_v  = plot_r["updated_threats"].fillna(0).astype(int).tolist()
                xp = range(len(xlbls))
                w  = 0.4
                fig_r, ax_r = plt.subplots(figsize=(min(9, len(xlbls)+2), 3.2))
                fig_r.patch.set_facecolor("#eef2e3")
                ax_r.set_facecolor("#fcfcfc")
                ax_r.bar([x-w/2 for x in xp], new_v, width=w, color="#043f2e", label="New")
                ax_r.bar([x+w/2 for x in xp], chg_v, width=w, color="#c8f169", label="Changed")
                ax_r.set_xticks(list(xp)); ax_r.set_xticklabels(xlbls, rotation=25, ha="right", fontsize=8, color="#043f2e")
                ax_r.tick_params(colors="#6b7c6a", labelsize=8)
                ax_r.spines[:].set_color("#e8edd9")
                ax_r.set_facecolor("#fcfcfc"); fig_r.patch.set_facecolor("#eef2e3")
                ax_r.legend(frameon=False, fontsize=8, labelcolor="#043f2e")
                plt.tight_layout()
                st.pyplot(fig_r, use_container_width=True)
                plt.close(fig_r)

        with mon_r:
            st.markdown("<span class='eyebrow'>Activity Feed</span>", unsafe_allow_html=True)
            if not hist_df2.empty:
                fc_opt = st.multiselect("Filter", ["new","escalated","reduced"],
                                         default=["new","escalated","reduced"], key="mon_filter")
                feed = hist_df2[hist_df2["change_type"].isin(fc_opt)].head(40)
                DOT2 = {"new":"dot-new","escalated":"dot-escalate","reduced":"dot-reduced"}
                CHANGE_LABEL = {"new":"🟢 NEW","escalated":"🔴 ESCALATED","reduced":"🔵 REDUCED"}
                for _, ev in feed.iterrows():
                    ct   = ev.get("change_type","")
                    dotc = DOT2.get(ct,"dot-new")
                    tid2 = str(ev.get("threat_id",""))[:30]
                    prev = ev.get("previous_priority") or "—"
                    newp = ev.get("new_priority") or "—"
                    ts   = str(ev.get("run_at",""))[:16].replace("T"," ")
                    clbl = CHANGE_LABEL.get(ct, ct)
                    arrow = f"{prev} → {newp}" if ct != "new" else f"Priority: {newp}"
                    st.markdown(
                        f"<div style='display:flex;gap:8px;padding:7px 0;"
                        f"border-bottom:1px solid #e8edd9;align-items:flex-start;'>"
                        f"<span class='{dotc}' style='margin-top:5px;flex-shrink:0;'></span>"
                        f"<div><div style='font-size:0.8rem;font-weight:500;color:#043f2e;'>{tid2}</div>"
                        f"<div style='font-size:0.73rem;color:#6b7c6a;'>{arrow} · {ts}</div></div>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

            st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
            st.markdown("<span class='eyebrow'>Per-Threat Timeline</span>", unsafe_allow_html=True)
            if not hist_df2.empty:
                th_ids = sorted(hist_df2["threat_id"].dropna().unique().tolist())
                sel_th = st.selectbox("Select threat", options=th_ids,
                                       format_func=lambda x: f"{x[:55]}..." if len(str(x))>55 else x,
                                       key="mon_th_sel")
                from src.pipeline.db import fetch_threat_history_for_id
                th_hist = fetch_threat_history_for_id(sel_th)
                if th_hist and len(th_hist) >= 2:
                    scores  = [float(h["new_score"]) for h in th_hist if h.get("new_score") is not None]
                    run_lbs = [f"R{h['run_id']}" for h in th_hist if h.get("new_score") is not None]
                    if len(scores) >= 2:
                        fig_h, ax_h = plt.subplots(figsize=(5, 2.5))
                        fig_h.patch.set_facecolor("#eef2e3")
                        ax_h.set_facecolor("#fcfcfc")
                        ax_h.plot(run_lbs, scores, color="#043f2e", linewidth=2,
                                   marker="o", markersize=5, markerfacecolor="#c8f169",
                                   markeredgecolor="#043f2e", markeredgewidth=1.2)
                        ax_h.set_ylim(0, 1.05)
                        ax_h.tick_params(colors="#6b7c6a", labelsize=8)
                        ax_h.spines[:].set_color("#e8edd9")
                        ax_h.set_ylabel("Score", color="#6b7c6a", fontsize=8)
                        plt.xticks(rotation=15, ha="right")
                        plt.tight_layout()
                        st.pyplot(fig_h, use_container_width=True)
                        plt.close(fig_h)
    else:
        st.info("No pipeline runs recorded yet. Run the pipeline to start monitoring.")

    # ── Download Report ────────────────────────────────────────────────────
    st.divider()
    st.markdown("<span class='eyebrow'>Threat Intelligence Report</span>", unsafe_allow_html=True)
    st.markdown(
        "<div style='background:#fcfcfc;border-radius:12px;padding:14px 18px;"
        "border:1px solid #e8edd9;margin-bottom:16px;font-size:0.85rem;color:#6b7c6a;'>"
        "Generates a self-contained HTML report with executive summary, priority distribution, "
        "top threats, priority changes, cluster summary, MITRE ATT&CK coverage, alerts, "
        "run history, and the full threat table — all embedded with charts. "
        "No external dependencies. Opens in any browser."
        "</div>",
        unsafe_allow_html=True,
    )

    rep_c1, rep_c2 = st.columns([2, 3])
    with rep_c1:
        scope_opt = st.selectbox(
            "Report scope",
            options=["All data", "Latest run only"],
            key="rep_scope",
        )
    with rep_c2:
        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
        if st.button("📥  Generate & Download Report", key="gen_report"):
            with st.spinner("Generating report…"):
                try:
                    from src.pipeline.reporter import generate_html_report
                    import datetime as _dt

                    _rows    = db.fetch_all_as_dicts()
                    _runs    = fetch_pipeline_runs(limit=50)
                    _history = fetch_threat_history(limit=1000)
                    _mitre   = fetch_all_mitre_mappings()
                    _alerts  = _fetch_alerts(limit=500)

                    _run_filter = None
                    if scope_opt == "Latest run only" and _runs:
                        _run_filter = {_runs[0]["run_id"]}

                    html_report = generate_html_report(
                        _rows, _runs, _history, _mitre, _alerts,
                        run_filter_ids=_run_filter,
                    )

                    _ts       = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                    _filename = f"threat_report_{_ts}.html"

                    # Save to reports/ directory
                    _out = REPORTS_DIR / _filename
                    _out.write_text(html_report, encoding="utf-8")

                    st.download_button(
                        label=f"⬇  Download {_filename}",
                        data=html_report.encode("utf-8"),
                        file_name=_filename,
                        mime="text/html",
                        key=f"dl_{_ts}",
                    )
                    st.success(
                        f"Report generated: **{len(html_report):,}** bytes · "
                        f"**{len(_rows):,}** threats · also saved to `reports/{_filename}`"
                    )
                except Exception as _e:
                    st.error(f"Report generation failed: {_e}")

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 6 — ALERTS (capped 20 visible, fast acknowledge)
# ═════════════════════════════════════════════════════════════════════════════
with tab_alerts:
    st.markdown("<span class='eyebrow'>Alerts</span>", unsafe_allow_html=True)

    al_c1, al_c2, al_c3 = st.columns([2, 2, 1])
    with al_c1:
        sev_filter_al = st.multiselect(
            "Severity", options=["critical","high","warning","info"],
            default=["critical","high","warning","info"], key="al_sev",
        )
    with al_c2:
        stat_filter_al = st.multiselect(
            "Status", options=["new","acknowledged","dismissed"],
            default=["new"], key="al_stat",
        )
    with al_c3:
        al_limit = st.selectbox("Show", options=[10, 20, 50], index=1, key="al_limit")

    all_alerts_raw = _fetch_alerts(limit=500)
    if not all_alerts_raw:
        st.markdown(
            "<div style='background:#fcfcfc;border-radius:12px;padding:40px;"
            "text-align:center;border:1px solid #e8edd9;color:#6b7c6a;'>"
            "✅ No alerts generated yet. Run the pipeline to trigger alerting.</div>",
            unsafe_allow_html=True,
        )
    else:
        al_df = pd.DataFrame(all_alerts_raw)
        filtered_al = al_df[
            al_df["severity"].isin(sev_filter_al) &
            al_df["status"].isin(stat_filter_al)
        ].head(al_limit)

        unread_count = int((al_df["status"] == "new").sum())
        total_count  = len(al_df)

        st.markdown(
            f"<div style='font-size:0.85rem;color:#6b7c6a;margin-bottom:14px;'>"
            f"<strong style='color:#043f2e;'>{unread_count}</strong> unread · "
            f"<strong style='color:#043f2e;'>{total_count}</strong> total · "
            f"showing <strong style='color:#043f2e;'>{len(filtered_al)}</strong></div>",
            unsafe_allow_html=True,
        )

        if not filtered_al.empty:
            # Bulk acknowledge button
            if unread_count > 0:
                bc1, bc2 = st.columns([1, 5])
                if bc1.button("✓ Acknowledge all new", key="ack_all"):
                    new_ids = al_df[al_df["status"] == "new"]["alert_id"].tolist()
                    for aid in new_ids:
                        _update_alert_status(int(aid), "acknowledged")
                    st.success(f"Acknowledged {len(new_ids)} alerts.")
                    st.rerun()

            AL_STYLE_M = {
                "critical": ("#dc2626", "#fff5f5", "🔴"),
                "high":     ("#ea580c", "#fff8f0", "🟠"),
                "warning":  ("#ca8a04", "#fffdf0", "🟡"),
                "info":     ("#043f2e", "#f0f7f0", "🟢"),
            }
            for _, al in filtered_al.iterrows():
                sev2   = str(al.get("severity","info")).lower()
                status2= al.get("status","new")
                atype2 = al.get("alert_type","").replace("_"," ").title()
                msg2   = al.get("message","")
                aid2   = int(al.get("alert_id", 0))
                tid3   = str(al.get("threat_id") or "")
                tid3   = "" if tid3 in ("nan","None","") else tid3
                run_id3= al.get("run_id","")
                created= str(al.get("created_at",""))[:16].replace("T"," ")

                brd_col, bg_col, dot3 = AL_STYLE_M.get(sev2, ("#043f2e","#f0f7f0","•"))
                opacity = "0.5" if status2 == "dismissed" else "1"

                st.markdown(
                    f"<div style='border-left:4px solid {brd_col};background:{bg_col};"
                    f"border-radius:8px;padding:12px 16px;margin-bottom:8px;opacity:{opacity};'>"
                    f"<div style='display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;'>"
                    f"<div>"
                    f"<span style='font-size:10px;font-weight:700;text-transform:uppercase;"
                    f"letter-spacing:0.06em;color:{brd_col};'>{dot3} {atype2}</span>"
                    f"<div style='font-size:0.88rem;color:#043f2e;margin-top:4px;"
                    f"font-weight:500;'>{msg2[:130]}</div>"
                    f"<div style='font-size:0.75rem;color:#6b7c6a;margin-top:4px;'>"
                    f"{'ID: ' + tid3[:45] + ' · ' if tid3 else ''}Run #{run_id3} · {created}"
                    f"&nbsp;·&nbsp;<span style='font-weight:600;'>{status2.upper()}</span></div>"
                    f"</div>"
                    f"</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

                # Action buttons — only for non-dismissed
                if status2 != "dismissed":
                    btn_c1, btn_c2, btn_c3 = st.columns([1, 1, 8])
                    if status2 == "new":
                        if btn_c1.button("✓ Ack", key=f"ack_{aid2}"):
                            _update_alert_status(aid2, "acknowledged")
                            st.rerun()
                    if btn_c2.button("✕ Dismiss", key=f"dis_{aid2}"):
                        _update_alert_status(aid2, "dismissed")
                        st.rerun()

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 7 — SETTINGS
# ═════════════════════════════════════════════════════════════════════════════
with tab_settings:
    from src.config_org import load_org_context, save_org_context, org_context_configured
    from src.pipeline.context_scorer import apply_context_score

    st.markdown("<span class='eyebrow'>Organisational Context</span>", unsafe_allow_html=True)
    st.markdown("""
<div style='background:#fcfcfc;border-radius:12px;padding:14px 18px;border:1px solid #e8edd9;
            margin-bottom:20px;font-size:0.85rem;color:#6b7c6a;'>
Configure your asset profile to receive a <em>context-adjusted score</em> alongside the ML prediction.
This score is for display guidance only — it never retrains the model.
Saved to <code>org_context.json</code> (not committed to git).
After saving, re-run: <code>python scripts/run_pipeline.py --retrain</code>
</div>
""", unsafe_allow_html=True)

    current_ctx = load_org_context()
    configured  = org_context_configured()
    if configured:
        st.success(f"Context configured: **{current_ctx.get('org_name','unnamed')}**")

    with st.form("org_form"):
        org_name = st.text_input("Organisation name", value=current_ctx.get("org_name",""), placeholder="e.g. Acme Corp")
        hv_raw   = st.text_input("High-value asset keywords (comma-separated)",
                                   value=", ".join(current_ctx.get("high_value_assets",[])),
                                   placeholder="e.g. Apache, OpenSSL, Cisco, Microsoft")
        inet_exp = st.checkbox("Internet-exposed environment", value=bool(current_ctx.get("internet_exposed", False)))
        crit_opt = ["low","medium","high","critical"]
        criticality = st.selectbox("Organisation criticality", options=crit_opt,
                                    index=crit_opt.index(current_ctx.get("criticality","medium")))
        ign_raw  = st.text_input("Ignored sources (comma-separated, leave blank for none)",
                                  value=", ".join(current_ctx.get("ignored_sources",[])))
        saved = st.form_submit_button("💾  Save Configuration")

    if saved:
        save_org_context({
            "org_name":          org_name.strip(),
            "high_value_assets": [a.strip() for a in hv_raw.split(",") if a.strip()],
            "internet_exposed":  inet_exp,
            "criticality":       criticality,
            "ignored_sources":   [s.strip() for s in ign_raw.split(",") if s.strip()],
        })
        st.success("Saved. Re-run the pipeline to apply context scores to all threats.")
        st.rerun()

    if configured and not saved:
        st.divider()
        st.markdown("<span class='eyebrow'>Live Preview (first 15 threats)</span>", unsafe_allow_html=True)
        preview_rows = df.head(15).to_dict(orient="records")
        ctx = load_org_context()
        prev_data = []
        for row in preview_rows:
            adj, reasons = apply_context_score(row, ctx)
            base = round(float(row.get("predicted_priority_score") or 0), 4)
            adj_v = round(adj, 4) if adj is not None else base
            diff  = round(adj_v - base, 4) if adj is not None else 0
            prev_data.append({
                "ID":            str(row.get("id",""))[:35],
                "ML Priority":   row.get("predicted_priority","—"),
                "Base Score":    base,
                "Context Score": adj_v,
                "Boost":         f"+{diff:.4f}" if diff > 0 else str(diff),
                "Reason":        reasons[0][:60] if reasons else "—",
            })
        st.dataframe(pd.DataFrame(prev_data), use_container_width=True, hide_index=True)

# ═════════════════════════════════════════════════════════════════════════════
#  TAB 8 — MODEL EVALUATION
# ═════════════════════════════════════════════════════════════════════════════
with tab_models:
    st.markdown("<span class='eyebrow'>Model Evaluation</span>", unsafe_allow_html=True)
    st.markdown("""
<div style='background:#fcfcfc;border-radius:12px;padding:12px 16px;border:1px solid #e8edd9;
            margin-bottom:16px;font-size:0.82rem;color:#6b7c6a;'>
⚠ Labels are heuristic — accuracy reflects how well the model learns the scoring formula,
not real analyst agreement. F1 &lt; 0.5 on Critical/High is expected with severe class imbalance.
</div>
""", unsafe_allow_html=True)

    metrics_path = REPORTS_DIR / "metrics.json"
    if not metrics_path.exists():
        st.info("No evaluation metrics found. Run the pipeline to generate them.")
    else:
        with open(metrics_path) as f:
            metrics = json.load(f)

        # Accuracy row
        acc_cols = st.columns(len(metrics))
        for col, (name, m) in zip(acc_cols, metrics.items()):
            col.metric(
                name.replace("_"," ").title(),
                f"{m['accuracy']*100:.1f}%",
                help="Accuracy on held-out test set (heuristic labels)",
            )

        # Per-class F1
        per_class_path = REPORTS_DIR / "per_class_metrics.json"
        f1_chart_path  = REPORTS_DIR / "per_class_f1_comparison.png"

        if per_class_path.exists():
            st.divider()
            st.markdown("<span class='eyebrow'>Per-Class F1 Scores</span>", unsafe_allow_html=True)
            with open(per_class_path) as f:
                per_class = json.load(f)

            for model_name, class_data in per_class.items():
                with st.expander(
                    f"{model_name.replace('_',' ').title()} — per-class metrics",
                    expanded=(model_name == "random_forest"),
                ):
                    pc_rows = []
                    for cls in ["Critical","High","Medium","Low"]:
                        cd  = class_data.get(cls, {})
                        f1v = cd.get("f1", 0)
                        pc_rows.append({
                            "Class":     cls,
                            "Precision": cd.get("precision", 0),
                            "Recall":    cd.get("recall",    0),
                            "F1":        f1v,
                            "Support":   cd.get("support",   0),
                            "Status":    "⚠️ LOW" if f1v < 0.5 else "✅",
                        })
                    st.dataframe(pd.DataFrame(pc_rows), use_container_width=True, hide_index=True)
                    if model_name == "random_forest_smote":
                        st.markdown(
                            "<div style='background:#f0fdf4;border-left:3px solid #16a34a;"
                            "border-radius:6px;padding:8px 12px;font-size:0.82rem;color:#166534;'>"
                            "⚗️ Strategy B (SMOTE) — compare Critical/High F1 with baseline Random Forest "
                            "to assess whether oversampling improves minority-class detection.</div>",
                            unsafe_allow_html=True,
                        )

        if f1_chart_path.exists():
            st.divider()
            st.markdown("<span class='eyebrow'>F1 Comparison Chart</span>", unsafe_allow_html=True)
            st.image(str(f1_chart_path), caption="Per-class F1 across all models (Phase 11)")

        st.divider()
        for name in metrics:
            cm_path = REPORTS_DIR / f"confusion_matrix_{name}.png"
            fi_path = REPORTS_DIR / f"feature_importance_{name}.png"
            if cm_path.exists() or fi_path.exists():
                with st.expander(f"{name.replace('_',' ').title()} — charts", expanded=False):
                    c1, c2 = st.columns(2)
                    if cm_path.exists():
                        c1.image(str(cm_path), caption="Confusion Matrix")
                    if fi_path.exists():
                        c2.image(str(fi_path), caption="Feature Importance")
