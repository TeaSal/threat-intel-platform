"""
Phase 6 — Automated Threat Intelligence Reports.

Generates a self-contained, dark-themed HTML report from DB data alone.
No external API calls are made. All charts are embedded as base64 PNGs.

Usage (standalone):
    python -m src.pipeline.reporter

Usage (from dashboard):
    from src.pipeline.reporter import generate_html_report
    html = generate_html_report(rows, runs, history, mitre, alerts)
"""

from __future__ import annotations

import base64
import datetime as dt
import io
import statistics
from typing import List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches


# ── Colour constants (match dashboard palette) ────────────────────────────────
_BG        = "#0d0d1a"
_CARD_BG   = "#1a0a3d"
_BORDER    = "#4a1d96"
_ACCENT    = "#a855f7"
_ACCENT2   = "#7c3aed"
_TEXT      = "#e8e0ff"
_MUTED     = "#9f7aea"
_CHART_BG  = "#130d2e"

_PRIORITY_COLORS = {
    "Critical": "#fda4af",
    "High":     "#fdba74",
    "Medium":   "#fde68a",
    "Low":      "#86efac",
}
_PRIORITY_BG = {
    "Critical": "#4c0519",
    "High":     "#431407",
    "Medium":   "#3b2509",
    "Low":      "#052e16",
}
_SEVERITY_ALERT = {
    "critical": "#fda4af",
    "high":     "#fdba74",
    "warning":  "#fde68a",
    "info":     "#93c5fd",
}


# ── Chart helpers ─────────────────────────────────────────────────────────────

def _fig_to_b64(fig) -> str:
    """Encode a matplotlib figure as a base64 PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode("utf-8")
    plt.close(fig)
    return encoded


def _chart_priority_distribution(rows: list) -> str:
    """Horizontal bar chart of predicted_priority distribution."""
    counts = {}
    for r in rows:
        p = r.get("predicted_priority") or "Unknown"
        counts[p] = counts.get(p, 0) + 1

    order  = ["Critical", "High", "Medium", "Low"]
    labels = [l for l in order if l in counts]
    values = [counts[l] for l in labels]
    colors = [_PRIORITY_COLORS.get(l, _ACCENT) for l in labels]

    fig, ax = plt.subplots(figsize=(7, 2.8))
    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_CHART_BG)
    bars = ax.barh(labels, values, color=colors, edgecolor=_BORDER, linewidth=0.7)
    ax.set_xlabel("Number of Threats", color=_MUTED, fontsize=9)
    ax.set_title("Priority Distribution", color=_ACCENT, fontsize=11, fontweight="bold")
    ax.tick_params(colors=_TEXT, labelsize=9)
    ax.spines[:].set_color(_BORDER)
    for bar, val in zip(bars, values):
        ax.text(val + 0.3, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", color=_TEXT, fontsize=9, fontweight="bold")
    plt.tight_layout(pad=0.4)
    return _fig_to_b64(fig)


def _chart_source_breakdown(rows: list) -> str:
    """Pie chart of threat source distribution."""
    counts = {}
    for r in rows:
        s = r.get("source") or "unknown"
        counts[s] = counts.get(s, 0) + 1

    labels = list(counts.keys())
    values = [counts[l] for l in labels]
    palette = ["#7c3aed", "#a855f7", "#c084fc", "#ddd6fe", "#4c1d96"]
    colors  = [palette[i % len(palette)] for i in range(len(labels))]

    fig, ax = plt.subplots(figsize=(5, 3.2))
    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_BG)
    wedges, texts, autotexts = ax.pie(
        values, labels=labels, colors=colors, autopct="%1.0f%%",
        startangle=90, counterclock=False,
        wedgeprops={"edgecolor": _BG, "linewidth": 2},
        textprops={"color": _TEXT, "fontsize": 9},
    )
    for at in autotexts:
        at.set_color(_BG)
        at.set_fontweight("bold")
    ax.set_title("Source Breakdown", color=_ACCENT, fontsize=11, fontweight="bold")
    plt.tight_layout(pad=0.4)
    return _fig_to_b64(fig)


def _chart_run_history(runs: list) -> str | None:
    """Bar chart of new + changed threats per run."""
    if not runs or len(runs) < 2:
        return None
    plot_runs = sorted(runs, key=lambda r: r.get("run_id", 0))[-20:]
    x_labels  = [f"Run {r['run_id']}" for r in plot_runs]
    new_vals  = [int(r.get("new_threats",     0) or 0) for r in plot_runs]
    chg_vals  = [int(r.get("updated_threats", 0) or 0) for r in plot_runs]

    fig, ax = plt.subplots(figsize=(max(6, len(x_labels) * 0.9), 3.2))
    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_CHART_BG)
    x   = range(len(x_labels))
    w   = 0.38
    ax.bar([i - w/2 for i in x], new_vals,  width=w, color=_ACCENT2,
           label="New",            edgecolor=_BORDER, linewidth=0.6)
    ax.bar([i + w/2 for i in x], chg_vals, width=w, color="#f97316",
           label="Priority changed", edgecolor=_BORDER, linewidth=0.6)
    ax.set_xticks(list(x))
    ax.set_xticklabels(x_labels, rotation=30, ha="right", fontsize=8, color=_TEXT)
    ax.set_ylabel("Threats", color=_MUTED, fontsize=9)
    ax.set_title("New & Changed Threats per Run", color=_ACCENT,
                 fontsize=11, fontweight="bold")
    ax.tick_params(colors=_TEXT, labelsize=8)
    ax.spines[:].set_color(_BORDER)
    ax.legend(facecolor=_CARD_BG, edgecolor=_BORDER,
              labelcolor=_TEXT, fontsize=8)
    plt.tight_layout(pad=0.4)
    return _fig_to_b64(fig)


def _chart_tactic_coverage(mitre: list) -> str | None:
    """Horizontal bar chart of MITRE tactic coverage."""
    if not mitre:
        return None
    counts: dict[str, int] = {}
    for m in mitre:
        t = m.get("tactic", "Unknown")
        counts[t] = counts.get(t, 0) + 1

    sorted_items = sorted(counts.items(), key=lambda x: x[1])
    labels = [i[0] for i in sorted_items]
    values = [i[1] for i in sorted_items]

    palette = [
        "#7c3aed", "#9333ea", "#a855f7", "#c084fc", "#6d28d9",
        "#8b5cf6", "#4c1d96", "#ddd6fe", "#ede9fe", "#5b21b6",
        "#7e22ce", "#6b21a8", "#581c87",
    ]
    colors = [palette[i % len(palette)] for i in range(len(labels))]

    fig, ax = plt.subplots(figsize=(8, max(3, len(labels) * 0.5)))
    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_CHART_BG)
    bars = ax.barh(labels, values, color=colors, edgecolor=_BORDER, linewidth=0.6)
    ax.set_xlabel("Number of Mappings", color=_MUTED, fontsize=9)
    ax.set_title("MITRE ATT&CK Tactic Coverage", color=_ACCENT,
                 fontsize=11, fontweight="bold")
    ax.tick_params(colors=_TEXT, labelsize=8)
    ax.spines[:].set_color(_BORDER)
    for bar, val in zip(bars, values):
        ax.text(val + 0.3, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", color=_TEXT, fontsize=8)
    plt.tight_layout(pad=0.4)
    return _fig_to_b64(fig)


# ── HTML building blocks ──────────────────────────────────────────────────────

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Inter', Arial, sans-serif;
    background: #0d0d1a;
    color: #e8e0ff;
    font-size: 14px;
    line-height: 1.6;
}
a { color: #a855f7; text-decoration: none; }
a:hover { text-decoration: underline; }

/* Layout */
.page { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }

/* Header */
.report-header {
    background: linear-gradient(135deg, #1e0a4a, #2d1066);
    border: 1px solid #4a1d96;
    border-radius: 16px;
    padding: 28px 32px;
    margin-bottom: 32px;
}
.report-header h1 {
    font-size: 2rem; font-weight: 800;
    background: linear-gradient(90deg, #a855f7, #7c3aed, #c084fc);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    margin-bottom: 6px;
}
.report-header .meta {
    color: #9f7aea; font-size: 0.85rem;
}

/* Section */
.section {
    background: #1a0a3d;
    border: 1px solid #4a1d96;
    border-radius: 12px;
    padding: 24px 28px;
    margin-bottom: 24px;
}
.section h2 {
    font-size: 1.15rem; font-weight: 700;
    color: #c084fc;
    border-bottom: 1px solid #4a1d96;
    padding-bottom: 10px; margin-bottom: 16px;
}
.section h3 {
    font-size: 0.95rem; font-weight: 700;
    color: #a855f7; margin: 16px 0 8px;
}

/* Metric grid */
.metric-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 14px;
    margin-bottom: 16px;
}
.metric-card {
    background: linear-gradient(135deg, #1e0a4a, #2d1066);
    border: 1px solid #6d28d9;
    border-radius: 10px;
    padding: 14px 16px;
    text-align: center;
}
.metric-card .label {
    color: #a78bfa; font-size: 0.72rem;
    font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.8px; margin-bottom: 4px;
}
.metric-card .value {
    color: #f5f0ff; font-size: 1.6rem; font-weight: 800;
}

/* Priority badge */
.badge {
    display: inline-block;
    padding: 2px 10px; border-radius: 20px;
    font-size: 0.72rem; font-weight: 700;
    letter-spacing: 0.4px;
}
.badge-Critical { background: #4c0519; color: #fda4af; border: 1px solid #9f1239; }
.badge-High     { background: #431407; color: #fdba74; border: 1px solid #9a3412; }
.badge-Medium   { background: #3b2509; color: #fde68a; border: 1px solid #92400e; }
.badge-Low      { background: #052e16; color: #86efac; border: 1px solid #166534; }

/* Alert severity badge */
.badge-sev-critical { background: #4c0519; color: #fda4af; border: 1px solid #9f1239; }
.badge-sev-high     { background: #431407; color: #fdba74; border: 1px solid #9a3412; }
.badge-sev-warning  { background: #3b2509; color: #fde68a; border: 1px solid #92400e; }
.badge-sev-info     { background: #0c1a4a; color: #93c5fd; border: 1px solid #1d4ed8; }

/* Table */
table {
    width: 100%; border-collapse: collapse;
    font-size: 0.85rem; margin-top: 8px;
}
thead tr { background: #3b0764; }
thead th {
    color: #e9d5ff; font-weight: 700; font-size: 0.75rem;
    text-transform: uppercase; letter-spacing: 0.6px;
    padding: 10px 14px; text-align: left;
    border-bottom: 2px solid #7c3aed;
}
tbody tr { border-bottom: 1px solid #2d1a4e; }
tbody tr:hover { background: #1e0a4a; }
tbody td { color: #ddd6fe; padding: 9px 14px; vertical-align: top; }
tbody td.mono { font-family: monospace; font-size: 0.8rem; color: #a78bfa; }

/* Chart container */
.chart-wrap {
    background: #0d0d1a;
    border: 1px solid #4a1d96;
    border-radius: 10px;
    padding: 12px;
    margin: 14px 0;
    text-align: center;
}
.chart-wrap img { max-width: 100%; border-radius: 6px; }

/* Change pills */
.pill-escalated { background: #4c0519; color: #fda4af; padding: 2px 8px;
                  border-radius: 10px; font-size: 0.72rem; font-weight: 700; }
.pill-reduced   { background: #0c1a4a; color: #93c5fd; padding: 2px 8px;
                  border-radius: 10px; font-size: 0.72rem; font-weight: 700; }
.pill-new       { background: #052e16; color: #86efac; padding: 2px 8px;
                  border-radius: 10px; font-size: 0.72rem; font-weight: 700; }

/* Footer */
.report-footer {
    margin-top: 40px;
    padding-top: 16px;
    border-top: 1px solid #4a1d96;
    color: #5b21b6;
    font-size: 0.78rem;
    text-align: center;
}
</style>
"""


def _metric(label: str, value) -> str:
    return (
        f"<div class='metric-card'>"
        f"<div class='label'>{label}</div>"
        f"<div class='value'>{value}</div>"
        f"</div>"
    )


def _badge(priority: str) -> str:
    cls = f"badge-{priority}" if priority in _PRIORITY_COLORS else "badge-Low"
    return f"<span class='badge {cls}'>{priority}</span>"


def _sev_badge(severity: str) -> str:
    cls = f"badge-sev-{severity.lower()}"
    return f"<span class='badge {cls}'>{severity.upper()}</span>"


def _esc(text: str) -> str:
    """Minimal HTML escaping for untrusted text."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ── Section builders ──────────────────────────────────────────────────────────

def _section_executive_summary(rows: list, runs: list, history: list,
                                alerts: list, run_filter_ids: set | None) -> str:
    total = len(rows)
    n_crit = sum(1 for r in rows if r.get("predicted_priority") == "Critical")
    n_high = sum(1 for r in rows if r.get("predicted_priority") == "High")
    n_med  = sum(1 for r in rows if r.get("predicted_priority") == "Medium")
    n_low  = sum(1 for r in rows if r.get("predicted_priority") == "Low")
    n_cve  = sum(1 for r in rows if r.get("threat_type") == "cve")
    n_ip   = sum(1 for r in rows if r.get("threat_type") == "malicious_ip")
    n_exp  = sum(1 for r in rows if bool(int(r.get("exploited_flag") or 0)))

    # New threats in scope (from history 'new' entries for filtered runs)
    if run_filter_ids:
        new_this_scope = sum(
            1 for h in history
            if h.get("change_type") == "new" and h.get("run_id") in run_filter_ids
        )
    else:
        new_this_scope = sum(1 for h in history if h.get("change_type") == "new")

    n_unack_alerts = sum(1 for a in alerts if a.get("status") == "new")

    metrics_html = (
        "<div class='metric-grid'>"
        + _metric("Total Threats",   f"{total:,}")
        + _metric("Critical",        f"{n_crit:,}")
        + _metric("High",            f"{n_high:,}")
        + _metric("Medium",          f"{n_med:,}")
        + _metric("Low",             f"{n_low:,}")
        + _metric("CVEs",            f"{n_cve:,}")
        + _metric("Malicious IPs",   f"{n_ip:,}")
        + _metric("With Exploit",    f"{n_exp:,}")
        + _metric("New (in scope)",  f"{new_this_scope:,}")
        + _metric("Open Alerts",     f"{n_unack_alerts:,}")
        + "</div>"
    )

    narrative = (
        f"<p style='color:#c4b5fd;font-size:0.9rem;line-height:1.7;'>"
        f"This report covers <b>{total:,}</b> threat intelligence records across "
        f"<b>{n_cve:,}</b> CVE vulnerabilities and <b>{n_ip:,}</b> malicious IP addresses. "
        f"Of these, <b style='color:#fda4af;'>{n_crit:,} are Critical</b> and "
        f"<b style='color:#fdba74;'>{n_high:,} are High</b> priority. "
        f"<b>{n_exp:,}</b> threat(s) carry active exploitation evidence. "
        f"<b>{n_unack_alerts:,}</b> alert(s) remain unacknowledged and require analyst attention."
        f"</p>"
    )

    return (
        "<div class='section'>"
        "<h2>📋 Executive Summary</h2>"
        + metrics_html
        + narrative
        + "</div>"
    )


def _section_priority_distribution(rows: list) -> str:
    chart_b64 = _chart_priority_distribution(rows)
    src_b64   = _chart_source_breakdown(rows)

    counts = {}
    for r in rows:
        p = r.get("predicted_priority") or "Unknown"
        counts[p] = counts.get(p, 0) + 1
    total = len(rows) or 1

    table_rows = ""
    for p in ["Critical", "High", "Medium", "Low"]:
        n = counts.get(p, 0)
        pct = n / total * 100
        table_rows += (
            f"<tr>"
            f"<td>{_badge(p)}</td>"
            f"<td style='text-align:right;'>{n:,}</td>"
            f"<td style='text-align:right;'>{pct:.1f}%</td>"
            f"</tr>"
        )

    table_html = (
        "<table>"
        "<thead><tr><th>Priority</th><th style='text-align:right;'>Count</th>"
        "<th style='text-align:right;'>Share</th></tr></thead>"
        f"<tbody>{table_rows}</tbody></table>"
    )

    charts_html = (
        "<div style='display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:12px;'>"
        f"<div class='chart-wrap'><img src='data:image/png;base64,{chart_b64}' alt='Priority distribution'/></div>"
        f"<div class='chart-wrap'><img src='data:image/png;base64,{src_b64}'   alt='Source breakdown'/></div>"
        "</div>"
    )

    return (
        "<div class='section'>"
        "<h2>📊 Priority Distribution</h2>"
        + table_html
        + charts_html
        + "</div>"
    )


def _section_top_threats(rows: list, n: int = 10) -> str:
    RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    sorted_rows = sorted(
        rows,
        key=lambda r: (
            RANK.get(r.get("predicted_priority") or "Low", 0),
            float(r.get("predicted_priority_score") or 0),
        ),
        reverse=True,
    )[:n]

    table_rows = ""
    for i, r in enumerate(sorted_rows, 1):
        title    = _esc(r.get("title") or r["id"])[:80]
        tid      = _esc(r["id"])
        sev      = r.get("severity_raw", "—")
        sev_str  = f"{float(sev):.1f}" if sev not in ("—", None, "") else "—"
        score    = r.get("predicted_priority_score")
        score_str= f"{float(score):.3f}" if score is not None else "—"
        priority = r.get("predicted_priority") or "—"
        source   = _esc(r.get("source") or "—")
        exploited= bool(int(r.get("exploited_flag") or 0))
        exp_html = (
            "<span style='color:#fda4af;font-weight:700;'>YES</span>"
            if exploited else
            "<span style='color:#6b7280;'>No</span>"
        )
        table_rows += (
            f"<tr>"
            f"<td style='color:#7c5cbf;font-weight:600;'>#{i}</td>"
            f"<td class='mono'>{tid[:50]}</td>"
            f"<td>{title}</td>"
            f"<td style='text-align:right;'>{sev_str}</td>"
            f"<td>{_badge(priority)}</td>"
            f"<td style='text-align:right;'>{score_str}</td>"
            f"<td>{source}</td>"
            f"<td style='text-align:center;'>{exp_html}</td>"
            f"</tr>"
        )

    return (
        "<div class='section'>"
        f"<h2>🏆 Top {n} Threats by Priority Score</h2>"
        "<table>"
        "<thead><tr>"
        "<th>#</th><th>ID</th><th>Title</th>"
        "<th style='text-align:right;'>Sev</th>"
        "<th>Priority</th><th style='text-align:right;'>Score</th>"
        "<th>Source</th><th style='text-align:center;'>Exploited</th>"
        "</tr></thead>"
        f"<tbody>{table_rows}</tbody>"
        "</table>"
        "</div>"
    )


def _section_priority_changes(history: list, rows: list,
                               run_filter_ids: set | None) -> str:
    if run_filter_ids:
        hist = [h for h in history if h.get("run_id") in run_filter_ids]
    else:
        hist = history

    escalated = [h for h in hist if h.get("change_type") == "escalated"]
    reduced   = [h for h in hist if h.get("change_type") == "reduced"]

    # Build title lookup
    title_map = {r["id"]: r.get("title") or r["id"] for r in rows}

    def _change_rows(entries: list, pill_cls: str, arrow: str) -> str:
        if not entries:
            return "<tr><td colspan='5' style='color:#5b21b6;font-style:italic;'>None in scope</td></tr>"
        out = ""
        for e in entries[:20]:
            tid   = _esc(e.get("threat_id", ""))
            title = _esc(title_map.get(e.get("threat_id", ""), tid))[:60]
            prev  = _esc(e.get("previous_priority") or "—")
            new   = _esc(e.get("new_priority") or "—")
            run   = e.get("run_id", "")
            out += (
                f"<tr>"
                f"<td class='mono'>{tid[:50]}</td>"
                f"<td>{title}</td>"
                f"<td>{_badge(prev)}</td>"
                f"<td style='text-align:center;'>{arrow}</td>"
                f"<td>{_badge(new)}</td>"
                f"<td style='color:#7c5cbf;'>Run #{run}</td>"
                f"</tr>"
            )
        return out

    esc_html = (
        f"<h3>⬆ Escalated ({len(escalated)})</h3>"
        "<table><thead><tr>"
        "<th>ID</th><th>Title</th><th>Previous</th><th></th><th>New</th><th>Run</th>"
        "</tr></thead><tbody>"
        + _change_rows(escalated, "pill-escalated", "→")
        + "</tbody></table>"
    )

    red_html = (
        f"<h3>⬇ Reduced ({len(reduced)})</h3>"
        "<table><thead><tr>"
        "<th>ID</th><th>Title</th><th>Previous</th><th></th><th>New</th><th>Run</th>"
        "</tr></thead><tbody>"
        + _change_rows(reduced, "pill-reduced", "→")
        + "</tbody></table>"
    )

    return (
        "<div class='section'>"
        "<h2>🔄 Priority Changes</h2>"
        "<p style='color:#9f7aea;font-size:0.85rem;margin-bottom:12px;'>"
        "Priority escalations and reductions recorded across pipeline runs in scope.</p>"
        + esc_html + red_html
        + "</div>"
    )


def _section_cluster_summary(rows: list) -> str:
    clusters: dict[int, list] = {}
    for r in rows:
        cid = r.get("cluster_id")
        if cid is None:
            continue
        try:
            cid = int(cid)
        except (ValueError, TypeError):
            continue
        clusters.setdefault(cid, []).append(r)

    if not clusters:
        return (
            "<div class='section'><h2>🔗 Cluster Summary</h2>"
            "<p style='color:#5b21b6;'>No cluster data available.</p></div>"
        )

    table_rows = ""
    for cid in sorted(clusters.keys()):
        members  = clusters[cid]
        n        = len(members)
        avg_sev  = statistics.mean(float(r.get("severity_raw") or 0) for r in members)
        n_crit   = sum(1 for r in members if r.get("predicted_priority") == "Critical")
        n_high   = sum(1 for r in members if r.get("predicted_priority") == "High")
        pct_exp  = sum(1 for r in members if bool(int(r.get("exploited_flag") or 0))) / n * 100
        dominant = (
            max(set(r.get("predicted_priority") or "Low" for r in members),
                key=lambda p: {"Critical":4,"High":3,"Medium":2,"Low":1}.get(p,0))
        )
        notable  = "⚠ YES" if (avg_sev >= 7.0 or pct_exp >= 20.0 or n_crit >= 3) else "No"
        table_rows += (
            f"<tr>"
            f"<td style='font-weight:700;color:#c084fc;'>Cluster {cid}</td>"
            f"<td style='text-align:right;'>{n:,}</td>"
            f"<td style='text-align:right;'>{avg_sev:.1f}</td>"
            f"<td>{_badge(dominant)}</td>"
            f"<td style='text-align:right;'>{pct_exp:.0f}%</td>"
            f"<td style='text-align:right;'>{n_crit}</td>"
            f"<td style='text-align:right;'>{n_high}</td>"
            f"<td style='color:#fda4af;font-weight:600;'>{notable}</td>"
            f"</tr>"
        )

    return (
        "<div class='section'>"
        "<h2>🔗 Cluster Summary</h2>"
        "<table><thead><tr>"
        "<th>Cluster</th><th style='text-align:right;'>Size</th>"
        "<th style='text-align:right;'>Avg Sev</th><th>Dominant</th>"
        "<th style='text-align:right;'>% Exploited</th>"
        "<th style='text-align:right;'>Critical</th>"
        "<th style='text-align:right;'>High</th>"
        "<th>Notable</th>"
        "</tr></thead>"
        f"<tbody>{table_rows}</tbody></table>"
        "</div>"
    )


def _section_mitre_coverage(mitre: list) -> str:
    if not mitre:
        return (
            "<div class='section'><h2>🧩 MITRE ATT&CK Coverage</h2>"
            "<p style='color:#5b21b6;'>No MITRE mapping data available.</p></div>"
        )

    tactic_counts: dict[str, int] = {}
    tech_counts:   dict[str, dict] = {}
    for m in mitre:
        t  = m.get("tactic", "Unknown")
        ti = m.get("technique_id", "")
        tn = m.get("technique_name", "")
        tactic_counts[t] = tactic_counts.get(t, 0) + 1
        if ti not in tech_counts:
            tech_counts[ti] = {"name": tn, "tactic": t, "count": 0}
        tech_counts[ti]["count"] += 1

    top_tactics = sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    top_techs   = sorted(tech_counts.items(), key=lambda x: x[1]["count"], reverse=True)[:10]

    tactic_rows = "".join(
        f"<tr><td>{_esc(t)}</td><td style='text-align:right;'>{c:,}</td></tr>"
        for t, c in top_tactics
    )
    tech_rows = "".join(
        f"<tr>"
        f"<td class='mono'>{_esc(tid)}</td>"
        f"<td>{_esc(d['name'])}</td>"
        f"<td>{_esc(d['tactic'])}</td>"
        f"<td style='text-align:right;'>{d['count']:,}</td>"
        f"</tr>"
        for tid, d in top_techs
    )

    chart_b64 = _chart_tactic_coverage(mitre)
    chart_html = (
        f"<div class='chart-wrap'><img src='data:image/png;base64,{chart_b64}' "
        f"alt='Tactic coverage'/></div>"
        if chart_b64 else ""
    )

    return (
        "<div class='section'>"
        "<h2>🧩 MITRE ATT&CK Coverage</h2>"
        + chart_html
        + "<div style='display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:8px;'>"
        "<div>"
        "<h3>Top Tactics</h3>"
        "<table><thead><tr><th>Tactic</th><th style='text-align:right;'>Mappings</th></tr></thead>"
        f"<tbody>{tactic_rows}</tbody></table>"
        "</div>"
        "<div>"
        "<h3>Top 10 Techniques</h3>"
        "<table><thead><tr><th>ID</th><th>Name</th><th>Tactic</th>"
        "<th style='text-align:right;'>Count</th></tr></thead>"
        f"<tbody>{tech_rows}</tbody></table>"
        "</div>"
        "</div>"
        "</div>"
    )


def _section_alerts_summary(alerts: list) -> str:
    if not alerts:
        return (
            "<div class='section'><h2>🚨 Alerts Summary</h2>"
            "<p style='color:#5b21b6;'>No alerts recorded.</p></div>"
        )

    counts_by_sev  = {}
    counts_by_type = {}
    for a in alerts:
        s = a.get("severity", "info")
        t = a.get("alert_type", "unknown")
        counts_by_sev[s]  = counts_by_sev.get(s, 0)  + 1
        counts_by_type[t] = counts_by_type.get(t, 0) + 1

    n_new = sum(1 for a in alerts if a.get("status") == "new")
    n_ack = sum(1 for a in alerts if a.get("status") == "acknowledged")
    n_dis = sum(1 for a in alerts if a.get("status") == "dismissed")

    sev_rows = "".join(
        f"<tr><td>{_sev_badge(s)}</td><td style='text-align:right;'>{c:,}</td></tr>"
        for s, c in sorted(counts_by_sev.items(),
                            key=lambda x: ["critical","high","warning","info"].index(x[0])
                            if x[0] in ["critical","high","warning","info"] else 99)
    )
    type_rows = "".join(
        f"<tr><td>{_esc(t.replace('_',' ').title())}</td>"
        f"<td style='text-align:right;'>{c:,}</td></tr>"
        for t, c in sorted(counts_by_type.items(), key=lambda x: x[1], reverse=True)
    )

    # Latest 10 open alerts
    open_alerts = [a for a in alerts if a.get("status") == "new"][:10]
    alert_rows = ""
    for a in open_alerts:
        sev  = a.get("severity", "info")
        msg  = _esc(a.get("message", "")[:120])
        run  = a.get("run_id", "—")
        ts   = str(a.get("created_at", ""))[:19].replace("T", " ")
        alert_rows += (
            f"<tr>"
            f"<td>{_sev_badge(sev)}</td>"
            f"<td>{_esc(a.get('alert_type','').replace('_',' ').title())}</td>"
            f"<td>{msg}</td>"
            f"<td style='color:#7c5cbf;'>Run #{run}</td>"
            f"<td style='color:#7c5cbf;'>{ts}</td>"
            f"</tr>"
        )

    return (
        "<div class='section'>"
        "<h2>🚨 Alerts Summary</h2>"
        "<div style='display:grid;grid-template-columns:repeat(3,auto);gap:14px;"
        "margin-bottom:16px;'>"
        + _metric("Unacknowledged", n_new)
        + _metric("Acknowledged",   n_ack)
        + _metric("Dismissed",      n_dis)
        + "</div>"
        "<div style='display:grid;grid-template-columns:1fr 1fr;gap:20px;'>"
        "<div>"
        "<h3>By Severity</h3>"
        "<table><thead><tr><th>Severity</th><th style='text-align:right;'>Count</th></tr></thead>"
        f"<tbody>{sev_rows}</tbody></table>"
        "</div>"
        "<div>"
        "<h3>By Alert Type</h3>"
        "<table><thead><tr><th>Type</th><th style='text-align:right;'>Count</th></tr></thead>"
        f"<tbody>{type_rows}</tbody></table>"
        "</div>"
        "</div>"
        + (
            "<h3>Open Alerts (latest 10)</h3>"
            "<table><thead><tr><th>Sev</th><th>Type</th><th>Message</th>"
            "<th>Run</th><th>Timestamp</th></tr></thead>"
            f"<tbody>{alert_rows}</tbody></table>"
            if open_alerts else ""
        )
        + "</div>"
    )


def _section_run_history(runs: list) -> str:
    if not runs:
        return (
            "<div class='section'><h2>📡 Pipeline Run History</h2>"
            "<p style='color:#5b21b6;'>No pipeline runs recorded.</p></div>"
        )

    chart_b64  = _chart_run_history(runs)
    chart_html = (
        f"<div class='chart-wrap'><img src='data:image/png;base64,{chart_b64}' "
        f"alt='Run history'/></div>"
        if chart_b64 else ""
    )

    table_rows = ""
    for r in sorted(runs, key=lambda x: x.get("run_id", 0), reverse=True)[:20]:
        ts = str(r.get("run_at", ""))[:19].replace("T", " ")
        table_rows += (
            f"<tr>"
            f"<td style='color:#c084fc;font-weight:700;'>#{r.get('run_id','')}</td>"
            f"<td>{ts}</td>"
            f"<td>{_esc(r.get('mode',''))}</td>"
            f"<td style='text-align:right;'>{r.get('total_threats',''):,}</td>"
            f"<td style='text-align:right;color:#86efac;'>{r.get('new_threats','')}</td>"
            f"<td style='text-align:right;color:#fda4af;'>{r.get('updated_threats','')}</td>"
            f"<td style='text-align:right;'>{r.get('n_critical','')}</td>"
            f"<td style='text-align:right;'>{r.get('n_high','')}</td>"
            f"<td style='text-align:right;color:#9f7aea;'>"
            f"{float(r.get('duration_secs') or 0):.1f}s</td>"
            f"</tr>"
        )

    return (
        "<div class='section'>"
        "<h2>📡 Pipeline Run History</h2>"
        + chart_html
        + "<table><thead><tr>"
        "<th>Run</th><th>Timestamp</th><th>Mode</th>"
        "<th style='text-align:right;'>Total</th>"
        "<th style='text-align:right;'>New</th>"
        "<th style='text-align:right;'>Changed</th>"
        "<th style='text-align:right;'>Critical</th>"
        "<th style='text-align:right;'>High</th>"
        "<th style='text-align:right;'>Duration</th>"
        "</tr></thead>"
        f"<tbody>{table_rows}</tbody></table>"
        "</div>"
    )


def _section_full_threat_table(rows: list) -> str:
    RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    sorted_rows = sorted(
        rows,
        key=lambda r: (
            RANK.get(r.get("predicted_priority") or "Low", 0),
            float(r.get("predicted_priority_score") or 0),
        ),
        reverse=True,
    )

    table_rows = ""
    for i, r in enumerate(sorted_rows, 1):
        title    = _esc(r.get("title") or r["id"])[:70]
        tid      = _esc(r["id"])[:50]
        sev      = r.get("severity_raw", "")
        sev_str  = f"{float(sev):.1f}" if sev not in ("", None) else "—"
        priority = r.get("predicted_priority") or "—"
        source   = _esc(r.get("source") or "—")
        last_seen= str(r.get("last_seen") or "")[:10]
        exploited= bool(int(r.get("exploited_flag") or 0))
        exp_html = (
            "<span style='color:#fda4af;'>✓</span>"
            if exploited else
            "<span style='color:#374151;'>—</span>"
        )
        table_rows += (
            f"<tr>"
            f"<td style='color:#5b21b6;font-size:0.78rem;'>{i}</td>"
            f"<td class='mono'>{tid}</td>"
            f"<td>{title}</td>"
            f"<td style='text-align:right;'>{sev_str}</td>"
            f"<td>{_badge(priority)}</td>"
            f"<td>{source}</td>"
            f"<td>{last_seen}</td>"
            f"<td style='text-align:center;'>{exp_html}</td>"
            f"</tr>"
        )

    return (
        "<div class='section'>"
        f"<h2>📎 Appendix — Full Threat Table ({len(rows):,} records)</h2>"
        "<p style='color:#9f7aea;font-size:0.83rem;margin-bottom:10px;'>"
        "All threats ordered by ML priority score (highest first).</p>"
        "<table><thead><tr>"
        "<th>#</th><th>ID</th><th>Title</th>"
        "<th style='text-align:right;'>Sev</th>"
        "<th>Priority</th><th>Source</th>"
        "<th>Last Seen</th><th style='text-align:center;'>Exploited</th>"
        "</tr></thead>"
        f"<tbody>{table_rows}</tbody></table>"
        "</div>"
    )


# ── Public API ────────────────────────────────────────────────────────────────

def generate_html_report(
    rows:    list,
    runs:    list,
    history: list,
    mitre:   list,
    alerts:  list,
    run_filter_ids: set | None = None,
    generated_at:   str | None = None,
) -> str:
    """
    Generate a self-contained HTML threat intelligence report.

    Parameters
    ----------
    rows            : all threat dicts from db.fetch_all_as_dicts()
    runs            : pipeline run dicts from db.fetch_pipeline_runs()
    history         : threat history dicts from db.fetch_threat_history()
    mitre           : all MITRE mapping dicts from db.fetch_all_mitre_mappings()
    alerts          : all alert dicts from db.fetch_alerts()
    run_filter_ids  : if set, limit 'changes' and history sections to these run IDs
    generated_at    : ISO timestamp string; defaults to now (UTC)

    Returns
    -------
    str — complete HTML document (self-contained, no external dependencies
          except the optional Google Fonts import which degrades gracefully)
    """
    if not rows:
        return "<html><body><p>No threat data available.</p></body></html>"

    ts = generated_at or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    n_runs = len(runs)
    latest_run_id = max((r.get("run_id", 0) for r in runs), default="—")

    header_html = (
        "<div class='report-header'>"
        "<h1>🛡️ Threat Intelligence Report</h1>"
        f"<div class='meta'>"
        f"Generated: <b>{ts}</b> &nbsp;|&nbsp; "
        f"Pipeline runs in DB: <b>{n_runs}</b> &nbsp;|&nbsp; "
        f"Latest run: <b>#{latest_run_id}</b>"
        + (f" &nbsp;|&nbsp; Scope: runs {sorted(run_filter_ids)}" if run_filter_ids else "")
        + "</div>"
        "</div>"
    )

    sections = [
        _section_executive_summary(rows, runs, history, alerts, run_filter_ids),
        _section_priority_distribution(rows),
        _section_top_threats(rows, n=10),
        _section_priority_changes(history, rows, run_filter_ids),
        _section_cluster_summary(rows),
        _section_mitre_coverage(mitre),
        _section_alerts_summary(alerts),
        _section_run_history(runs),
        _section_full_threat_table(rows),
    ]

    footer_html = (
        "<div class='report-footer'>"
        "⚠️ Priority labels are derived from a documented heuristic, not analyst-verified ground truth. "
        "MITRE mappings are inferred — not analyst-assigned. "
        "Cluster membership reflects statistical similarity, not confirmed campaign attribution."
        "<br>Generated by the AI-Powered Threat Intelligence Platform — offline, reproducible, no external API calls."
        "</div>"
    )

    return (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
        f"<title>Threat Intelligence Report — {ts}</title>"
        + _CSS
        + "</head><body><div class='page'>"
        + header_html
        + "".join(sections)
        + footer_html
        + "</div></body></html>"
    )


# ── Standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

    from src.pipeline import db
    from src.config import REPORTS_DIR

    print("[reporter] loading data from DB...")
    rows    = db.fetch_all_as_dicts()
    runs    = db.fetch_pipeline_runs(limit=50)
    history = db.fetch_threat_history(limit=1000)
    mitre   = db.fetch_all_mitre_mappings()
    alerts  = db.fetch_alerts(limit=500)

    if not rows:
        print("[reporter] ERROR: no data in DB. Run the pipeline first.")
        sys.exit(1)

    html = generate_html_report(rows, runs, history, mitre, alerts)

    ts_file = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = REPORTS_DIR / f"threat_report_{ts_file}.html"
    out_path.write_text(html, encoding="utf-8")
    print(f"[reporter] report saved to {out_path}  ({len(html):,} bytes)")
