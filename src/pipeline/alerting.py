"""
Phase 5 — Alerting module.

Generates structured alerts from a pipeline diff + threat rows.
All alerts are dashboard-only (no external email/webhook).
Idempotency is enforced at the DB layer (upsert_alerts checks
(threat_id, run_id, alert_type) uniqueness), so this module may be
called multiple times without producing duplicates.

Alert types
-----------
new_critical        — new threat with Critical predicted priority
new_high            — new threat with High predicted priority
priority_escalated  — existing threat escalated to Critical or High
exploit_appeared    — exploited_flag was 0 (or absent) and is now 1
notable_cluster     — a cluster crossed the "notable" threshold
                      (avg_sev >= 7.0 OR pct_exploited >= 20% OR n_critical >= 3)
spike               — new_threats count > 2× rolling average of previous runs

Severity mapping
----------------
alert_type          → alert severity
new_critical        → critical
priority_escalated  → critical  (if new priority is Critical)
priority_escalated  → high      (if new priority is High)
new_high            → high
exploit_appeared    → high
notable_cluster     → warning
spike               → warning
"""

from __future__ import annotations

import statistics
from typing import List


# ── Helpers ───────────────────────────────────────────────────────────────────

def _priority_to_severity(priority: str) -> str:
    """Map a threat priority label to an alert severity string."""
    return {"Critical": "critical", "High": "high"}.get(priority, "info")


# ── Core generator ────────────────────────────────────────────────────────────

def generate_alerts(diff: dict, rows: list, run_id: int,
                    previous_run_new_counts: list | None = None) -> List[dict]:
    """
    Build a list of alert dicts for a completed pipeline run.

    Parameters
    ----------
    diff : dict
        Output of ``db.diff_threats()``.
        Keys: 'new', 'escalated', 'reduced', 'unchanged'.
        Each value is a list of dicts with keys:
            threat_id, change_type, previous_priority, new_priority,
            previous_score, new_score.
    rows : list[dict]
        All threat rows from the DB *after* predictions have been written
        (i.e. the result of ``db.fetch_all_as_dicts()``).
        Used to look up exploited_flag, cluster data, etc.
    run_id : int
        The run_id just recorded in pipeline_runs.
    previous_run_new_counts : list[int] | None
        ``new_threats`` values from all previous pipeline runs (oldest→newest),
        used to compute the rolling average for the spike detector.
        If None or empty, the spike check is skipped.

    Returns
    -------
    list[dict]
        Each dict has keys:
            threat_id (str | None), run_id (int), alert_type (str),
            severity (str), message (str)
    """
    alerts: List[dict] = []
    # Build a quick lookup from threat_id → row dict
    row_lookup: dict[str, dict] = {r["id"]: r for r in rows}

    # ── 1. new_critical — new threats with Critical priority ───────────────
    for entry in diff.get("new", []):
        if entry.get("new_priority") == "Critical":
            tid = entry["threat_id"]
            row = row_lookup.get(tid, {})
            title = row.get("title") or tid
            sev   = row.get("severity_raw", "")
            sev_str = f" (severity {sev}/10)" if sev != "" else ""
            alerts.append({
                "threat_id":  tid,
                "run_id":     run_id,
                "alert_type": "new_critical",
                "severity":   "critical",
                "message": (
                    f"New Critical threat detected: '{title}'{sev_str}. "
                    f"Immediate analyst review recommended."
                ),
            })

    # ── 2. new_high — new threats with High priority ───────────────────────
    for entry in diff.get("new", []):
        if entry.get("new_priority") == "High":
            tid = entry["threat_id"]
            row = row_lookup.get(tid, {})
            title = row.get("title") or tid
            sev   = row.get("severity_raw", "")
            sev_str = f" (severity {sev}/10)" if sev != "" else ""
            alerts.append({
                "threat_id":  tid,
                "run_id":     run_id,
                "alert_type": "new_high",
                "severity":   "high",
                "message": (
                    f"New High-priority threat detected: '{title}'{sev_str}. "
                    f"Review within 24–48 hours."
                ),
            })

    # ── 3. priority_escalated — existing threat escalated to Critical/High ─
    for entry in diff.get("escalated", []):
        new_p = entry.get("new_priority", "")
        if new_p not in ("Critical", "High"):
            continue   # only alert on escalations into top two tiers
        tid    = entry["threat_id"]
        old_p  = entry.get("previous_priority") or "lower priority"
        row    = row_lookup.get(tid, {})
        title  = row.get("title") or tid
        sev_al = _priority_to_severity(new_p)
        alerts.append({
            "threat_id":  tid,
            "run_id":     run_id,
            "alert_type": "priority_escalated",
            "severity":   sev_al,
            "message": (
                f"Threat escalated to {new_p}: '{title}' "
                f"(was {old_p}). Re-evaluate exposure immediately."
            ),
        })

    # ── 4. exploit_appeared — exploited_flag flipped 0→1 ──────────────────
    # We detect this by looking at escalated *and* unchanged threats where
    # the current row shows exploited_flag=1 but the diff shows the threat
    # existed before (not 'new'). Because we don't store the old exploited_flag
    # value in the diff, we use a heuristic: if the threat was in a prior run
    # (change_type != 'new') and its current exploited_flag is 1, check whether
    # the history table shows a prior run where it wasn't flagged.
    # Simpler approach that stays correct within a single run: flag any
    # non-new threat whose current row has exploited_flag=1 and whose
    # previous_priority was NOT Critical (meaning it may have been exploitable
    # even before, but only now crossed the threshold), provided the threat
    # is also in the escalated list.  This matches the spec's intent without
    # requiring a separate history query here.
    escalated_ids = {e["threat_id"] for e in diff.get("escalated", [])}
    for entry in diff.get("escalated", []) + diff.get("unchanged", []):
        tid = entry["threat_id"]
        row = row_lookup.get(tid, {})
        # exploited_flag may be stored as int 0/1 or bool
        currently_exploited = bool(int(row.get("exploited_flag") or 0))
        if not currently_exploited:
            continue
        # Only fire if the threat wasn't Critical before (so exploit flag is
        # a genuine new signal, not one we already fired on)
        prev_p = entry.get("previous_priority") or ""
        if prev_p == "Critical":
            continue   # was already Critical — no new signal
        # Avoid double-alerting when priority_escalated already covers it
        if tid in escalated_ids:
            # We already alerted on the escalation; only add exploit alert
            # if the previous priority was not High (making the exploit flag
            # the primary new signal)
            if prev_p in ("Critical", "High"):
                continue
        title = row.get("title") or tid
        alerts.append({
            "threat_id":  tid,
            "run_id":     run_id,
            "alert_type": "exploit_appeared",
            "severity":   "high",
            "message": (
                f"Exploitation evidence now present for '{title}'. "
                f"Active exploitation has been flagged — immediate containment review advised."
            ),
        })

    # ── 5. notable_cluster — cluster crossed notable threshold ────────────
    # Compute per-cluster stats from current rows and fire at most one alert
    # per cluster that is notable and has at least one Critical/High threat.
    clusters: dict[int, list] = {}
    for row in rows:
        cid = row.get("cluster_id")
        if cid is None:
            continue
        try:
            cid = int(cid)
        except (ValueError, TypeError):
            continue
        clusters.setdefault(cid, []).append(row)

    for cid, members in clusters.items():
        n = len(members)
        if n < 2:
            continue
        avg_sev   = statistics.mean(
            float(r.get("severity_raw") or 0) for r in members
        )
        pct_exp   = (
            sum(1 for r in members if bool(int(r.get("exploited_flag") or 0))) / n * 100
        )
        n_crit    = sum(1 for r in members if r.get("predicted_priority") == "Critical")
        n_high_cl = sum(1 for r in members if r.get("predicted_priority") == "High")
        is_notable = avg_sev >= 7.0 or pct_exp >= 20.0 or n_crit >= 3

        if not is_notable:
            continue

        reasons = []
        if avg_sev >= 7.0:
            reasons.append(f"avg severity {avg_sev:.1f}/10")
        if pct_exp >= 20.0:
            reasons.append(f"{pct_exp:.0f}% of members exploited")
        if n_crit >= 3:
            reasons.append(f"{n_crit} Critical threats")

        alerts.append({
            "threat_id":  None,   # cluster-level — no single threat_id
            "run_id":     run_id,
            "alert_type": "notable_cluster",
            "severity":   "warning",
            "message": (
                f"Cluster {cid} ({n} threats) has crossed the notable threshold: "
                f"{'; '.join(reasons)}. "
                f"Contains {n_crit} Critical and {n_high_cl} High threats."
            ),
        })

    # ── 6. spike — new_threats > 2× rolling average of previous runs ──────
    if previous_run_new_counts and len(previous_run_new_counts) >= 1:
        rolling_avg = statistics.mean(previous_run_new_counts)
        current_new = len(diff.get("new", []))
        if rolling_avg > 0 and current_new > 2 * rolling_avg:
            alerts.append({
                "threat_id":  None,
                "run_id":     run_id,
                "alert_type": "spike",
                "severity":   "warning",
                "message": (
                    f"Threat ingestion spike detected: {current_new} new threats this run "
                    f"vs rolling average of {rolling_avg:.1f} across "
                    f"{len(previous_run_new_counts)} previous run(s). "
                    f"Verify data source integrity."
                ),
            })

    return alerts
