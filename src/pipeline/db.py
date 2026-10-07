"""
SQLite storage layer. One table, `threats`, holding normalized records plus
(once computed) predicted priority. This is the single source of truth the
dashboard and the training script both read from.

Phase 3 adds a second table, `mitre_mappings`, which stores inferred MITRE
ATT&CK technique associations. It is kept separate from `threats` so that:
  - The threats table schema stays clean and backward-compatible.
  - One threat can map to multiple techniques (one-to-many relationship).
  - Mappings can be updated independently without touching the threat record.

Phase 4 adds two monitoring tables:
  - `pipeline_runs`  — one row per pipeline execution, records timing and
                       high-level stats (new/updated/unchanged threat counts).
  - `threat_history` — audit log; one row per (threat_id, run_id) whenever a
                       threat's predicted_priority changes between runs.
"""
import sqlite3
import json
import datetime as dt
from typing import List, Optional
from contextlib import contextmanager

from src.config import DB_PATH
from src.schema import NormalizedThreat

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS threats (
    id TEXT PRIMARY KEY,
    threat_type TEXT NOT NULL,
    title TEXT,
    description TEXT,
    severity_raw REAL,
    report_count INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    source TEXT,
    source_reliability REAL,
    exploited_flag INTEGER,
    extra_json TEXT,
    predicted_priority TEXT,
    predicted_priority_score REAL,
    heuristic_label TEXT,
    cluster_id INTEGER,
    ai_summary TEXT
);
"""

# Phase 3: separate table for MITRE ATT&CK mappings (one-to-many with threats).
MITRE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS mitre_mappings (
    rowid    INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id       TEXT NOT NULL,
    tactic          TEXT NOT NULL,
    technique_id    TEXT NOT NULL,
    technique_name  TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    basis           TEXT,
    UNIQUE(threat_id, technique_id)
);
"""

# Phase 4: pipeline run log — one row per execution.
PIPELINE_RUNS_SQL = """
CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at          TEXT NOT NULL,
    mode            TEXT NOT NULL,
    total_threats   INTEGER,
    new_threats     INTEGER,
    updated_threats INTEGER,
    unchanged_threats INTEGER,
    n_critical      INTEGER,
    n_high          INTEGER,
    n_medium        INTEGER,
    n_low           INTEGER,
    duration_secs   REAL,
    notes           TEXT
);
"""

# Phase 4: per-threat priority change audit log.
THREAT_HISTORY_SQL = """
CREATE TABLE IF NOT EXISTS threat_history (
    history_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id       TEXT NOT NULL,
    run_id          INTEGER NOT NULL,
    run_at          TEXT NOT NULL,
    previous_priority TEXT,
    new_priority      TEXT,
    previous_score    REAL,
    new_score         REAL,
    change_type       TEXT NOT NULL
);
"""

# Phase 9: analyst feedback table — one row per threat, stores validated labels.
ANALYST_FEEDBACK_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS analyst_feedback (
    feedback_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id     TEXT    NOT NULL UNIQUE,
    analyst_label TEXT    NOT NULL,
    feedback_notes TEXT,
    analyst_id    TEXT    NOT NULL DEFAULT 'analyst_1',
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);
"""

# Phase 5: alerts table — one row per generated alert, with analyst status tracking.
ALERTS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id   TEXT,
    run_id      INTEGER,
    alert_type  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'new'
);
"""

# Columns added in post-Review-2 phases. Each entry is (column_name, column_def).
# init_db() applies these as safe ALTER TABLE migrations on existing databases so
# we never destroy existing data.
_MIGRATION_COLUMNS = [
    ("cluster_id",              "INTEGER"),
    ("ai_summary",              "TEXT"),      # Phase 2: template-based analyst summary
    ("explanation_json",        "TEXT"),      # Phase 8: ML feature-contribution explanation
    ("context_adjusted_score",  "REAL"),      # Phase 10: org-context boosted score (display only)
]


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create all tables if they don't exist, then apply any pending column migrations."""
    with get_connection() as conn:
        conn.execute(SCHEMA_SQL)
        conn.execute(MITRE_SCHEMA_SQL)       # Phase 3
        conn.execute(PIPELINE_RUNS_SQL)      # Phase 4
        conn.execute(THREAT_HISTORY_SQL)     # Phase 4
        conn.execute(ALERTS_SCHEMA_SQL)              # Phase 5
        conn.execute(ANALYST_FEEDBACK_SCHEMA_SQL)    # Phase 9
        # Safe ALTER TABLE migrations for the threats table.
        existing = {row[1] for row in conn.execute("PRAGMA table_info(threats)").fetchall()}
        for col_name, col_def in _MIGRATION_COLUMNS:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE threats ADD COLUMN {col_name} {col_def}")
                print(f"[db] migration: added column '{col_name} {col_def}' to threats table")


def upsert_threats(threats: List[NormalizedThreat]):
    init_db()
    with get_connection() as conn:
        for t in threats:
            conn.execute(
                """
                INSERT INTO threats (id, threat_type, title, description, severity_raw,
                    report_count, first_seen, last_seen, source, source_reliability,
                    exploited_flag, extra_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title, description=excluded.description,
                    severity_raw=excluded.severity_raw, report_count=excluded.report_count,
                    last_seen=excluded.last_seen, source_reliability=excluded.source_reliability,
                    exploited_flag=excluded.exploited_flag, extra_json=excluded.extra_json
                """,
                (t.id, t.threat_type, t.title, t.description, t.severity_raw, t.report_count,
                 t.first_seen, t.last_seen, t.source, t.source_reliability,
                 int(t.exploited_flag), json.dumps(t.extra)),
            )


def update_heuristic_labels(id_to_label: dict):
    with get_connection() as conn:
        for tid, label in id_to_label.items():
            conn.execute("UPDATE threats SET heuristic_label=? WHERE id=?", (label, tid))


def update_predictions(id_to_prediction: dict):
    """id_to_prediction: {id: (predicted_label, predicted_score)}"""
    with get_connection() as conn:
        for tid, (label, score) in id_to_prediction.items():
            conn.execute(
                "UPDATE threats SET predicted_priority=?, predicted_priority_score=? WHERE id=?",
                (label, float(score), tid),
            )


def update_cluster_ids(id_to_cluster: dict):
    """id_to_cluster: {threat_id: cluster_id (int)}"""
    with get_connection() as conn:
        for tid, cid in id_to_cluster.items():
            conn.execute(
                "UPDATE threats SET cluster_id=? WHERE id=?",
                (int(cid), tid),
            )


def update_summaries(id_to_summary: dict):
    """id_to_summary: {threat_id: summary_text (str)}  — Phase 2"""
    with get_connection() as conn:
        for tid, summary in id_to_summary.items():
            conn.execute(
                "UPDATE threats SET ai_summary=? WHERE id=?",
                (summary, tid),
            )


# ── Phase 3: MITRE ATT&CK mappings ────────────────────────────────────────────

def upsert_mitre_mappings(mappings: list):
    """
    mappings: list of dicts, each with keys:
        threat_id, tactic, technique_id, technique_name, confidence, basis
    Uses INSERT OR REPLACE so re-runs are idempotent on (threat_id, technique_id).
    """
    init_db()
    with get_connection() as conn:
        for m in mappings:
            conn.execute(
                """
                INSERT INTO mitre_mappings
                    (threat_id, tactic, technique_id, technique_name, confidence, basis)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(threat_id, technique_id) DO UPDATE SET
                    tactic=excluded.tactic,
                    technique_name=excluded.technique_name,
                    confidence=excluded.confidence,
                    basis=excluded.basis
                """,
                (
                    m["threat_id"], m["tactic"], m["technique_id"],
                    m["technique_name"], m["confidence"], m.get("basis", ""),
                ),
            )


def fetch_mitre_for_threat(threat_id: str) -> List[dict]:
    """Return all MITRE mappings for a single threat, ordered by confidence."""
    init_db()
    confidence_order = {"High": 0, "Medium": 1, "Low": 2, "Inferred": 3}
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM mitre_mappings WHERE threat_id=?", (threat_id,)
        ).fetchall()
    results = [dict(r) for r in rows]
    results.sort(key=lambda r: confidence_order.get(r.get("confidence", "Inferred"), 99))
    return results


def fetch_all_mitre_mappings() -> List[dict]:
    """Return all rows from mitre_mappings — used for dashboard overview."""
    init_db()
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM mitre_mappings").fetchall()
        return [dict(r) for r in rows]


def count_mitre_mappings() -> int:
    init_db()
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) as c FROM mitre_mappings").fetchone()["c"]


# ── Phase 4: Monitoring / Continuous Ingestion ────────────────────────────────

def snapshot_priorities() -> dict:
    """
    Returns {threat_id: (predicted_priority, predicted_priority_score)}
    for every row currently in the threats table.
    Called BEFORE upsert/predictions so we can diff against the new values.
    """
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, predicted_priority, predicted_priority_score FROM threats"
        ).fetchall()
    return {
        r["id"]: (r["predicted_priority"], r["predicted_priority_score"])
        for r in rows
    }


def diff_threats(before_ids: set, after_ids: set,
                 before_priorities: dict, after_priorities: dict) -> dict:
    """
    Compares two snapshots and categorises every threat as:
      new       — id appeared for the first time in this run
      escalated — priority went up   (e.g. Medium → High)
      reduced   — priority went down (e.g. High → Medium)
      unchanged — in DB before and priority did not change

    Parameters
    ----------
    before_ids        : set of threat IDs present before collection
    after_ids         : set of threat IDs present after collection
    before_priorities : {id: (priority, score)} before predictions
    after_priorities  : {id: (priority, score)} after predictions

    Returns
    -------
    dict with keys: new, escalated, reduced, unchanged
    Each value is a list of dicts with full diff details.
    """
    PRIORITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    result = {"new": [], "escalated": [], "reduced": [], "unchanged": []}

    for tid in after_ids:
        after_p, after_s = after_priorities.get(tid, (None, None))
        if tid not in before_ids:
            result["new"].append({
                "threat_id": tid,
                "change_type": "new",
                "previous_priority": None,
                "new_priority": after_p,
                "previous_score": None,
                "new_score": after_s,
            })
        else:
            before_p, before_s = before_priorities.get(tid, (None, None))
            br = PRIORITY_RANK.get(before_p, 0)
            ar = PRIORITY_RANK.get(after_p, 0)
            if ar > br:
                result["escalated"].append({
                    "threat_id": tid,
                    "change_type": "escalated",
                    "previous_priority": before_p,
                    "new_priority": after_p,
                    "previous_score": before_s,
                    "new_score": after_s,
                })
            elif ar < br:
                result["reduced"].append({
                    "threat_id": tid,
                    "change_type": "reduced",
                    "previous_priority": before_p,
                    "new_priority": after_p,
                    "previous_score": before_s,
                    "new_score": after_s,
                })
            else:
                result["unchanged"].append({
                    "threat_id": tid,
                    "change_type": "unchanged",
                    "previous_priority": before_p,
                    "new_priority": after_p,
                    "previous_score": before_s,
                    "new_score": after_s,
                })

    return result


def record_pipeline_run(
    mode: str,
    total_threats: int,
    new_threats: int,
    updated_threats: int,
    unchanged_threats: int,
    n_critical: int,
    n_high: int,
    n_medium: int,
    n_low: int,
    duration_secs: float,
    notes: str = "",
) -> int:
    """Insert a pipeline_runs row and return the new run_id."""
    init_db()
    run_at = dt.datetime.now(dt.timezone.utc).isoformat()
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO pipeline_runs
                (run_at, mode, total_threats, new_threats, updated_threats,
                 unchanged_threats, n_critical, n_high, n_medium, n_low,
                 duration_secs, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (run_at, mode, total_threats, new_threats, updated_threats,
             unchanged_threats, n_critical, n_high, n_medium, n_low,
             round(duration_secs, 2), notes),
        )
        return cur.lastrowid


def record_threat_history(run_id: int, diff_entries: list):
    """
    Insert rows into threat_history for all changed threats.
    diff_entries: list of dicts from diff_threats() — all change_types.
    """
    init_db()
    run_at = dt.datetime.now(dt.timezone.utc).isoformat()
    with get_connection() as conn:
        for entry in diff_entries:
            if entry["change_type"] == "unchanged":
                continue   # only record actual changes + new threats
            conn.execute(
                """
                INSERT INTO threat_history
                    (threat_id, run_id, run_at, previous_priority, new_priority,
                     previous_score, new_score, change_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry["threat_id"], run_id, run_at,
                    entry.get("previous_priority"),
                    entry.get("new_priority"),
                    entry.get("previous_score"),
                    entry.get("new_score"),
                    entry["change_type"],
                ),
            )


def fetch_pipeline_runs(limit: int = 50) -> List[dict]:
    """Return the most recent pipeline runs, newest first."""
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM pipeline_runs ORDER BY run_id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def fetch_threat_history(limit: int = 500) -> List[dict]:
    """Return recent threat history entries (new + priority changes), newest first."""
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT th.*, t.title, t.threat_type, t.source, t.severity_raw
            FROM threat_history th
            LEFT JOIN threats t ON t.id = th.threat_id
            ORDER BY th.history_id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def fetch_threat_history_for_id(threat_id: str) -> List[dict]:
    """Return all history rows for a specific threat, oldest first."""
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM threat_history WHERE threat_id=? ORDER BY history_id ASC",
            (threat_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def fetch_all_as_dicts() -> List[dict]:
    init_db()
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM threats").fetchall()
        return [dict(r) for r in rows]


def count() -> int:
    init_db()
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) as c FROM threats").fetchone()["c"]


def update_explanations(id_to_explanation: dict):
    """
    id_to_explanation: {threat_id: explanation_dict}  — Phase 8
    Serialises each explanation dict to JSON and stores it in explanation_json column.
    """
    with get_connection() as conn:
        for tid, exp in id_to_explanation.items():
            conn.execute(
                "UPDATE threats SET explanation_json=? WHERE id=?",
                (json.dumps(exp), tid),
            )


# ── Phase 9: Analyst Feedback ─────────────────────────────────────────────────

# Valid analyst label values
ANALYST_LABEL_OPTIONS = [
    "Confirmed_Critical",
    "Confirmed_High",
    "Confirmed_Medium",
    "Confirmed_Low",
    "False_Positive",
    "Needs_Review",
]


def upsert_analyst_feedback(
    threat_id:      str,
    analyst_label:  str,
    notes:          str = "",
    analyst_id:     str = "analyst_1",
) -> None:
    """
    Insert or update analyst feedback for a threat.
    The original heuristic label and ML prediction are NEVER modified here.
    """
    assert analyst_label in ANALYST_LABEL_OPTIONS, (
        f"Invalid analyst_label '{analyst_label}'. "
        f"Must be one of: {ANALYST_LABEL_OPTIONS}"
    )
    init_db()
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    with get_connection() as conn:
        existing = conn.execute(
            "SELECT feedback_id, created_at FROM analyst_feedback WHERE threat_id=?",
            (threat_id,),
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE analyst_feedback
                SET analyst_label=?, feedback_notes=?, analyst_id=?, updated_at=?
                WHERE threat_id=?
                """,
                (analyst_label, notes, analyst_id, now, threat_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO analyst_feedback
                    (threat_id, analyst_label, feedback_notes, analyst_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (threat_id, analyst_label, notes, analyst_id, now, now),
            )


def fetch_analyst_feedback(limit: int = 2000) -> List[dict]:
    """Return all analyst feedback rows, newest updated first."""
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM analyst_feedback ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def fetch_feedback_for_threat(threat_id: str) -> Optional[dict]:
    """Return analyst feedback for a single threat, or None if not submitted."""
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM analyst_feedback WHERE threat_id=?", (threat_id,)
        ).fetchone()
        return dict(row) if row else None


# ── Phase 5: Alerts ───────────────────────────────────────────────────────────

def upsert_alerts(alerts: list):
    """
    Insert alerts that don't already exist for the same (threat_id, run_id, alert_type).
    Idempotent — re-running the pipeline will not create duplicate alerts.

    alerts: list of dicts with keys:
        threat_id, run_id, alert_type, severity, message
    """
    init_db()
    created_at = dt.datetime.now(dt.timezone.utc).isoformat()
    with get_connection() as conn:
        for a in alerts:
            # Only insert if no existing row matches the unique triple
            existing = conn.execute(
                """
                SELECT alert_id FROM alerts
                WHERE threat_id=? AND run_id=? AND alert_type=?
                """,
                (a.get("threat_id"), a.get("run_id"), a["alert_type"]),
            ).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO alerts
                        (threat_id, run_id, alert_type, severity, message, created_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'new')
                    """,
                    (
                        a.get("threat_id"),
                        a.get("run_id"),
                        a["alert_type"],
                        a["severity"],
                        a["message"],
                        created_at,
                    ),
                )


def fetch_alerts(status_filter: Optional[str] = None, limit: int = 200) -> List[dict]:
    """
    Return alerts ordered newest first.
    status_filter: 'new' | 'acknowledged' | 'dismissed' | None (all)
    """
    init_db()
    with get_connection() as conn:
        if status_filter:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE status=? ORDER BY alert_id DESC LIMIT ?",
                (status_filter, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY alert_id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def fetch_unacknowledged_alert_count() -> int:
    """Return the count of alerts with status='new'."""
    init_db()
    with get_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE status='new'"
        ).fetchone()["c"]


def update_alert_status(alert_id: int, status: str):
    """
    Update a single alert's status.
    status must be one of: 'new' | 'acknowledged' | 'dismissed'
    """
    assert status in ("new", "acknowledged", "dismissed"), f"Invalid status: {status}"
    init_db()
    with get_connection() as conn:
        conn.execute(
            "UPDATE alerts SET status=? WHERE alert_id=?", (status, alert_id)
        )


# ── Phase 10: Organisational Context ──────────────────────────────────────────

def update_context_scores(id_to_context: dict):
    """
    id_to_context: {threat_id: adjusted_score_float_or_None}
    Stores the context-adjusted score for display.
    Does NOT touch predicted_priority or predicted_priority_score.
    """
    with get_connection() as conn:
        for tid, score in id_to_context.items():
            conn.execute(
                "UPDATE threats SET context_adjusted_score=? WHERE id=?",
                (float(score) if score is not None else None, tid),
            )


if __name__ == "__main__":
    init_db()
    print(f"DB initialized at {DB_PATH}. Current row count: {count()}")
