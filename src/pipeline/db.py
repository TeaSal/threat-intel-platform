"""
SQLite storage layer. One table, `threats`, holding normalized records plus
(once computed) predicted priority. This is the single source of truth the
dashboard and the training script both read from.

Phase 3 adds a second table, `mitre_mappings`, which stores inferred MITRE
ATT&CK technique associations. It is kept separate from `threats` so that:
  - The threats table schema stays clean and backward-compatible.
  - One threat can map to multiple techniques (one-to-many relationship).
  - Mappings can be updated independently without touching the threat record.
"""
import sqlite3
import json
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

# Columns added in post-Review-2 phases. Each entry is (column_name, column_def).
# init_db() applies these as safe ALTER TABLE migrations on existing databases so
# we never destroy existing data.
_MIGRATION_COLUMNS = [
    ("cluster_id",  "INTEGER"),
    ("ai_summary",  "TEXT"),      # Phase 2: template-based analyst summary
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
    """Create the threats table if it doesn't exist, then apply any pending column migrations."""
    with get_connection() as conn:
        conn.execute(SCHEMA_SQL)
        conn.execute(MITRE_SCHEMA_SQL)   # Phase 3: MITRE mappings table
        # Safe ALTER TABLE migrations: add columns introduced after Review 2.
        # SQLite does not support IF NOT EXISTS on ALTER TABLE, so we query
        # existing columns and only add the ones that are missing.
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


def fetch_all_as_dicts() -> List[dict]:
    init_db()
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM threats").fetchall()
        return [dict(r) for r in rows]


def count() -> int:
    init_db()
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) as c FROM threats").fetchone()["c"]


if __name__ == "__main__":
    init_db()
    print(f"DB initialized at {DB_PATH}. Current row count: {count()}")
