"""
SQLite storage layer. One table, `threats`, holding normalized records plus
(once computed) predicted priority. This is the single source of truth the
dashboard and the training script both read from.
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
    heuristic_label TEXT
);
"""


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
    with get_connection() as conn:
        conn.execute(SCHEMA_SQL)


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
