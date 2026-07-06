import json
import os
import sqlite3
import time
from typing import Optional

DB_PATH = os.getenv("SESSION_DB", "/data/sessions.db")


class SessionStore:
    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                target TEXT,
                phases TEXT,
                current_phase TEXT,
                results TEXT,
                state TEXT,
                created_at REAL,
                updated_at REAL
            )
        """)
        self.conn.commit()

    def save(self, session_id: str, data: dict):
        self.conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, target, phases, current_phase, results, state, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (session_id, data.get("target", ""),
             json.dumps(data.get("phases", [])),
             data.get("current_phase"),
             json.dumps(data.get("results", {})),
             json.dumps(data.get("state", {})),
             time.time())
        )
        self.conn.commit()

    def load(self, session_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if not row:
            return None
        return {
            "session_id": row["session_id"],
            "target": row["target"],
            "phases": json.loads(row["phases"]),
            "current_phase": row["current_phase"],
            "results": json.loads(row["results"]),
            "state": json.loads(row["state"]),
        }

    def list_active(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT session_id, target, current_phase, updated_at FROM sessions \
             WHERE updated_at > ? ORDER BY updated_at DESC",
            (time.time() - 86400,)
        ).fetchall()
        return [dict(r) for r in rows]

    def delete(self, session_id: str):
        self.conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        self.conn.commit()
