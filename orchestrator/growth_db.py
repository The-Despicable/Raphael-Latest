import json
import os
import sqlite3
import time
import hashlib
from pathlib import Path

DB_PATH = os.getenv("GROWTH_DB_PATH", str(Path(__file__).resolve().parent / "data" / "growth.db"))


class GrowthDB:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS targets (
                    id TEXT PRIMARY KEY,
                    host TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    tags TEXT DEFAULT '',
                    notes TEXT DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'info',
                    description TEXT NOT NULL,
                    evidence TEXT DEFAULT '',
                    payload TEXT DEFAULT '',
                    timestamp REAL NOT NULL,
                    FOREIGN KEY (target_id) REFERENCES targets(id)
                );
                CREATE TABLE IF NOT EXISTS patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_type TEXT NOT NULL,
                    pattern_data TEXT NOT NULL,
                    source_target TEXT DEFAULT '',
                    effectiveness REAL DEFAULT 1.0,
                    use_count INTEGER DEFAULT 1,
                    first_seen REAL NOT NULL,
                    last_used REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS techniques (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    technique_name TEXT NOT NULL UNIQUE,
                    category TEXT NOT NULL DEFAULT 'general',
                    description TEXT DEFAULT '',
                    mitre_id TEXT DEFAULT '',
                    success_count INTEGER DEFAULT 0,
                    fail_count INTEGER DEFAULT 0,
                    last_used REAL DEFAULT 0,
                    confidence REAL DEFAULT 0.5
                );
                CREATE TABLE IF NOT EXISTS knowledge_edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_type TEXT NOT NULL,
                    from_value TEXT NOT NULL,
                    to_type TEXT NOT NULL,
                    to_value TEXT NOT NULL,
                    weight REAL DEFAULT 1.0,
                    last_seen REAL NOT NULL
                );
            """)

    def record_target(self, host: str, tags: str = "", notes: str = "") -> str:
        now = time.time()
        tid = hashlib.sha256(f"{host}:{now}".encode()).hexdigest()[:12]
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute("SELECT id, tags, notes FROM targets WHERE host = ?", (host,)).fetchone()
            if existing:
                tid = existing[0]
                merged_tags = f"{existing[1]} {tags}".strip()
                merged_notes = f"{existing[2]}\n---\n{notes}".strip() if existing[2] and notes else (existing[2] or notes)
                conn.execute("UPDATE targets SET last_seen = ?, tags = ?, notes = ? WHERE id = ?",
                             (now, merged_tags, merged_notes, tid))
            else:
                conn.execute("INSERT INTO targets (id, host, first_seen, last_seen, tags, notes) VALUES (?, ?, ?, ?, ?, ?)",
                             (tid, host, now, now, tags, notes))
        return tid

    def record_finding(self, target_id: str, phase: str, finding_type: str,
                       severity: str = "info", description: str = "",
                       evidence: str = "", payload: str = ""):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO findings (target_id, phase, finding_type, severity, description, evidence, payload, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (target_id, phase, finding_type, severity, description, evidence[:500], payload[:500], time.time()),
            )
            if severity in ("critical", "high"):
                conn.execute(
                    "INSERT OR IGNORE INTO techniques (technique_name, category, description, last_used, confidence) VALUES (?, ?, ?, ?, ?)",
                    (finding_type, phase, description[:200], time.time(), 0.5),
                )

    def record_pattern(self, pattern_type: str, pattern_data: dict, source_target: str = ""):
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id, use_count, effectiveness FROM patterns WHERE pattern_type = ? AND pattern_data = ?",
                (pattern_type, json.dumps(pattern_data, sort_keys=True)),
            ).fetchone()
            now = time.time()
            if existing:
                pid, count, eff = existing
                conn.execute(
                    "UPDATE patterns SET use_count = ?, last_used = ? WHERE id = ?",
                    (count + 1, now, pid),
                )
            else:
                conn.execute(
                    "INSERT INTO patterns (pattern_type, pattern_data, source_target, effectiveness, use_count, first_seen, last_used) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (pattern_type, json.dumps(pattern_data, sort_keys=True), source_target, 1.0, 1, now, now),
                )

    def record_technique_result(self, technique_name: str, category: str, success: bool, description: str = ""):
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute("SELECT id, success_count, fail_count, confidence FROM techniques WHERE technique_name = ?",
                                    (technique_name,)).fetchone()
            if existing:
                tid, sc, fc, conf = existing
                if success:
                    sc += 1
                else:
                    fc += 1
                total = sc + fc
                new_conf = min(0.95, sc / total) if total > 0 else 0.5
                conn.execute("UPDATE techniques SET success_count = ?, fail_count = ?, confidence = ?, last_used = ? WHERE id = ?",
                             (sc, fc, new_conf, now, tid))
            else:
                sc = 1 if success else 0
                fc = 0 if success else 1
                conn.execute(
                    "INSERT INTO techniques (technique_name, category, description, success_count, fail_count, last_used, confidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (technique_name, category, description[:200], sc, fc, now, 0.5),
                )

    def record_knowledge_edge(self, from_type: str, from_value: str, to_type: str, to_value: str, weight: float = 1.0):
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM knowledge_edges WHERE from_type = ? AND from_value = ? AND to_type = ? AND to_value = ?",
                (from_type, from_value, to_type, to_value),
            ).fetchone()
            if existing:
                conn.execute("UPDATE knowledge_edges SET weight = ?, last_seen = ? WHERE id = ?",
                             (weight, now, existing[0]))
            else:
                conn.execute(
                    "INSERT INTO knowledge_edges (from_type, from_value, to_type, to_value, weight, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                    (from_type, from_value, to_type, to_value, weight, now),
                )

    def store_engagement_results(self, target: str, results: dict) -> str:
        tid = self.record_target(target)
        for phase_name, phase_data in results.get("results", results.get("phases", {})).items():
            if not isinstance(phase_data, dict):
                continue
            success = phase_data.get("success", False)
            for finding in phase_data.get("findings", phase_data.get("data", {}).get("findings", [])):
                if isinstance(finding, dict):
                    self.record_finding(
                        target_id=tid,
                        phase=phase_name,
                        finding_type=finding.get("type", "unknown"),
                        severity=finding.get("severity", "info"),
                        description=finding.get("description", ""),
                        evidence=finding.get("evidence", ""),
                        payload=finding.get("payload", ""),
                    )
                    self.record_technique_result(
                        technique_name=finding.get("type", "unknown"),
                        category=phase_name,
                        success=success,
                        description=finding.get("description", ""),
                    )
                    port = finding.get("port")
                    svc = finding.get("service")
                    if port:
                        self.record_knowledge_edge("target", target, "port", f"{port}/{svc or '?'}", weight=1.0)
        return tid

    def get_target_summary(self, target: str = None) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            if target:
                rows = conn.execute(
                    "SELECT id, host, first_seen, last_seen, tags, notes FROM targets WHERE host LIKE ? ORDER BY last_seen DESC",
                    (f"%{target}%",),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, host, first_seen, last_seen, tags, notes FROM targets ORDER BY last_seen DESC LIMIT 20",
                ).fetchall()
            return [{"id": r[0], "host": r[1], "first_seen": r[2], "last_seen": r[3], "tags": r[4], "notes": r[5][:200]} for r in rows]

    def get_techniques(self, min_confidence: float = 0.0) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT technique_name, category, description, mitre_id, success_count, fail_count, confidence, last_used FROM techniques WHERE confidence >= ? ORDER BY confidence DESC",
                (min_confidence,),
            ).fetchall()
            return [{"technique": r[0], "category": r[1], "description": r[2], "mitre_id": r[3],
                     "successes": r[4], "failures": r[5], "confidence": r[6], "last_used": r[7]} for r in rows]

    def get_patterns(self, pattern_type: str = None) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            if pattern_type:
                rows = conn.execute(
                    "SELECT pattern_type, pattern_data, source_target, effectiveness, use_count, first_seen, last_used FROM patterns WHERE pattern_type = ? ORDER BY use_count DESC",
                    (pattern_type,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT pattern_type, pattern_data, source_target, effectiveness, use_count, first_seen, last_used FROM patterns ORDER BY use_count DESC LIMIT 50",
                ).fetchall()
            return [{"type": r[0], "data": json.loads(r[1]), "source": r[2], "effectiveness": r[3],
                     "uses": r[4], "first_seen": r[5], "last_used": r[6]} for r in rows]

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            targets = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            patterns = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
            techniques = conn.execute("SELECT COUNT(*) FROM techniques").fetchone()[0]
            edges = conn.execute("SELECT COUNT(*) FROM knowledge_edges").fetchone()[0]
            return {"targets": targets, "findings": findings, "patterns": patterns, "techniques": techniques, "knowledge_edges": edges}


grow = GrowthDB()
