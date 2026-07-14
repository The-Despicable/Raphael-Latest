import json
import logging
import os
import sqlite3
import time
import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("growth_db")

DB_PATH = os.getenv("GROWTH_DB_PATH", str(Path(__file__).resolve().parent / "data" / "growth.db"))


# ═══════════════════════════════════════════════════════════════════════════════
# SANITIZATION — Prevent injection via field values
# ═══════════════════════════════════════════════════════════════════════════════

# Allowlist patterns for field values
ALLOWED_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9._-]+$')
ALLOWED_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
ALLOWED_URL_RE = re.compile(r'^https?://[a-zA-Z0-9._/-]+$')
ALLOWED_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.@-]{1,256}$')
ALLOWED_PATH_RE = re.compile(r'^/[a-zA-Z0-9._/-]+$')

# Maximum lengths for input fields
MAX_FIELD_LENGTHS = {
    "hostname": 253,
    "url": 2048,
    "username": 256,
    "path": 4096,
    "domain": 253,
    "ip_address": 45,  # IPv6 max
    "service": 64,
    "technique_name": 128,
    "tool_name": 64,
}


def _sanitize_finding_value(key: str, value: Any) -> Any:
    """
    Sanitize a finding value based on its key name.

    Returns the sanitized value, or None if the value should be rejected.
    """
    if not isinstance(value, str):
        return value  # Non-string values pass through (e.g., ports as ints)

    # Truncate to max length
    max_len = MAX_FIELD_LENGTHS.get(key, 4096)
    value = value[:max_len]

    key_lower = key.lower()

    # Hostname validation
    if key_lower in ("hostname", "host", "host_name"):
        if not ALLOWED_HOSTNAME_RE.match(value):
            logger.warning("Rejecting invalid hostname: %s", value)
            return None
        return value.lower()

    # IP address validation
    if key_lower in ("ip", "ip_address", "ip_addr"):
        if not ALLOWED_IP_RE.match(value):
            logger.warning("Rejecting invalid IP: %s", value)
            return None
        return value

    # URL validation
    if key_lower in ("url", "uri", "endpoint"):
        if not ALLOWED_URL_RE.match(value):
            logger.warning("Rejecting invalid URL: %s", value)
            return None
        return value

    # Username validation
    if key_lower in ("username", "user", "account"):
        if not ALLOWED_USERNAME_RE.match(value):
            logger.warning("Rejecting invalid username: %s", value)
            return None
        return value

    # Path validation
    if key_lower in ("path", "directory", "file_path"):
        if not ALLOWED_PATH_RE.match(value):
            # Allow relative paths too
            cleaned = value.lstrip("./")
            if ALLOWED_PATH_RE.match("/" + cleaned):
                return "/" + cleaned
            logger.warning("Rejecting invalid path: %s", value)
            return None
        return value

    # Strip null bytes and control characters from all string values
    value = value.replace("\x00", "").replace("\r", "")
    # Remove any non-printable characters
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', value)

    return value


def _sanitize_pattern_data(data: Mapping[str, Any]) -> dict[str, Any]:
    """
    Recursively sanitize all string values in a pattern data dict.
    Returns a new dict with sanitized values.
    """
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            sanitized[key] = _sanitize_pattern_data(value)
        elif isinstance(value, list):
            sanitized[key] = [
                _sanitize_finding_value(key, item) if isinstance(item, str) else item
                for item in value
            ]
        elif isinstance(value, str):
            sanitized_val = _sanitize_finding_value(key, value)
            if sanitized_val is not None:
                sanitized[key] = sanitized_val
            else:
                # Drop the field if it failed validation, but log it
                logger.warning("Dropping invalid field %s=%s", key, repr(value))
        else:
            sanitized[key] = value
    return sanitized


# ═══════════════════════════════════════════════════════════════════════════════
# PRIMARY KEY GENERATION — Deterministic, non-injectable
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_pattern_id(pattern_data: Mapping[str, Any]) -> str:
    """
    Generate a deterministic, non-injectable primary key from pattern data.

    Uses SHA-256 of the normalized (sorted keys) JSON representation.
    This prevents any injection into the primary key space because:
    - The hash is fixed-width (64 hex chars), regardless of input size
    - Input is sanitized before hashing
    - The hash function is one-way — no reverse engineering from PK to data
    """
    normalized = json.dumps(pattern_data, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE SCHEMA — Updated with non-injectable PK and TTL
# ═══════════════════════════════════════════════════════════════════════════════

CREATE_PATTERNS_TABLE = """
CREATE TABLE IF NOT EXISTS patterns (
    pattern_id TEXT PRIMARY KEY,        -- SHA-256 hash (64 chars) — non-injectable
    pattern_data TEXT NOT NULL,          -- JSON blob (sanitized)
    technique_name TEXT,
    confidence REAL DEFAULT 0.0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    first_seen REAL NOT NULL,            -- Unix timestamp
    last_seen REAL NOT NULL,
    ttl REAL DEFAULT 7776000.0           -- 90 days in seconds
);
"""

CREATE_PATTERNS_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_patterns_technique ON patterns(technique_name);
CREATE INDEX IF NOT EXISTS idx_patterns_confidence ON patterns(confidence DESC);
CREATE INDEX IF NOT EXISTS idx_patterns_last_seen ON patterns(last_seen);
"""


# ═══════════════════════════════════════════════════════════════════════════════
# RECORD PATTERN WITH INJECTION PROTECTION
# ═══════════════════════════════════════════════════════════════════════════════

def record_pattern(
    conn: sqlite3.Connection,
    technique_name: str,
    pattern_data: Mapping[str, Any],
    confidence_weight: float = 1.0,
) -> str:
    """
    Record a pattern in the growth database.

    Returns the pattern_id (SHA-256 hash).

    Raises ValueError if pattern_data contains invalid fields after sanitization.
    """
    # 1. Sanitize input
    sanitized_data = _sanitize_pattern_data(pattern_data)
    if not sanitized_data:
        raise ValueError("Pattern data is empty after sanitization")

    # 2. Generate deterministic primary key
    pattern_id = _generate_pattern_id(sanitized_data)

    # 3. Validate technique name
    if technique_name and len(technique_name) > 128:
        technique_name = technique_name[:128]

    # 4. Upsert with TTL
    now = time.time()
    sanitized_json = json.dumps(sanitized_data, indent=None, separators=(",", ":"))

    conn.execute(
        """
        INSERT INTO patterns
            (pattern_id, pattern_data, technique_name, confidence,
             success_count, failure_count, first_seen, last_seen)
        VALUES (?, ?, ?, ?, 1, 0, ?, ?)
        ON CONFLICT(pattern_id) DO UPDATE SET
            last_seen = excluded.last_seen,
            success_count = success_count + 1,
            confidence = CAST(success_count + 1 AS REAL) /
                         CAST(success_count + 1 + failure_count AS REAL)
        """,
        (pattern_id, sanitized_json, technique_name,
         confidence_weight, now, now),
    )
    conn.commit()

    # 5. Enforce TTL — purge expired patterns
    _purge_expired_patterns(conn)

    logger.info(
        "Recorded pattern %s (technique=%s, fields=%d)",
        pattern_id[:12], technique_name, len(sanitized_data),
    )
    return pattern_id


def _purge_expired_patterns(conn: sqlite3.Connection) -> None:
    """Delete patterns older than their TTL."""
    now = time.time()
    cursor = conn.execute(
        "DELETE FROM patterns WHERE last_seen + ttl < ?",
        (now,),
    )
    if cursor.rowcount > 0:
        logger.info("Purged %d expired patterns", cursor.rowcount)
    conn.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# GROWTH DB CLASS — Updated to use new pattern recording
# ═══════════════════════════════════════════════════════════════════════════════

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
                -- Drop old patterns table (no technique_name column, injectable PK)
                DROP TABLE IF EXISTS patterns;
                -- New patterns table with non-injectable PK (SHA-256 hash)
                CREATE TABLE IF NOT EXISTS patterns (
                    pattern_id TEXT PRIMARY KEY,        -- SHA-256 hash (64 chars) — non-injectable
                    pattern_data TEXT NOT NULL,          -- JSON blob (sanitized)
                    technique_name TEXT,
                    confidence REAL DEFAULT 0.0,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    first_seen REAL NOT NULL,            -- Unix timestamp
                    last_seen REAL NOT NULL,
                    ttl REAL DEFAULT 7776000.0           -- 90 days in seconds
                );
            """ + CREATE_PATTERNS_INDEXES)

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
        """
        Legacy method — kept for compatibility.
        Delegates to the new injection-safe record_pattern.
        """
        with sqlite3.connect(self.db_path) as conn:
            try:
                record_pattern(
                    conn,
                    technique_name=pattern_type,
                    pattern_data=pattern_data,
                    confidence_weight=1.0,
                )
            except ValueError as e:
                logger.warning("Pattern rejected: %s", e)

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