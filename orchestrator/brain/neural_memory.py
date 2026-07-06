import sqlite3, json, time, hashlib, os
from pathlib import Path

DB_PATH = os.getenv("BRAIN_DB", str(Path(__file__).resolve().parent.parent / "data" / "brain.db"))

EXPIRY_EPISODIC = 86400 * 30
EXPIRY_SEMANTIC = 0


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS episodic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT, target TEXT, model TEXT, context TEXT,
            input_hash TEXT, output_summary TEXT,
            success INTEGER, score REAL, latency REAL,
            embedding BLOB,
            timestamp REAL, expires_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_episodic_target ON episodic(target);
        CREATE INDEX IF NOT EXISTS idx_episodic_type ON episodic(event_type);
        CREATE INDEX IF NOT EXISTS idx_episodic_expires ON episodic(expires_at);

        CREATE TABLE IF NOT EXISTS semantic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            concept TEXT UNIQUE, data TEXT,
            confidence REAL DEFAULT 0.5,
            source TEXT, updated_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_semantic_concept ON semantic(concept);

        CREATE TABLE IF NOT EXISTS target_profiles (
            target TEXT PRIMARY KEY,
            profile_json TEXT,
            last_seen REAL,
            attack_count INTEGER DEFAULT 0,
            success_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS skill_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            skill_name TEXT, target TEXT, subdomain TEXT,
            result_summary TEXT,
            success INTEGER, latency REAL,
            timestamp REAL
        );
        CREATE INDEX IF NOT EXISTS idx_skill_name ON skill_memory(skill_name);
        CREATE INDEX IF NOT EXISTS idx_skill_target ON skill_memory(target);
    """)
    conn.commit()


_conn_local = {}


def _get_conn() -> sqlite3.Connection:
    import threading
    tid = threading.get_ident()
    if tid not in _conn_local:
        conn = _connect()
        _init(conn)
        _conn_local[tid] = conn
    return _conn_local[tid]


def store_episodic(event_type: str, target: str, model: str, context: str,
                   input_data: str, output_summary: str,
                   success: bool, score: float, latency: float,
                   ttl: int = EXPIRY_EPISODIC) -> int:
    conn = _get_conn()
    input_hash = hashlib.sha256(input_data.encode()).hexdigest()[:16]
    expires = time.time() + ttl if ttl > 0 else 0
    cur = conn.execute(
        """INSERT INTO episodic
           (event_type, target, model, context, input_hash, output_summary,
            success, score, latency, timestamp, expires_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (event_type, target, model, context, input_hash, output_summary[:2000],
         int(success), score, latency, time.time(), expires),
    )
    conn.commit()
    return cur.lastrowid


def retrieve_episodic(target: str = None, event_type: str = None, limit: int = 50) -> list:
    conn = _get_conn()
    now = time.time()
    conn.execute("DELETE FROM episodic WHERE expires_at > 0 AND expires_at < ?", (now,))
    conn.commit()
    q = "SELECT * FROM episodic WHERE 1=1"
    params = []
    if target:
        q += " AND target=?"
        params.append(target)
    if event_type:
        q += " AND event_type=?"
        params.append(event_type)
    q += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    return [dict(r) for r in rows]


def store_semantic(concept: str, data: dict, confidence: float = 0.5, source: str = "brain"):
    conn = _get_conn()
    conn.execute(
        """INSERT INTO semantic (concept, data, confidence, source, updated_at)
           VALUES (?,?,?,?,?)
           ON CONFLICT(concept) DO UPDATE SET data=excluded.data, confidence=excluded.confidence,
           source=excluded.source, updated_at=excluded.updated_at""",
        (concept, json.dumps(data), confidence, source, time.time()),
    )
    conn.commit()


def retrieve_semantic(concept: str = None, min_confidence: float = 0.0) -> list:
    conn = _get_conn()
    if concept:
        rows = conn.execute("SELECT * FROM semantic WHERE concept=?", (concept,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM semantic WHERE confidence>=?", (min_confidence,)).fetchall()
    return [dict(r) for r in rows]


def store_target_profile(target: str, profile: dict):
    conn = _get_conn()
    row = conn.execute("SELECT * FROM target_profiles WHERE target=?", (target,)).fetchone()
    if row:
        existing = json.loads(row["profile_json"])
        existing.update(profile)
        profile = existing
        attack_count = row["attack_count"]
        success_count = row["success_count"]
    else:
        attack_count = 0
        success_count = 0
    conn.execute(
        """INSERT INTO target_profiles (target, profile_json, last_seen, attack_count, success_count)
           VALUES (?,?,?,?,?)
           ON CONFLICT(target) DO UPDATE SET profile_json=excluded.profile_json,
           last_seen=excluded.last_seen""",
        (target, json.dumps(profile), time.time(), attack_count, success_count),
    )
    conn.commit()


def get_target_profile(target: str) -> dict:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM target_profiles WHERE target=?", (target,)).fetchone()
    if row:
        return {
            "target": target,
            "profile": json.loads(row["profile_json"]),
            "last_seen": row["last_seen"],
            "attack_count": row["attack_count"],
            "success_count": row["success_count"],
        }
    return {}


def update_target_stats(target: str, success: bool):
    conn = _get_conn()
    if success:
        conn.execute(
            "UPDATE target_profiles SET attack_count=attack_count+1, success_count=success_count+1, last_seen=? WHERE target=?",
            (time.time(), target),
        )
    else:
        conn.execute(
            "UPDATE target_profiles SET attack_count=attack_count+1, last_seen=? WHERE target=?",
            (time.time(), target),
        )
    conn.commit()


def decay_memories(factor: float = 0.95):
    conn = _get_conn()
    conn.execute("UPDATE semantic SET confidence = confidence * ? WHERE confidence > 0.01", (factor,))
    conn.execute("DELETE FROM semantic WHERE confidence < 0.01")
    conn.commit()


def get_memory_stats() -> dict:
    conn = _get_conn()
    e_count = conn.execute("SELECT COUNT(*) as c FROM episodic").fetchone()["c"]
    s_count = conn.execute("SELECT COUNT(*) as c FROM semantic").fetchone()["c"]
    t_count = conn.execute("SELECT COUNT(*) as c FROM target_profiles").fetchone()["c"]
    sk_count = conn.execute("SELECT COUNT(*) as c FROM skill_memory").fetchone()["c"]
    return {
        "episodic_count": e_count,
        "semantic_count": s_count,
        "target_count": t_count,
        "skill_memory_count": sk_count,
    }


def record_schema_drift(service: str, path: str, declared_schema_hash: str,
                         field_errors: str, payload_sent: dict):
    conn = _get_conn()
    concept = f"schema_drift:{service}:{path}"
    data = {
        "service": service,
        "path": path,
        "declared_schema_hash": declared_schema_hash,
        "field_errors": field_errors,
        "payload_sent": payload_sent,
        "timestamp": time.time(),
    }
    conn.execute(
        """INSERT INTO semantic (concept, data, confidence, source, updated_at)
           VALUES (?,?,?,?,?)
           ON CONFLICT(concept) DO UPDATE SET data=excluded.data,
           confidence=min(0.9, confidence + 0.1), source=excluded.source,
           updated_at=excluded.updated_at""",
        (concept, json.dumps(data), 0.8, "schema_registry", time.time()),
    )
    conn.commit()


def store_skill_memory(skill_name: str, target: str, subdomain: str,
                       result_summary: str, success: bool, latency: float):
    conn = _get_conn()
    conn.execute(
        """INSERT INTO skill_memory (skill_name, target, subdomain, result_summary, success, latency, timestamp)
           VALUES (?,?,?,?,?,?,?)""",
        (skill_name, target, subdomain, result_summary[:1000], int(success), latency, time.time()),
    )
    conn.commit()


def retrieve_skill_memory(skill_name: str = None, target: str = None, limit: int = 50) -> list:
    conn = _get_conn()
    q = "SELECT * FROM skill_memory WHERE 1=1"
    params = []
    if skill_name:
        q += " AND skill_name=?"
        params.append(skill_name)
    if target:
        q += " AND target=?"
        params.append(target)
    q += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    return [dict(r) for r in rows]


def get_skill_memory_stats() -> dict:
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(*) as total, SUM(success) as successes FROM skill_memory"
    ).fetchone()
    return {"total": row["total"], "successes": row["successes"] or 0, "failures": row["total"] - (row["successes"] or 0)}


class NeuralMemory:
    def store_episodic(self, event_type, target, model, context, input_data, output_summary, success, score, latency, ttl=EXPIRY_EPISODIC):
        return store_episodic(event_type, target, model, context, input_data, output_summary, success, score, latency, ttl)

    def retrieve_episodic(self, target=None, event_type=None, limit=50):
        return retrieve_episodic(target, event_type, limit)

    def store_semantic(self, concept, data, confidence=0.5, source="brain"):
        store_semantic(concept, data, confidence, source)

    def retrieve_semantic(self, concept=None, min_confidence=0.0):
        return retrieve_semantic(concept, min_confidence)

    def store_target_profile(self, target, profile):
        store_target_profile(target, profile)

    def get_target_profile(self, target):
        return get_target_profile(target)

    def decay(self, factor=0.95):
        decay_memories(factor)

    def record_schema_drift(self, service, path, declared_schema_hash, field_errors, payload_sent):
        record_schema_drift(service, path, declared_schema_hash, field_errors, payload_sent)

    def get_stats(self):
        return get_memory_stats()
