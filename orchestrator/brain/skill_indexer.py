import numpy as np
import re, sqlite3, json, time, os
from pathlib import Path
from collections import Counter

DB_PATH = os.getenv("BRAIN_DB", str(Path(__file__).resolve().parent.parent / "data" / "brain.db"))

NGRAM_RANGE = (1, 3)
TOP_K = 20


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_vector_table():
    conn = _connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS skill_vectors (
            skill_name TEXT PRIMARY KEY,
            subdomain TEXT,
            description TEXT,
            ngram_vector BLOB,
            mitre_tags TEXT,
            nist_tags TEXT,
            updated_at REAL
        );
    """)
    conn.commit()
    conn.close()


def _tokenize(text: str) -> list[str]:
    text = re.sub(r"[^a-z0-9\s]", " ", text.lower())
    return text.split()


def _ngrams(tokens: list[str]) -> Counter:
    counts = Counter()
    for n in range(NGRAM_RANGE[0], NGRAM_RANGE[1] + 1):
        for i in range(len(tokens) - n + 1):
            counts[" ".join(tokens[i:i+n])] += 1
    return counts


def _vector_from_counter(c: Counter, vocab: dict[str, int]) -> np.ndarray:
    vec = np.zeros(len(vocab), dtype=np.float32)
    for term, count in c.items():
        if term in vocab:
            vec[vocab[term]] = count
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec


def _build_vocab(all_docs: list[Counter]) -> dict[str, int]:
    vocab = {}
    for doc in all_docs:
        for term in doc:
            if term not in vocab:
                vocab[term] = len(vocab)
    return vocab


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b))


class SkillIndexer:
    def __init__(self):
        _init_vector_table()
        self._vocab: dict[str, int] = {}
        self._vectors: dict[str, np.ndarray] = {}
        self._metadata: dict[str, dict] = {}

    def _resolve_subdomain(self, s: dict) -> str:
        sd = s.get("subdomain", "") or ""
        if not sd:
            sd = s.get("domain", "") or ""
        return sd

    def build_index(self, skills: list[dict]):
        all_counters = []
        for s in skills:
            subdomain = self._resolve_subdomain(s)
            tags = [str(t) for t in (s.get("tags") or []) if t is not None]
            mitre = [str(m) for m in (s.get("mitre_attack") or []) if m is not None]
            nist = [str(n) for n in (s.get("nist_csf") or []) if n is not None]
            source = s.get("source", "anthropic")
            text = f"{s.get('name', '')} {s.get('description', '') or ''} {' '.join(tags)} {' '.join(mitre)} {' '.join(nist)} {subdomain} {source}"
            tokens = _tokenize(text)
            c = _ngrams(tokens)
            all_counters.append(c)
            self._metadata[s["name"]] = {
                "name": s["name"],
                "subdomain": subdomain,
                "description": s.get("description", ""),
                "mitre_attack": s.get("mitre_attack", []),
                "nist_csf": s.get("nist_csf", []),
                "tags": s.get("tags", []),
                "source": source,
            }

        self._vocab = _build_vocab(all_counters)

        conn = _connect()
        for s, c in zip(skills, all_counters):
            subdomain = self._resolve_subdomain(s)
            vec = _vector_from_counter(c, self._vocab)
            self._vectors[s["name"]] = vec
            vec_bytes = vec.tobytes()
            conn.execute(
                """INSERT OR REPLACE INTO skill_vectors
                   (skill_name, subdomain, description, ngram_vector, mitre_tags, nist_tags, updated_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    s["name"], subdomain, s.get("description", ""),
                    vec_bytes,
                    json.dumps(s.get("mitre_attack", [])),
                    json.dumps(s.get("nist_csf", [])),
                    time.time(),
                ),
            )
        conn.commit()
        conn.close()

    def search(self, query: str, top_k: int = TOP_K) -> list[dict]:
        if not self._vectors:
            self._load_from_db()
        if not self._vectors:
            return []

        tokens = _tokenize(query)
        query_counter = _ngrams(tokens)
        qvec = _vector_from_counter(query_counter, self._vocab)

        scored = []
        for name, vec in self._vectors.items():
            sim = _cosine_similarity(qvec, vec)
            if sim > 0:
                scored.append((sim, name))

        scored.sort(reverse=True)
        results = []
        for sim, name in scored[:top_k]:
            meta = self._metadata.get(name, {})
            results.append({
                "name": name,
                "score": round(sim, 4),
                "subdomain": meta.get("subdomain", ""),
                "description": meta.get("description", "")[:200],
                "mitre_attack": meta.get("mitre_attack", []),
                "nist_csf": meta.get("nist_csf", []),
            })
        return results

    def search_by_subdomain(self, subdomain: str) -> list[dict]:
        return [m for m in self._metadata.values()
                if m.get("subdomain") == subdomain or m.get("subdomain") == f"domain:{subdomain}"]

    def search_by_mitre(self, technique_id: str) -> list[dict]:
        return [
            m for m in self._metadata.values()
            if technique_id in m.get("mitre_attack", [])
        ]

    def _load_from_db(self):
        conn = _connect()
        rows = conn.execute("SELECT * FROM skill_vectors").fetchall()
        conn.close()
        vocab = {}
        for row in rows:
            vec = np.frombuffer(row["ngram_vector"], dtype=np.float32)
            self._vectors[row["skill_name"]] = vec
            self._metadata[row["skill_name"]] = {
                "name": row["skill_name"],
                "subdomain": row["subdomain"],
                "description": row["description"],
                "mitre_attack": json.loads(row["mitre_tags"] or "[]"),
                "nist_csf": json.loads(row["nist_tags"] or "[]"),
                "tags": [],
            }
            for i in range(len(vec)):
                if vec[i] != 0 and i not in vocab:
                    vocab[i] = f"dim_{i}"
        self._vocab = {v: k for k, v in vocab.items()}

    def stats(self) -> dict:
        return {
            "indexed_skills": len(self._vectors),
            "vocab_size": len(self._vocab),
            "subdomains": len(set(m["subdomain"] for m in self._metadata.values())),
        }
