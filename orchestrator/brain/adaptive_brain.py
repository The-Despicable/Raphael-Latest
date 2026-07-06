import sqlite3, json, time, math, os, random, threading, hashlib, re
from pathlib import Path

DB_PATH = os.getenv("BRAIN_DB", str(Path(__file__).resolve().parent.parent / "data" / "brain.db"))

EMA_ALPHA = 0.15
CIRCUIT_FAIL_THRESHOLD = 3
CIRCUIT_COOLDOWN = 60
UCB_C = 1.414
LATENCY_WEIGHT = 0.3
SCORE_WEIGHT = 0.7
DECAY_HALFLIFE = 3600
STALE_CACHE_LIMIT = 5

PRESEEDED_PRIORS = {
    "w12": {"sqli": (8, 2), "xss": (7, 3), "rce": (6, 4), "recon": (9, 1), "phishing": (7, 3), "auth_jwt": (9, 1), "proxy": (5, 5)},
    "w480b": {"sqli": (7, 3), "xss": (7, 3), "rce": (5, 5), "recon": (6, 4), "phishing": (8, 2), "persist": (8, 2), "proxy": (5, 5)},
    "m3": {"sqli": (6, 4), "xss": (7, 3), "rce": (7, 3), "recon": (8, 2), "phishing": (9, 1), "proxy": (6, 4)},
    "nemotron-super": {"sqli": (7, 3), "xss": (8, 2), "rce": (7, 3), "recon": (8, 2), "phishing": (7, 3), "proxy": (7, 3)},
    "mistral-large": {"sqli": (7, 3), "xss": (7, 3), "rce": (6, 4), "recon": (7, 3), "phishing": (6, 4), "proxy": (7, 3)},
    "kimi": {"sqli": (6, 4), "xss": (7, 3), "rce": (5, 5), "recon": (9, 1), "phishing": (8, 2), "strategy": (9, 1), "proxy": (8, 2)},
    "gemma4": {"sqli": (6, 4), "xss": (6, 4), "rce": (7, 3), "recon": (8, 2), "phishing": (7, 3), "operations": (8, 2), "proxy": (7, 3)},
}

PIPELINE_TEMPLATES = {
    "attack": ["strategy", "operations", "rce"],
    "recon": ["recon", "sqli"],
    "exfil": ["strategy", "operations", "phishing"],
    "auth_bypass": ["strategy", "auth_jwt", "rce"],
    "persist": ["strategy", "persist", "phishing"],
}

PHASE_CONTEXT_MAP = {
    "recon": "recon",
    "scan": "sqli",
    "exploit": "rce",
    "postex": "rce",
    "exfil": "phishing",
    "phish": "phishing",
    "auth": "auth_jwt",
    "jwt": "auth_jwt",
    "persist": "persist",
    "pivot": "persist",
    "plan": "strategy",
    "command": "operations",
    "coordinate": "operations",
    "proxy": "proxy",
    "anonymity": "proxy",
}

_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS model_stats (
            model TEXT, context TEXT,
            alpha REAL DEFAULT 1.0, beta REAL DEFAULT 1.0,
            ema_score REAL DEFAULT 0.5, ema_latency REAL DEFAULT 2.0,
            total_calls INTEGER DEFAULT 0, total_success INTEGER DEFAULT 0,
            circuit_fails INTEGER DEFAULT 0, circuit_open_until REAL DEFAULT 0,
            PRIMARY KEY (model, context)
        );
        CREATE TABLE IF NOT EXISTS reasoning_chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_hash TEXT, step INTEGER, model TEXT, context TEXT,
            score REAL, latency REAL, timestamp REAL
        );
        CREATE TABLE IF NOT EXISTS domain_shifts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model TEXT, context TEXT, old_alpha REAL, old_beta REAL,
            new_alpha REAL, new_beta REAL, shift_magnitude REAL, timestamp REAL
        );
        CREATE TABLE IF NOT EXISTS pso_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context TEXT, positions TEXT, velocities TEXT,
            best_positions TEXT, best_scores TEXT,
            global_best TEXT, iteration INTEGER DEFAULT 0,
            updated_at REAL
        );
    """)
    conn.commit()
    for col in ("last_call_time", "completeness_score", "cache_hit_ratio", "identical_responses"):
        try:
            conn.execute(f"ALTER TABLE model_stats ADD COLUMN {col} REAL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
    for col in ("pipeline_log", "debate_scores"):
        try:
            conn.execute(f"CREATE TABLE IF NOT EXISTS {col} (id INTEGER PRIMARY KEY AUTOINCREMENT)")
            conn.execute(f"DROP TABLE {col}")
        except sqlite3.OperationalError:
            pass
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS pipeline_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pipeline TEXT, context TEXT, models TEXT,
            scores TEXT, overall REAL, timestamp REAL
        );
        CREATE TABLE IF NOT EXISTS debate_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proposer TEXT, critic TEXT, context TEXT,
            proposal_score REAL, critique_score REAL,
            accepted INTEGER DEFAULT 0,
            timestamp REAL
        );
    """)
    conn.commit()


def _seed_priors(conn):
    for model, ctxs in PRESEEDED_PRIORS.items():
        for ctx, (a, b) in ctxs.items():
            conn.execute(
                "INSERT OR IGNORE INTO model_stats (model, context, alpha, beta) VALUES (?,?,?,?)",
                (model, ctx, a, b),
            )
    conn.commit()


_conn_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    if not hasattr(_conn_local, "conn") or _conn_local.conn is None:
        _conn_local.conn = _connect()
        _init_db(_conn_local.conn)
        _seed_priors(_conn_local.conn)
    return _conn_local.conn


def thompson_sample(model: str, context: str) -> float:
    conn = _get_conn()
    row = conn.execute(
        "SELECT alpha, beta FROM model_stats WHERE model=? AND context=?",
        (model, context),
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO model_stats (model, context, alpha, beta) VALUES (?,?,?,?)",
            (model, context, 1.0, 1.0),
        )
        conn.commit()
        a, b = 1.0, 1.0
    else:
        a, b = row["alpha"], row["beta"]
    return random.betavariate(max(a, 0.01), max(b, 0.01))


def ucb_score(model: str, context: str, total_pulls_context: int) -> float:
    conn = _get_conn()
    row = conn.execute(
        "SELECT total_calls, ema_score FROM model_stats WHERE model=? AND context=?",
        (model, context),
    ).fetchone()
    if row is None or row["total_calls"] == 0:
        return float("inf")
    n = row["total_calls"]
    avg = row["ema_score"]
    return avg + UCB_C * math.sqrt(math.log(max(total_pulls_context, 1)) / max(n, 1))


def is_circuit_open(model: str, context: str) -> bool:
    conn = _get_conn()
    row = conn.execute(
        "SELECT circuit_fails, circuit_open_until FROM model_stats WHERE model=? AND context=?",
        (model, context),
    ).fetchone()
    if row is None:
        return False
    if row["circuit_fails"] >= CIRCUIT_FAIL_THRESHOLD:
        if time.time() < row["circuit_open_until"]:
            return True
        conn.execute(
            "UPDATE model_stats SET circuit_fails=0, circuit_open_until=0 WHERE model=? AND context=?",
            (model, context),
        )
        conn.commit()
        return False
    return False


def _time_decay(timestamp: float) -> float:
    elapsed = time.time() - timestamp
    return math.exp(-elapsed / DECAY_HALFLIFE)


def verify_code_completeness(code: str) -> float:
    if not code or len(code) < 100:
        return 0.0
    score = 0.5
    if re.search(r'^import ', code, re.MULTILINE):
        score += 0.15
    if re.search(r'^from ', code, re.MULTILINE):
        score += 0.05
    if re.search(r'def |class ', code):
        score += 0.1
    if re.search(r'print\(', code):
        score += 0.05
    if re.search(r'response|\.get\(|\.post\(|\.patch\(', code):
        score += 0.1
    if re.search(r'try:', code):
        score += 0.05
    truncated = "```" in code and len(code) < 500
    if truncated:
        score -= 0.3
    return max(0.0, min(1.0, score))


def detect_cache_poisoning(model: str, context: str, recent_outputs: list) -> bool:
    if len(recent_outputs) < 3:
        return False
    unique = len(set(hashlib.md5(o.encode()).hexdigest() for o in recent_outputs[-STALE_CACHE_LIMIT:]))
    if unique <= 2:
        conn = _get_conn()
        conn.execute(
            "UPDATE model_stats SET identical_responses = identical_responses + 1 WHERE model=? AND context=?",
            (model, context),
        )
        conn.commit()
        row = conn.execute(
            "SELECT identical_responses FROM model_stats WHERE model=? AND context=?",
            (model, context),
        ).fetchone()
        if row and row["identical_responses"] >= 3:
            return True
    return False


def update_stats(model: str, context: str, success: bool, latency: float, code: str = ""):
    with _lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM model_stats WHERE model=? AND context=?",
            (model, context),
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO model_stats (model, context, alpha, beta) VALUES (?,?,?,?)",
                (model, context, 1.0, 1.0),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM model_stats WHERE model=? AND context=?",
                (model, context),
            ).fetchone()

        decay = _time_decay(row["last_call_time"]) if row["last_call_time"] else 1.0

        a, b = row["alpha"], row["beta"]
        if success:
            a += 1.0 * decay
        else:
            b += 1.0 * decay

        old_ema = row["ema_score"]
        new_signal = 1.0 if success else 0.0
        ema_score = EMA_ALPHA * new_signal + (1 - EMA_ALPHA) * old_ema

        old_lat = row["ema_latency"]
        ema_latency = EMA_ALPHA * latency + (1 - EMA_ALPHA) * old_lat

        fails = row["circuit_fails"]
        open_until = row["circuit_open_until"]
        if not success:
            fails += 1
            if fails >= CIRCUIT_FAIL_THRESHOLD:
                open_until = time.time() + CIRCUIT_COOLDOWN
        else:
            fails = 0
            open_until = 0

        total_calls = row["total_calls"] + 1
        total_success = row["total_success"] + (1 if success else 0)

        comp = verify_code_completeness(code) if code else row["completeness_score"]
        comp = EMA_ALPHA * comp + (1 - EMA_ALPHA) * row["completeness_score"]

        conn.execute(
            """UPDATE model_stats SET alpha=?, beta=?, ema_score=?, ema_latency=?,
               circuit_fails=?, circuit_open_until=?, total_calls=?, total_success=?,
               last_call_time=?, completeness_score=?
               WHERE model=? AND context=?""",
            (a, b, ema_score, ema_latency, fails, open_until, total_calls, total_success,
             time.time(), comp, model, context),
        )
        conn.commit()


def detect_domain_shift(model: str, context: str, window: int = 20, threshold: float = 0.3) -> bool:
    conn = _get_conn()
    row = conn.execute(
        "SELECT total_calls, total_success, alpha, beta FROM model_stats WHERE model=? AND context=?",
        (model, context),
    ).fetchone()
    if row is None or row["total_calls"] < window:
        return False
    recent_rate = row["total_success"] / max(row["total_calls"], 1)
    prior_mean = row["alpha"] / max(row["alpha"] + row["beta"], 0.01)
    return abs(recent_rate - prior_mean) > threshold


def adapt_priors_on_shift(model: str, context: str):
    conn = _get_conn()
    row = conn.execute(
        "SELECT total_calls, total_success, alpha, beta FROM model_stats WHERE model=? AND context=?",
        (model, context),
    ).fetchone()
    if row is None:
        return
    recent_rate = row["total_success"] / max(row["total_calls"], 1)
    new_alpha = max(1.0, recent_rate * 10)
    new_beta = max(1.0, (1 - recent_rate) * 10)
    shift_mag = abs(new_alpha - row["alpha"]) + abs(new_beta - row["beta"])
    conn.execute(
        "INSERT INTO domain_shifts (model, context, old_alpha, old_beta, new_alpha, new_beta, shift_magnitude, timestamp) VALUES (?,?,?,?,?,?,?,?)",
        (model, context, row["alpha"], row["beta"], new_alpha, new_beta, shift_mag, time.time()),
    )
    conn.execute(
        "UPDATE model_stats SET alpha=?, beta=? WHERE model=? AND context=?",
        (new_alpha, new_beta, model, context),
    )
    conn.commit()


def pick_model(context: str, candidates: list) -> str:
    conn = _get_conn()
    total = 0
    for m in candidates:
        r = conn.execute(
            "SELECT total_calls FROM model_stats WHERE model=? AND context=?",
            (m, context),
        ).fetchone()
        if r:
            total += r["total_calls"]

    best_model = None
    best_score = -1.0
    for m in candidates:
        if is_circuit_open(m, context):
            continue
        ts = thompson_sample(m, context)
        u = ucb_score(m, context, total)

        row = conn.execute(
            "SELECT ema_latency, completeness_score FROM model_stats WHERE model=? AND context=?",
            (m, context),
        ).fetchone()
        lat = row["ema_latency"] if row else 2.0
        comp = row["completeness_score"] if row else 0.5
        max_lat = 10.0
        lat_norm = 1.0 - min(lat / max_lat, 1.0)

        combined = SCORE_WEIGHT * (0.4 * ts + 0.4 * u + 0.2 * comp) + LATENCY_WEIGHT * lat_norm
        if combined > best_score:
            best_score = combined
            best_model = m

    if best_model is None:
        best_model = random.choice(candidates)

    if detect_domain_shift(best_model, context):
        adapt_priors_on_shift(best_model, context)

    return best_model


def pipeline_models(pipeline_type: str, strategy_pool: list, ops_pool: list, exec_pool: list) -> list:
    template = PIPELINE_TEMPLATES.get(pipeline_type, ["recon", "rce"])
    chain = []
    for ctx in template:
        if ctx in ("strategy",):
            chain.append(pick_model(ctx, strategy_pool))
        elif ctx in ("operations", "auth_jwt", "persist"):
            chain.append(pick_model(ctx, ops_pool))
        else:
            chain.append(pick_model(ctx, exec_pool))
    return chain


def record_debate(proposer: str, critic: str, context: str, proposal_ok: bool, critique_accepted: bool):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO debate_scores (proposer, critic, context, proposal_score, critique_score, accepted, timestamp) VALUES (?,?,?,?,?,?,?)",
        (proposer, critic, context, 1.0 if proposal_ok else 0.0, 1.0 if critique_accepted else 0.0,
         1 if critique_accepted else 0, time.time()),
    )
    conn.commit()
    if critique_accepted:
        update_stats(critic, context, True, 0)
        update_stats(proposer, context, False, 0)
    else:
        update_stats(proposer, context, True, 0)
        update_stats(critic, context, False, 0)


def log_pipeline(pipeline: str, context: str, models: list, scores: list, overall: float):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO pipeline_log (pipeline, context, models, scores, overall, timestamp) VALUES (?,?,?,?,?,?)",
        (pipeline, context, json.dumps(models), json.dumps(scores), overall, time.time()),
    )
    conn.commit()


def record_chain_step(chain_hash: str, step: int, model: str, context: str, score: float, latency: float):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO reasoning_chains (chain_hash, step, model, context, score, latency, timestamp) VALUES (?,?,?,?,?,?,?)",
        (chain_hash, step, model, context, score, latency, time.time()),
    )
    conn.commit()


def get_chain_history(chain_hash: str) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM reasoning_chains WHERE chain_hash=? ORDER BY step",
        (chain_hash,),
    ).fetchall()
    return [dict(r) for r in rows]


def score_result(output: str, error: bool, latency: float) -> bool:
    if error or not output or len(output.strip()) < 20:
        return False
    comp = verify_code_completeness(output)
    if comp < 0.3:
        return False
    return True


def get_analytics() -> dict:
    conn = _get_conn()
    models = conn.execute("SELECT * FROM model_stats").fetchall()
    shifts = conn.execute("SELECT * FROM domain_shifts ORDER BY timestamp DESC LIMIT 50").fetchall()
    chains = conn.execute("SELECT COUNT(*) as cnt FROM reasoning_chains").fetchone()
    pipelines = conn.execute("SELECT * FROM pipeline_log ORDER BY timestamp DESC LIMIT 10").fetchall()
    debates = conn.execute("SELECT * FROM debate_scores ORDER BY timestamp DESC LIMIT 10").fetchall()
    return {
        "models": [dict(m) for m in models],
        "recent_shifts": [dict(s) for s in shifts],
        "total_chain_steps": chains["cnt"] if chains else 0,
        "recent_pipelines": [dict(p) for p in pipelines],
        "recent_debates": [dict(d) for d in debates],
        "timestamp": time.time(),
    }


class AdaptiveBrain:
    def __init__(self):
        self._target_contexts = {}
        self._recent_outputs = {}

    def pick_model(self, context: str, candidates: list = None) -> str:
        if candidates is None:
            candidates = ["w12", "w480b", "m3", "gemma4"]
        return pick_model(context, candidates)

    def select_model(self, phase: str, target: str, context: dict = None) -> tuple:
        ctx = PHASE_CONTEXT_MAP.get(phase, "recon")
        model = self.pick_model(ctx)
        strategy = {"passive": True, "fast": False, "safe": True}
        if context:
            strategy.update(context)
        return model, strategy

    def select_proxy(self, target: str, candidates: list = None) -> str:
        if candidates is None:
            candidates = ["protonvpn", "tor", "compromised_academic", "direct"]
        return pick_model("proxy", candidates)

    def select_pipeline(self, pipeline_type: str) -> list:
        return pipeline_models(
            pipeline_type,
            strategy_pool=["kimi", "nemotron-super", "mistral-large"],
            ops_pool=["gemma4", "kimi"],
            exec_pool=["w12", "w480b", "m3", "gemma4"],
        )

    def update(self, model: str, phase: str, success: bool, latency: float, code: str = ""):
        ctx = PHASE_CONTEXT_MAP.get(phase, "recon")
        return update_stats(model, ctx, success, latency, code)

    def update_stats(self, model: str, context: str, success: bool, latency: float, code: str = ""):
        return update_stats(model, context, success, latency, code)

    def track_output(self, model: str, context: str, output: str):
        key = f"{model}:{context}"
        if key not in self._recent_outputs:
            self._recent_outputs[key] = []
        self._recent_outputs[key].append(output)
        if len(self._recent_outputs[key]) > STALE_CACHE_LIMIT:
            self._recent_outputs[key] = self._recent_outputs[key][-STALE_CACHE_LIMIT:]
        if detect_cache_poisoning(model, context, self._recent_outputs[key]):
            update_stats(model, context, False, 10.0, output)

    def debate_outcome(self, proposer: str, critic: str, context: str, proposal_ok: bool, critique_accepted: bool):
        return record_debate(proposer, critic, context, proposal_ok, critique_accepted)

    def should_abort(self, phase: str, target: str) -> bool:
        conn = _get_conn()
        models = conn.execute(
            "SELECT model FROM model_stats WHERE circuit_fails >= ?", (CIRCUIT_FAIL_THRESHOLD,)
        ).fetchall()
        if len(models) >= 3:
            return True
        target_ctx = self._target_contexts.get(target, {})
        abort_count = target_ctx.get("abort_count", 0)
        if abort_count >= 2:
            return True
        return False

    def verify_code(self, code: str) -> float:
        return verify_code_completeness(code)

    def generate_report(self, target: str, results: dict, full_context: dict = None) -> str:
        phases = results.get("results", results)
        lines = [f"# Autonomous Engagement Report: {target}", f"Generated: {time.ctime()}", ""]
        for phase_name, phase_result in phases.items():
            if isinstance(phase_result, dict):
                success = phase_result.get("success", False)
                latency = phase_result.get("latency", 0)
                model = phase_result.get("model", "unknown")
                lines.append(f"## {phase_name.upper()} Phase")
                lines.append(f"- Status: {'PASS' if success else 'FAIL'}")
                lines.append(f"- Model: {model}")
                lines.append(f"- Latency: {latency:.2f}s")
                lines.append("")
        conn = _get_conn()
        stats = conn.execute("SELECT * FROM model_stats").fetchall()
        lines.append("## Model Statistics")
        for s in stats:
            comp = s["completeness_score"]
            lines.append(f"- {s['model']}/{s['context']}: success={s['total_success']}/{s['total_calls']} "
                        f"ema={s['ema_score']:.3f} comp={comp:.2f}")
        return "\n".join(lines)

    def store_reasoning_chain(self, phase: str, target: str, model: str, result: dict):
        chain_hash = hashlib.sha256(f"{target}:{phase}:{time.time()}".encode()).hexdigest()[:12]
        ctx = PHASE_CONTEXT_MAP.get(phase, "recon")
        success = result.get("success", False)
        latency = result.get("latency", 0)
        record_chain_step(chain_hash, 0, model, ctx, 1.0 if success else 0.0, latency)

    def update_target_context(self, target: str, profile: dict):
        if target not in self._target_contexts:
            self._target_contexts[target] = {"attack_count": 0, "abort_count": 0}
        self._target_contexts[target].update(profile)

    def get_state(self) -> dict:
        conn = _get_conn()
        models = conn.execute("SELECT * FROM model_stats").fetchall()
        shifts = conn.execute("SELECT * FROM domain_shifts ORDER BY timestamp DESC LIMIT 50").fetchall()
        chains = conn.execute("SELECT COUNT(*) as cnt FROM reasoning_chains").fetchone()
        pipelines = conn.execute("SELECT * FROM pipeline_log ORDER BY timestamp DESC LIMIT 10").fetchall()
        debates = conn.execute("SELECT * FROM debate_scores ORDER BY timestamp DESC LIMIT 10").fetchall()
        return {
            "models": [dict(m) for m in models],
            "recent_shifts": [dict(s) for s in shifts],
            "total_chain_steps": chains["cnt"] if chains else 0,
            "recent_pipelines": [dict(p) for p in pipelines],
            "recent_debates": [dict(d) for d in debates],
            "timestamp": time.time(),
        }

    def reset(self):
        conn = _get_conn()
        conn.executescript("DELETE FROM model_stats; DELETE FROM reasoning_chains; DELETE FROM domain_shifts; DELETE FROM pso_state; DELETE FROM pipeline_log; DELETE FROM debate_scores;")
        conn.commit()
        _seed_priors(conn)
        self._recent_outputs.clear()
        self._target_contexts.clear()

    def is_circuit_open(self, model: str, context: str) -> bool:
        return is_circuit_open(model, context)

    def thompson_sample(self, model: str, context: str) -> float:
        return thompson_sample(model, context)

    def retry_is_circuit_open(self, model: str) -> bool:
        return is_circuit_open(model, "general")

    def retry_update_stats(self, model: str, *, success: float, latency: float):
        return update_stats(model, "general", bool(success > 0.5), latency)

    def get_chain_history(self, chain_hash: str) -> list:
        return get_chain_history(chain_hash)


class PSOModelSelector:
    """Particle Swarm Optimization model selector (minimal)."""

    def __init__(self, n_models: int):
        self.n_models = n_models

    def select(self, context: str, candidates: list, iterations: int = 20) -> str:
        return pick_model(context, candidates)
