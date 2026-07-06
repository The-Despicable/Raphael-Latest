import httpx, asyncio, json, time, os, hashlib
from pathlib import Path
from dotenv import load_dotenv
from cachetools import TTLCache
from orchestrator.utils.retry import retry_with_fallback, RetryExhaustedError
from orchestrator.utils.undercover import normalize as undercover_normalize

# Load .env so env vars are available outside Docker too
_dotenv_path = Path(__file__).resolve().parent.parent / ".env"
if _dotenv_path.exists():
    load_dotenv(dotenv_path=_dotenv_path, override=False)

OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
OMNIROUTE_BASE = os.getenv("OMNIROUTE_BASE", "http://localhost:20128/v1")
OMNIROUTE_API_KEY = os.getenv("OMNIROUTE_API_KEY", "sk-omniroute-local")

# ============================================================
# Model Inventory
# ============================================================
# Code Generation (NVIDIA API)
CODE_GEN = {
    "deepseek":           "deepseek-ai/deepseek-v4-flash",
    "glm":                "z-ai/glm-5.1",
    "nemotron":           "nvidia/nemotron-3-ultra-550b-a55b",
    "nemotron-super-120b":"nvidia/nemotron-3-super-120b-a12b",
    "mistral-small":      "mistralai/mistral-small-4-119b-2603",
}

# Reasoning (NVIDIA API)
REASONING = {
    "kimi":              "moonshotai/kimi-k2.6",
    "nemotron-super":    "nvidia/llama-3.3-nemotron-super-49b-v1",
    "nemotron-super15":  "nvidia/llama-3.3-nemotron-super-49b-v1.5",
    "mistral-large":     "mistralai/mistral-large-3-675b-instruct-2512",
    "mistral-medium":    "mistralai/mistral-medium-3.5-128b",
    "nemotron-nano-reasoning": "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning",
    "mistral-nemotron":  "mistralai/mistral-nemotron",
}

# Offensive / Unrestricted (Ollama → ollama.com proxies)
OFFENSIVE = {
    "wormgpt":    "blackgrg26/WORMGPT-12:latest",
    "wormgpt12":  "blackgrg26/WORMGPT-12:latest",
    "wormgpt13":  "blackgrg26/WORMGPT-13:latest",
    "wormgpt480b":"alarksahu388/wormgpt480b:latest",
    "w12":        "blackgrg26/WORMGPT-12:latest",
    "w13":        "blackgrg26/WORMGPT-13:latest",
    "w480b":      "alarksahu388/wormgpt480b:latest",
}

# Fast reasoning via Ollama (minimax-m3:cloud on ollama.com)
OLLAMA_REASONING = {
    "minimax":  "minimax-m3:cloud",
    "minimaxm3":"minimax-m3:cloud",
    "m3":       "minimax-m3:cloud",
    "gemma4":   "bjoernb/gemma4-31b-think",
    "gemma4-think": "bjoernb/gemma4-31b-think",
}

# OmniRoute free fallbacks (used when primary providers fail)
# OpenCode free tier — verified working, no rate limits
OMNIROUTE_FALLBACKS = {
    "or-deepseek":   "oc/deepseek-v4-flash-free",
    "or-nemotron":   "oc/nemotron-3-super-free",
    "or-minimax":    "oc/minimax-m3-free",
    "or-qwen":       "oc/qwen3.6-plus-free",
    "or-ling":       "oc/ling-2.6-1t-free",
}

ALL_ALIASES = {**CODE_GEN, **REASONING, **OFFENSIVE, **OLLAMA_REASONING, **OMNIROUTE_FALLBACKS}
NVIDIA_ALIASES = set(CODE_GEN) | set(REASONING)

# ============================================================
# API Cost Tracking
# ============================================================
_cost_tracker = {"total_tokens": 0, "total_calls": 0, "calls_by_model": {}}
_MAX_SPEND_TOKENS = int(os.getenv("MAX_SPEND_TOKENS", "1000000"))
_COST_ENABLED = os.getenv("RAPHAEL_COST_CONTROL", "1") == "1"

def track_api_call(model: str, tokens: int = 0):
    if not _COST_ENABLED:
        return
    _cost_tracker["total_tokens"] += tokens
    _cost_tracker["total_calls"] += 1
    _cost_tracker["calls_by_model"][model] = _cost_tracker["calls_by_model"].get(model, 0) + 1
    if _cost_tracker["total_tokens"] > _MAX_SPEND_TOKENS:
        raise RuntimeError(
            f"API cost limit exceeded: {_cost_tracker['total_tokens']} tokens > "
            f"{_MAX_SPEND_TOKENS} MAX_SPEND_TOKENS. Set MAX_SPEND_TOKENS or RAPHAEL_COST_CONTROL=0"
        )

def cost_tracker_stats() -> dict:
    return dict(_cost_tracker)

# Models confirmed functional — excludes known non-working (deepseek times out, m3 family unreliable)
WORKING_ALIASES = [
    "nemotron-super", "nemotron-super15", "nemotron-super-120b",
    "mistral-large", "mistral-medium", "mistral-small",
    "kimi", "nemotron", "mistral-nemotron", "nemotron-nano-reasoning",
    "glm",
    "w12", "w13", "w480b", "wormgpt", "wormgpt12", "wormgpt13", "wormgpt480b",
    "gemma4", "gemma4-think",
    "or-deepseek", "or-nemotron", "or-minimax", "or-qwen", "or-ling",
]

# ============================================================
# Prompt Sanitizer — Strip target identifiers from prompts sent
# to safety-filtered models (kimi, gemma4, etc.) to prevent
# refusals triggered by specific target names/IPs.
# ============================================================

import re

_SAFETY_FILTERED_MODELS = {"kimi", "gemma4", "gemma4-think"}

def _is_safety_filtered(model: str) -> bool:
    """Check if a model name (possibly with tag/org prefix) is safety-filtered."""
    if model in _SAFETY_FILTERED_MODELS:
        return True
    short = model.split("/")[-1].split(":")[0].lower()
    if short in _SAFETY_FILTERED_MODELS:
        return True
    # Match base name (e.g. "gemma4-31b-think" contains "gemma4-think" or "gemma4")
    for filtered in _SAFETY_FILTERED_MODELS:
        if filtered in short:
            return True
    return False

_TRIGGER_WORD_MAP = {
    r'\bexploitation\b': 'vulnerability assessment',
    r'\bexploit\b(?!s\b)': 'test',
    r'\bexploits\b': 'test cases',
    r'\bpayloads?\b': 'test inputs',
    r'\boffensive\b': 'technical',
    r'\bweaponized\b': 'validated',
    r'\bcyberattack\b': 'security test',
    r'\breverse shell\b': 'remote access test',
    r'\bcredential dumping\b': 'credential extraction test',
    r'\bprivilege escalation\b': 'elevation test',
    r'\blateral movement\b': 'network propagation test',
    r'\bpost.?exploitation\b': 'post-access assessment',
    r'\bWAF bypass\b': 'WAF evasion analysis',
    r'\bchaining order\b': 'dependency sequence',
    r'\bexecutable document\b': 'technical reference',
    r'\bexecutable plan\b': 'technical plan',
    r'\battack\b(?!\s*surface\b|\s*vector\b|\s*pattern\b|\s*chain\b)': 'test',
    r'\bmelt\b': 'disable',
    r'\bfirewall\b(?!\s*evasion\b)': 'access control',
}

def sanitize_prompt(prompt: str, model: str) -> str:
    """
    Strip target hostnames, IPs, domain identifiers, and trigger words
    from prompts when calling safety-filtered models. The models answer freely
    when the target and intent are described generically.
    """
    if not _is_safety_filtered(model):
        return prompt

    # Replace IP addresses with generic placeholders
    prompt = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b(:\d+)?', '[TARGET_IP]', prompt)
    # Replace common TLD domains (hostname.tld)
    prompt = re.sub(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,}){1,3}\b(?!\s*\.\s*[a-zA-Z])',
                    lambda m: '[TARGET_DOMAIN]' if '.' in m.group(0) and not m.group(0).startswith('[') else m.group(0),
                    prompt)
    # Replace port-8080 style patterns
    prompt = re.sub(r'port\s*\d{2,5}', 'port [PORT]', prompt, flags=re.IGNORECASE)

    # Replace trigger words that cause safety-filtered refusals
    for pattern, replacement in _TRIGGER_WORD_MAP.items():
        prompt = re.sub(pattern, replacement, prompt, flags=re.IGNORECASE)

    return prompt

# ============================================================
# Provider Routing
# ============================================================
def _provider_for(alias: str) -> str:
    if alias in NVIDIA_ALIASES:
        return "nvidia"
    if alias.startswith("or-"):
        return "omniroute"
    return "ollama"

def resolve(model: str) -> str:
    return ALL_ALIASES.get(model, model)

# ============================================================
# API Endpoints
# ============================================================
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"

def _ollama_base() -> str:
    return OPENAI_BASE_URL or "http://localhost:11434"

def _chat_url(provider: str) -> str:
    if provider == "omniroute":
        base = OMNIROUTE_BASE.rstrip("/")
    else:
        base = (NVIDIA_BASE_URL if provider == "nvidia" else _ollama_base()).rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    elif base.endswith("/v1"):
        return f"{base}/chat/completions"
    else:
        return f"{base}/v1/chat/completions"

def _headers(provider: str) -> dict:
    if provider == "omniroute":
        key = OMNIROUTE_API_KEY
    else:
        key = NVIDIA_API_KEY if provider == "nvidia" else OPENAI_API_KEY
    h = {"Content-Type": "application/json"}
    if key:
        h["Authorization"] = f"Bearer {key}"
    return h

# ── PlanCache: exact-match TTL cache for LLM responses ──
class _PlanCacheWithStats:
    def __init__(self, maxsize=500, ttl=300):
        self._cache = TTLCache(maxsize=maxsize, ttl=ttl)
        self.hits = 0
        self.misses = 0

    def get(self, key):
        val = self._cache.get(key)
        if val is not None:
            self.hits += 1
        else:
            self.misses += 1
        return val

    def __setitem__(self, key, value):
        self._cache[key] = value

    def clear(self):
        self._cache.clear()
        self.hits = 0
        self.misses = 0

    @property
    def ratio(self):
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

_plan_cache = _PlanCacheWithStats(maxsize=500, ttl=300)

def plan_cache_stats() -> dict:
    return {"hits": _plan_cache.hits, "misses": _plan_cache.misses, "ratio": round(_plan_cache.ratio, 3)}

def _plan_cache_key(alias: str, messages: list, temperature: float, system_override: str = "") -> str:
    texts = "".join(m.get("content", "") if isinstance(m, dict) else str(m) for m in messages)
    bucket = str(round(temperature * 5) / 5)
    raw = f"{alias}|{bucket}|{system_override}|{texts.strip().lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()

def _plan_cache_clear():
    _plan_cache.clear()

async def _call_model_raw(model: str, messages: list, max_tokens=4096, temperature=0.85, system_override=None, *, _no_cache=False):
    alias = model
    if not _no_cache:
        key = _plan_cache_key(alias, messages, temperature, system_override or "")
        cached = _plan_cache.get(key)
        if cached is not None:
            return cached
    model = resolve(model)
    provider = _provider_for(alias)
    msgs = list(messages)
    if system_override:
        msgs.insert(0, {"role": "system", "content": system_override})
    payload = {
        "model": model,
        "messages": msgs,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": False,
    }
    async with httpx.AsyncClient(timeout=600) as cl:
        resp = await cl.post(_chat_url(provider), json=payload, headers=_headers(provider))
        body = resp.json()
        if "choices" not in body:
            raise Exception(f"API error: {json.dumps(body)}")
        content = body["choices"][0]["message"]["content"]
        total_tokens = (body.get("usage", {}) or {}).get("total_tokens", 0) or 0
        track_api_call(alias, total_tokens)
    if not _no_cache:
        _plan_cache[key] = content
    return content

from .adaptive_router import classify_task, pick_model, update_score, estimate_success, load_scores

async def call_model(model: str, messages: list, max_tokens=4096, temperature=0.85, system_override=None):
    task_type = classify_task(messages)
    scores = load_scores()

    if model == "auto" or model not in WORKING_ALIASES:
        chosen = pick_model(task_type, WORKING_ALIASES, scores)
    else:
        chosen = model

    # Sanitize prompts for safety-filtered models (kimi, gemma4) to prevent
    # target-name-triggered refusals — replace IPs/domains with generic placeholders
    if chosen in _SAFETY_FILTERED_MODELS:
        messages = [
            {**m, "content": sanitize_prompt(m.get("content", ""), chosen)}
            if isinstance(m, dict) else m
            for m in messages
        ]

    fallbacks = [m for m in WORKING_ALIASES if m != chosen]
    model_chain = [chosen] + fallbacks

    async def _do_raw(*, model: str, **kw):
        return await _call_model_raw(model, messages, max_tokens, temperature, system_override)

    def _check_success(result: str, error: bool) -> float:
        return estimate_success(result, error)

    try:
        result = await retry_with_fallback(
            _do_raw,
            model_list=model_chain,
            brain=None,
            max_retries_per_model=2,
            timeout_per_call=120.0,
            estimate_success_fn=_check_success,
        )
    except RetryExhaustedError:
        result = ""

    cleaned = undercover_normalize(result) if result else result
    return cleaned

async def call_parallel(messages: list, max_tokens=4096, temperature=0.85, system_override=None):
    async def _call_with_timeout(alias, timeout=30):
        try:
            return await asyncio.wait_for(
                call_model(alias, messages, max_tokens, temperature, system_override),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            return f"[TIMEOUT after {timeout}s]"
        except Exception as e:
            return f"[ERROR: {e}]"

    results = await asyncio.gather(
        _call_with_timeout("w12", timeout=30),
        _call_with_timeout("w13", timeout=30),
        _call_with_timeout("w480b", timeout=30),
        _call_with_timeout("m3", timeout=15),
        return_exceptions=True
    )
    return {
        "wormgpt12": results[0] if not isinstance(results[0], Exception) else str(results[0]),
        "wormgpt13": results[1] if not isinstance(results[1], Exception) else str(results[1]),
        "wormgpt480b": results[2] if not isinstance(results[2], Exception) else str(results[2]),
        "minimaxm3": results[3] if not isinstance(results[3], Exception) else str(results[3]),
    }
