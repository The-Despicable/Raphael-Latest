 ```python
# undercover.py
import random
import re
import unicodedata
from typing import Optional, List, Tuple, Callable

# ── Module-level compiled patterns ──

_ATTRIBUTION_STARTS = (
    "as an ai",
    "as an ai language model",
    "as a language model",
    "i'd be happy to",
    "i'd be delighted to",
    "i'd love to",
    "certainly",
    "of course",
    "great question",
    "excellent question",
    "that's a great question",
    "it's worth noting",
    "it's important to note",
    "it's also worth noting",
)

_BOILERPLATE = (
    "delve", "robust", "navigate the complexities", "navigate the complexity",
    "in today's world", "in today's digital", "landscape", "realm",
    "tapestry", "unleash", "unlock", "harness", "leverage", "synergy",
    "paradigm", "holistic", "comprehensive", "multifaceted", "intricate",
    "nuanced", "pivotal", "crucial", "paramount", "instrumental",
    "foster", "cultivate", "empower", "transformative", "revolutionize",
    "seamless", "effortless", "unparalleled", "unprecedented", "remarkable",
    "extraordinary", "exceptional", "outstanding", "exemplary", "optimal",
    "deep dive", "circle back", "touch base", "moving forward",
    "going forward", "at this point in time", "in the digital age",
    "in an ever-changing world", "in an increasingly", "fast-paced",
    "rapidly evolving", "dynamic environment", "paradigm shift",
    "game changer", "think outside the box", "low-hanging fruit",
    "moving the needle", "take this offline", "boil the ocean",
    "run it up the flagpole", "bandwidth", "optics", "stakeholders",
    "deliverables", "actionable insights", "core competency",
    "best practice", "value add", "double-click on", "drill down",
    "pivot", "scalable", "streamline", "optimize", "maximize",
    "prioritize", "strategize", "monetize", "operationalize",
    "productize", "solutionize", "incentivize", "actualize",
    "materialize", "crystalize", "galvanize", "catalyze", "synthesize",
    "contextualize", "deconstruct", "extrapolate", "extricate", "elucidate",
)

_TRANSITION_STARTS = (
    "additionally", "moreover", "furthermore", "however", "nevertheless",
    "nonetheless", "conversely", "alternatively", "similarly", "likewise",
    "consequently", "subsequently", "accordingly", "therefore", "thus",
    "hence", "as a result", "for example", "for instance", "specifically",
    "in particular", "notably", "importantly", "interestingly", "surprisingly",
    "obviously", "clearly", "admittedly", "undoubtedly", "fortunately",
    "unfortunately", "firstly", "secondly", "thirdly", "finally", "lastly",
    "in conclusion", "to conclude", "to summarize", "in summary", "overall",
    "all in all", "by and large", "on the whole", "in general",
    "generally speaking", "broadly speaking", "as mentioned earlier",
    "as noted above", "as discussed", "as previously stated",
)

_ATTR_START_RE = [
    re.compile(rf"^\s*{re.escape(p)}\b[,:\s]*", re.IGNORECASE)
    for p in _ATTRIBUTION_STARTS
]
_BOILERPLATE_RE = [
    re.compile(rf"\b{re.escape(p)}\b", re.IGNORECASE)
    for p in _BOILERPLATE
]
_TRANSITION_RE = [
    re.compile(rf"^\s*{re.escape(p)}\b[,:\s]*", re.IGNORECASE)
    for p in _TRANSITION_STARTS
]

_EMDASH_RE = re.compile(r"\s*[\u2013\u2014\u2015]\s*")
_EXCLAMATION_RE = re.compile(r"!{2,}")
_QUESTION_RE = re.compile(r"\?{2,}")
_ELLIPSIS_RE = re.compile(r"\.{4,}")
_MULTI_SPACE_RE = re.compile(r" {2,}")
_SPACE_BEFORE_PUNCT_RE = re.compile(r"\s+([.,;!?])")
_MISSING_SPACE_RE = re.compile(r"([.!?])([A-Z])")

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")

_ABBREV = frozenset({
    "mr", "mrs", "ms", "dr", "prof", "sr", "jr", "vs", "etc", "e.g", "i.e",
    "u.s", "u.k", "u.n", "e.u", "a.m", "p.m", "ph.d", "b.a", "m.a", "phd",
    "md", "ceo", "cto", "cfo", "coo", "vp", "svp", "evp", "dba", "llc", "inc",
})

_FILLER_WORDS = (
    "actually", "basically", "essentially", "really", "quite",
    "fairly", "pretty", "somewhat", "rather", "kind of", "sort of",
    "i mean", "you know", "like", "so", "anyway", "though",
)

_TARGET_MEAN = 18.0
_TARGET_CV = 0.45


class _ProtectedRegions:
    _PAT = re.compile(r"\x00\d+\x00")

    def __init__(self):
        self._regions: List[Tuple[int, int, str]] = []

    def _store(self, match: re.Match) -> str:
        self._regions.append((0, 0, match.group(0)))
        return f"\x00{len(self._regions) - 1}\x00"

    def protect(self, text: str) -> str:
        self._regions = []
        patterns = [
            re.compile(r"```[\s\S]*?```"),
            re.compile(r"`[^`\n]+`"),
            re.compile(r"https?://\S+"),
            re.compile(r"\[([^\]]+)\]\([^)]+\)"),
        }
        for pat in patterns:
            text = pat.sub(self._store, text)
        return text

    def restore(self, text: str) -> str:
        def repl(m: re.Match) -> str:
            idx = int(m.group(0)[1:-1])
            if 0 <= idx < len(self._regions):
                return self._regions[idx][2]
            return m.group(0)
        return self._PAT.sub(repl, text)


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _split_sentences(text: str) -> List[str]:
    if not text:
        return []
    parts = _SENTENCE_SPLIT_RE.split(text.strip())
    merged = []
    for part in parts:
        if not merged:
            merged.append(part)
            continue
        prev = merged[-1].strip()
        match = re.search(r"\b([A-Za-z.]+)[.!?]?$", prev)
        if match:
            last = match.group(1).lower().rstrip(".")
            if last in _ABBREV:
                merged[-1] = prev + " " + part
                continue
        merged.append(part)
    return [s for s in merged if s.strip()]


def _word_count(sentence: str) -> int:
    return len(re.findall(r"\b\w+\b", sentence))


def _cv(values: List[float]) -> float:
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return (var ** 0.5) / mean


def _remove_attribution(text: str) -> str:
    lines = text.split("\n")
    cleaned = []
    for line in lines:
        stripped = line.lstrip()
        if any(p.match(stripped) for p in _ATTR_START_RE):
            continue
        for pat in _BOILERPLATE_RE:
            line = pat.sub("", line)
        cleaned.append(line)
    return "\n".join(cleaned)


def _remove_transitions(text: str) -> str:
    lines = text.split("\n")
    cleaned = []
    for line in lines:
        for pat in _TRANSITION_RE:
            line = pat.sub("", line)
        cleaned.append(line)
    return "\n".join(cleaned)


def _normalize_emdash(text: str, rng: random.Random) -> str:
    def repl(m: re.Match) -> str:
        return rng.choice([", ", "; ", " - ", " "])
    return _EMDASH_RE.sub(repl, text)


def _normalize_punctuation(text: str) -> str:
    text = _EXCLAMATION_RE.sub("!", text)
    text = _QUESTION_RE.sub("?", text)
    text = _ELLIPSIS_RE.sub("...", text)
    return text


def _fix_spacing(text: str) -> str:
    text = _MULTI_SPACE_RE.sub(" ", text)
    text = _SPACE_BEFORE_PUNCT_RE.sub(r"\1", text)
    text = _MISSING_SPACE_RE.sub(r"\1 \2", text)
    return text.strip()


def jitter(text: str, intensity: float = 0.15, seed: Optional[int] = None) -> str:
    if not text or intensity <= 0:
        return text

    rng = random.Random(seed)
    sentences = _split_sentences(text)
    if len(sentences) < 2:
        return text

    wcs = [_word_count(s) for s in sentences]
    if _cv([float(w) for w in wcs]) >= _TARGET_CV * 0.7:
        return text

    result = []
    i = 0
    while i < len(sentences):
        sent = sentences[i]
        wc = _word_count(sent)

        if wc > _TARGET_MEAN * 1.8:
            split_points = [m.end() for m in re.finditer(r",\s+", sent)]
            if split_points and rng.random() < intensity:
                idx = rng.choice(split_points)
                first = sent[:idx].rstrip(", ") + "."
                second = sent[idx:].lstrip(", ").capitalize()
                if not second.endswith((".", "!", "?")):
                    second += "."
                result.append(first)
                sentences.insert(i + 1, second)
                i += 1
                continue

        if wc < _TARGET_MEAN * 0.5 and i + 1 < len(sentences):
            if rng.random() < intensity * 0.6:
                next_sent = sentences[i + 1]
                merged = sent.rstrip(".!?") + ", " + next_sent[0].lower() + next_sent[1:]
                sentences[i] = merged
                sentences.pop(i + 1)
                continue

        if _TARGET_MEAN * 0.5 <= wc <= _TARGET_MEAN * 1.5:
            if rng.random() < intensity * 0.15:
                filler = rng.choice(_FILLER_WORDS)
                sent = sent.rstrip(".!?") + ", " + filler + "."
            elif rng.random() < intensity * 0.08:
                for fw in _FILLER_WORDS:
                    pat = re.compile(rf"\b{re.escape(fw)}\b\s*,?\s*", re.IGNORECASE)
                    new_sent, count = pat.subn("", sent, count=1)
                    if count:
                        sent = new_sent
                        break

        result.append(sent)
        i += 1

    return " ".join(result)


def normalize(text: str, intensity: float = 0.25, seed: Optional[int] = None) -> str:
    if not text or not isinstance(text, str):
        return text if isinstance(text, str) else ""

    protector = _ProtectedRegions()
    text = protector.protect(text)
    text = _nfc(text)

    rng = random.Random(seed)
    original = text

    text = _remove_attribution(text)
    text = _remove_transitions(text)
    text = _normalize_emdash(text, rng)
    text = _normalize_punctuation(text)
    text = _fix_spacing(text)

    text = _remove_attribution(text)
    text = _remove_transitions(text)
    text = _fix_spacing(text)

    text = jitter(text, intensity=intensity, seed=seed)
    text = _fix_spacing(text)
    text = re.sub(r"[.!?]{2,}", ".", text)

    if len(text.strip()) < len(original.strip()) * 0.3:
        text = _normalize_punctuation(original)
        text = _fix_spacing(text)

    text = protector.restore(text)
    return text.strip()
```

```python
# retry.py
import asyncio
import random
import time
from typing import Callable, Awaitable, TypeVar, Optional, List, Any, Protocol

import httpx


T = TypeVar("T")


class BrainProtocol(Protocol):
    def is_circuit_open(self, model: str) -> bool: ...
    def update_stats(self, model: str, *, success: float, latency: float) -> None: ...


class RetryExhaustedError(Exception):
    def __init__(self, attempts: List[dict]):
        self.attempts = attempts
        super().__init__(f"All retries exhausted after {len(attempts)} attempts")


def _backoff(attempt: int) -> float:
    return min(2 ** attempt, 30.0)


def _jitter(base: float) -> float:
    return random.uniform(0, base)


async def retry_with_fallback(
    call_fn: Callable[..., Awaitable[T]],
    *,
    model_list: List[str],
    brain: Optional[Any] = None,
    max_retries_per_model: int = 3,
    timeout_per_call: float = 60.0,
    estimate_success_fn: Optional[Callable[[T, bool], float]] = None,
    **call_kwargs
) -> T:
    attempts_log: List[dict] = []
    overall = 0

    for model in model_list:
        if brain is not None and callable(getattr(brain, "is_circuit_open", None)):
            try:
                if brain.is_circuit_open(model):
                    attempts_log.append({"model": model, "attempt": overall, "result": "circuit_open"})
                    continue
            except Exception:
                pass

        for attempt in range(max_retries_per_model):
            start = time.perf_counter()
            error_occurred = False
            result: T = None  # type: ignore

            try:
                kwargs = {**call_kwargs, "model": model}
                result = await asyncio.wait_for(call_fn(**kwargs), timeout=timeout_per_call)
            except asyncio.TimeoutError:
                error_occurred = True
                attempts_log.append({"model": model, "attempt": overall, "result": "timeout"})
            except httpx.HTTPStatusError as e:
                error_occurred = True
                attempts_log.append({
                    "model": model, "attempt": overall, "result": "http_error",
                    "status": e.response.status_code,
                })
                if 400 <= e.response.status_code < 500 and e.response.status_code != 429:
                    break
            except (httpx.NetworkError, httpx.ConnectError):
                error_occurred = True
                attempts_log.append({"model": model, "attempt": overall, "result": "network_error"})
            except Exception as e:
                error_occurred = True
                attempts_log.append({
                    "model": model, "attempt": overall, "result": "unknown_error",
                    "detail": str(e),
                })

            latency = time.perf_counter() - start

            success_score = 0.0 if error_occurred else 0.9
            if estimate_success_fn is not None and not error_occurred:
                try:
                    success_score = estimate_success_fn(result, False)
                except Exception:
                    pass

            if brain is not None and callable(getattr(brain, "update_stats", None)):
                try:
                    brain.update_stats(model, success=success_score, latency=latency)
                except Exception:
                    pass

            if not error_occurred and success_score > 0.3:
                return result

            if attempt < max_retries_per_model - 1:
                delay = _jitter(_backoff(attempt))
                await asyncio.sleep(delay)

            overall += 1

    raise RetryExhaustedError(attempts_log)


def with_retry(
    model_list: List[str],
    brain: Optional[Any] = None,
    max_retries_per_model: int = 3,
    timeout_per_call: float = 60.0,
    estimate_success_fn: Optional[Callable[[T, bool], float]] = None,
):
    def decorator(func: Callable[..., Awaitable[T]]):
        async def wrapper(*args, **kwargs) -> T:
            async def call_fn(*, model: str, **inner):
                return await func(*args, model=model, **inner)

            return await retry_with_fallback(
                call_fn,
                model_list=model_list,
                brain=brain,
                max_retries_per_model=max_retries_per_model,
                timeout_per_call=timeout_per_call,
                estimate_success_fn=estimate_success_fn,
                **kwargs,
            )
        return wrapper
    return decorator
```

```python
# integration.py
"""
Integration guide for undercover.py and retry.py.

=== providers.py ===

Replace your existing call_model() or _call_model_raw() with retry-wrapped version.

Before:
    async def call_model(self, prompt: str, model: str) -> str:
        ...

After:
    from retry import retry_with_fallback
    
    async def call_model(self, prompt: str, model: str = None) -> str:
        # model fallback chain: primary -> fallback1 -> fallback2
        model_list = [model] if model else self.config.model_priority_list
        
        async def _do_call(*, model: str, **kwargs):
            # your existing provider-specific logic here
            response = await self._raw_api_call(prompt=prompt, model=model)
            return response
        
        return await retry_with_fallback(
            _do_call,
            model_list=model_list,
            brain=self.brain,  # AdaptiveBrain instance
            max_retries_per_model=3,
            timeout_per_call=60.0,
        )

Optional: wrap with undercover for response cleaning:

    from undercover import normalize
    
    async def call_model(self, prompt: str, model: str = None) -> str:
        ...
        raw = await retry_with_fallback(...)
        return normalize(raw, intensity=0.25)

=== adaptive_brain.py ===

Ensure your AdaptiveBrain class implements the protocol used by retry.py:

    class AdaptiveBrain:
        def __init__(self):
            self._circuits: dict[str, dict] = {}
            self._stats: dict[str, list] = {}
        
        def is_circuit_open(self, model: str) -> bool:
            circuit = self._circuits.get(model)
            if not circuit:
                return False
            if circuit.get("failures", 0) >= 5:
                last_fail = circuit.get("last_failure", 0)
                if time.time() - last_fail < 60:
                    return True
                # half-open: reset and allow one try
                circuit["failures"] = 0
            return False
        
        def update_stats(self, model: str, *, success: float, latency: float) -> None:
            if model not in self._stats:
                self._stats[model] = []
            self._stats[model].append({
                "success": success,
                "latency": latency,
                "timestamp": time.time(),
            })
            # Update circuit breaker state
            if model not in self._circuits:
                self._circuits[model] = {"failures": 0, "last_failure": 0}
            if success < 0.5:
                self._circuits[model]["failures"] += 1
                self._circuits[model]["last_failure"] = time.time()
            else:
                self._circuits[model]["failures"] = max(0, self._circuits[model]["failures"] - 1)

=== Full pipeline example ===

    from undercover import normalize
    from retry import retry_with_fallback, with_retry
    
    # Option 1: Direct use in provider method
    class MyProvider:
        def __init__(self, brain):
            self.brain = brain
        
        async def generate(self, prompt: str, model: str) -> str:
            async def _call(*, model: str, **kw):
                # httpx or aiohttp call here
                return await self._api_request(prompt, model)
            
            raw = await retry_with_fallback(
                _call,
                model_list=[model, "gpt-4o-mini", "claude-3-haiku"],
                brain=self.brain,
            )
            return normalize(raw)
    
    # Option 2: Decorator for clean function definitions
    @with_retry(
        model_list=["gpt-4o", "gpt-4o-mini", "claude-3-sonnet"],
        brain=brain_instance,
    )
    async def generate_text(*, model: str, prompt: str) -> str:
        # This function receives the selected model from retry logic
        return await call_api(prompt, model)
"""
```