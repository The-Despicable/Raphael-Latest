#!/usr/bin/env python3
"""Community-mode implementation: 4 models code-generate Undercover + Retry in parallel."""

import asyncio, json, httpx, time, os

API_BASE = "https://integrate.api.nvidia.com/v1"
API_KEY = os.getenv("NVIDIA_API_KEY")
if not API_KEY:
    raise RuntimeError("NVIDIA_API_KEY environment variable required")

TEAM = {
    "glm-5.1": "z-ai/glm-5.1",
    "kimi-k2.6": "moonshotai/kimi-k2.6",
    "nemotron-ultra-550b": "nvidia/nemotron-3-ultra-550b-a55b",
}

CONTEXT = """RAPHAEL CODEBASE CONTEXT for code generation:

EXISTING orchestrator/providers.py (simplified):
- call_model(): wraps _call_model_raw(), single try/except, returns "" on error
- call_parallel(): asyncio.gather with 4 worm models, return_exceptions=True
- No retry logic anywhere
- Uses httpx.AsyncClient

EXISTING brain/adaptive_brain.py:
- Thompson sampling with Beta(alpha, beta) per model per context
- UCB scores
- Circuit breaker: 3 failures → 60s cooldown
- update_stats(success, latency) feeds back to priors
- pick_model() selects best model for context

EXISTING orchestrator/adaptive_router.py:
- classify_task() from message text
- update_score(model, task_type, success, latency) saves to JSON
- estimate_success(response_text, error_occurred) → 0.0-0.9

EXISTING sword/report.py:
- SwordReport class generates markdown/html reports from engagement results
- Uses LLM-generated text in reports that goes to saved files

EXISTING exfil/*.py, phishing/*.py:
- Mostly wrappers around external tools (GoPhish, EvilGinx, SET, DNS, SMTP)
- No direct LLM text generation in output paths

TASK 1: Write undercover.py
A utility that strips LLM attribution markers from generated text.
Must detect and remove: "As an AI", "I'd be happy to", "Certainly!", em-dashes, "delve", "robust", "navigate the complexities", "Great question", sentence length variance normalization, "It's worth noting", "Furthermore", "In conclusion", "ultimately", "However", boilerplate transitions.
Must include:
- normalize() function
- jitter function to vary sentence lengths slightly (LLMs are too consistent)
- Must NOT be detectable as "cleaned by a tool"
- ~120-180 lines, pure Python stdlib (re, random, string)

TASK 2: Write retry.py
An exponential backoff retry utility with jitter and model fallback.
Must include:
- async retry decorator/function
- Exponential backoff: 1s, 2s, 4s, 8s, max 30s
- Full jitter: random(0, delay)
- Model fallback list (tries next model if current fails)
- Respects circuit breaker (skip if circuit open)
- Updates brain stats on each attempt
- ~80-120 lines, uses httpx, asyncio

TASK 3: Show how to integrate
For undercover.py:
- Where to call normalize() in providers.py (after call_model succeeds, before returning)
- Where to call normalize() in sword/report.py (before saving reports)

For retry.py:
- How to replace the single try/except in providers.py call_model() with retry logic
- How model fallback integrates with adaptive_brain.py's pick_model()

Write ACTUAL Python code. Not pseudocode. I need to save these files directly."""

async def call_model(model_id, prompt, temperature=0.3, max_tokens=4096):
    async with httpx.AsyncClient(timeout=600) as cl:
        resp = await cl.post(
            f"{API_BASE}/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
            json={
                "model": model_id,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": temperature,
                "stream": False,
            }
        )
        body = resp.json()
        if "choices" not in body:
            return f"ERROR: {json.dumps(body)[:300]}"
        return body["choices"][0]["message"]["content"]

async def main():
    print("=" * 70)
    print("COMMUNITY MODE: Implementing Undercover + Retry")
    print(f"Team: {', '.join(TEAM.keys())}")
    print("=" * 70 + "\n")

    contributions = {}

    # Round 1: All 4 propose implementations
    print("▶ ROUND 1: Code Proposals\n")
    
    async def propose(name):
        t0 = time.time()
        result = await call_model(TEAM[name], CONTEXT, temperature=0.4)
        elapsed = time.time() - t0
        print(f"  {name} done ({elapsed:.0f}s)")
        return name, result

    tasks = [propose(name) for name in TEAM]
    done = await asyncio.gather(*tasks)
    for name, result in done:
        contributions[name] = result

    # Round 2: Cross-pollinate and fill gaps
    print("\n▶ ROUND 2: Cross-pollination\n")
    
    cross = ""
    for name, text in contributions.items():
        # Extract just the code sections
        cross += f"=== {name} ===\n{text}\n\n"
    
    round2_prompt = f"""All 4 proposals are below. Write a CRITIQUE of the approaches:

1. What code is good and should be kept?
2. What code is wrong or dangerous?
3. What's missing across all proposals?

Then write your IMPROVED version of undercover.py and retry.py combining the best ideas.

{cross}"""

    async def refine(name):
        t0 = time.time()
        result = await call_model(TEAM[name], round2_prompt, temperature=0.3, max_tokens=4096)
        elapsed = time.time() - t0
        print(f"  {name} round 2 done ({elapsed:.0f}s)")
        return name, result

    round2 = await asyncio.gather(*[refine(name) for name in TEAM])
    for name, result in round2:
        contributions[f"{name}_r2"] = result

    # Phase 3: kimi-k2.6 produces final files
    print("\n▶ ROUND 3: Final Synthesis\n")
    
    all_content = ""
    for name, text in contributions.items():
        all_content += f"=== {name} ===\n{text}\n\n"
    
    final_prompt = f"""You are the lead engineer. All proposals and critiques are below.

{all_content}

Your job: Produce the FINAL, definitive Python files.

Write them as ACTUAL files that can be saved directly:
1. undercover.py — complete, production-ready
2. retry.py — complete, production-ready
3. integration guide — where to hook each into providers.py and adaptive_brain.py

Rules:
- Pure Python stdlib (re, random, string, asyncio, httpx)
- No external dependencies beyond what Raphael already uses
- Clean code, single responsibility, no comments
- Undercover must strip: AI boilerplate, em-dashes, "delve/robust/navigate", sentence length normalization, "As an AI", "I'd be happy to", "Certainly!", "Great question", "It's worth noting", "Furthermore", "In conclusion", wordiness patterns
- Retry must: exp backoff 1-30s, full jitter, model fallback, respect circuit breaker, update brain stats

Output format:
```python
# undercover.py
[full code]
```

```python
# retry.py
[full code]
```

```python
# integration.py
[how to hook into providers.py and adaptive_brain.py]
```"""

    final = await call_model(TEAM["kimi-k2.6"], final_prompt, temperature=0.2, max_tokens=8192)
    
    print(final)
    
    # Save everything
    report = {
        "round1": {k: contributions[k] for k in TEAM},
        "round2": {f"{k}_r2": contributions[f"{k}_r2"] for k in TEAM},
        "final_synthesis": final,
    }
    with open("/home/yaser/Ultimate skill/raphael-2.0/orchestrator/community_impl_report.json", "w") as f:
        json.dump(report, f, indent=2)
    with open("/home/yaser/Ultimate skill/raphael-2.0/orchestrator/community_impl_final.md", "w") as f:
        f.write(final)
    print("\nSaved to community_impl_report.json and community_impl_final.md")

asyncio.run(main())
