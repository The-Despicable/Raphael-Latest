#!/usr/bin/env python3
"""
Fleet analysis: call ALL models (NVIDIA + Ollama + OmniRoute) on the same question,
then synthesize the best answer.

Usage:
    python3 orchestrator/fleet_analysis.py [--output /tmp/fleet_result.json]
"""
import asyncio, json, sys, os, time, logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from orchestrator.providers import _call_model_raw, ALL_ALIASES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("fleet")

FLEET_MODELS = [
    # NVIDIA reasoning
    "kimi", "nemotron-super", "nemotron-super15", "mistral-large",
    "mistral-medium", "nemotron-nano-reasoning", "mistral-nemotron",
    # NVIDIA code-gen
    "deepseek", "glm", "nemotron", "nemotron-super-120b", "mistral-small",
    # Ollama
    "minimax", "gemma4",
    # Offensive
    "w12", "w13", "w480b",
    # OmniRoute fallbacks
    "or-deepseek", "or-nemotron", "or-minimax", "or-qwen", "or-ling",
]

QUESTION = """Analyze the 18 HTB Insane walkthroughs from the knowledge base.
For EACH machine, extract the specific techniques, CVEs, and tools required.
Then produce a PRIORITIZED BUILD LIST of missing capabilities for Raphael 2.0.

Group missing capabilities into:
1. QUICK_WIN: wrapper around existing kali-tools binary (< 100 LOC)
2. NEW_MODULE: custom Python module needed (100-300 LOC)  
3. INFRA: new containers/services needed (> 300 LOC)

For each item include:
- technique name
- which boxes need it
- estimated LOC
- priority (critical/high/medium/low)

Output format: valid JSON with keys: analysis, build_list[], summary"""


async def call_model(alias: str, model_name: str, timeout: int = 180) -> dict:
    t0 = time.time()
    msgs = [{"role": "user", "content": QUESTION}]
    try:
        result = await asyncio.wait_for(
            _call_model_raw(alias, msgs, max_tokens=4096, temperature=0.7),
            timeout=timeout,
        )
        elapsed = time.time() - t0
        return {"alias": alias, "model": model_name, "success": True, "response": result, "elapsed": round(elapsed, 1)}
    except asyncio.TimeoutError:
        return {"alias": alias, "model": model_name, "success": False, "error": "timeout", "elapsed": timeout}
    except Exception as e:
        return {"alias": alias, "model": model_name, "success": False, "error": str(e)[:100], "elapsed": round(time.time() - t0, 1)}


async def main():
    output_file = "/tmp/fleet_analysis.json"
    for i, a in enumerate(sys.argv):
        if a == "--output" and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]

    # Resolve model names
    models_to_call = []
    for alias in FLEET_MODELS:
        if alias in ALL_ALIASES:
            models_to_call.append((alias, ALL_ALIASES[alias]))
        else:
            logger.warning(f"Alias '{alias}' not found in ALL_ALIASES")

    logger.info(f"Fleet: {len(models_to_call)} models")
    results = await asyncio.gather(*[call_model(a, m) for a, m in models_to_call])

    successes = [r for r in results if r.get("success")]
    failures = [r for r in results if not r.get("success")]

    logger.info(f"Success: {len(successes)}/{len(results)}  Failures: {len(failures)}")

    # Build synthesis context from all successful responses
    all_responses = "\n\n".join(
        f"=== {r['alias']} ({r['model']}) ===\n{r['response'][:3000]}"
        for r in successes
    )

    # Synthesize using kimi (best reasoning)
    synthesis = ""
    if "kimi" in ALL_ALIASES:
        try:
            synthesis_msgs = [{"role": "user", "content": (
                f"[FLEET SYNTHESIS]\n\nBelow are {len(successes)} model responses analyzing "
                f"the same question about HTB Insane walkthrough gaps.\n\n{all_responses}\n\n"
                f"Now produce a SINGLE decisive prioritized build list as JSON. "
                f"Resolve disagreements. Focus on actionable items."
            )}]
            syn = await asyncio.wait_for(
                _call_model_raw("kimi", synthesis_msgs, max_tokens=4096, temperature=0.3),
                timeout=300,
            )
            synthesis = syn
        except Exception as e:
            synthesis = f"[Synthesis failed: {e}]"

    output = {
        "question": QUESTION,
        "models_called": len(models_to_call),
        "successful": len(successes),
        "failed": len(failures),
        "individual_results": successes,
        "synthesis": synthesis,
    }

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nSaved to {output_file}")
    print(f"\n=== SYNTHESIS ===\n{synthesis[:3000]}")

    # Print per-model latency
    print(f"\n=== MODEL PERFORMANCE ===")
    for r in sorted(successes, key=lambda x: x["elapsed"]):
        print(f"  {r['alias']:25s} {r['elapsed']:5.1f}s  {'✓' if r['success'] else '✗'}")

if __name__ == "__main__":
    asyncio.run(main())
