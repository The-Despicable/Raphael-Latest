#!/usr/bin/env python3
"""mistral + kimi + gemma4 + me on the hallucination corpus."""
import asyncio, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from config.paths import get_base_dir
from orchestrator.providers import call_model, call_parallel, resolve

CORPUS = """LLM Hallucination Research Corpus (15 sources from Red Hat article):

[1] Red Hat: Mitigations = fine-tuning(InstructLab) + RAG + CoT/few-shot + guardrails
[2] arxiv 2406.10279: 5.2% comm / 21.7% OSS package hallucination, 205k unique fake packages, 576k code samples across 16 LLMs
[3] Lasso Security: GPT-4 24.2%, GPT-3.5 22.2%, Gemini 64.5%, Cohere 29.1%; fake "huggingface-cli" got 30k+ real downloads; 215 packages hallucinated across ALL models
[4] Wikipedia: Typosquatting — URLs exploiting typos; malware delivery; Diesel Vortex campaign (Feb 2026) stole 1600+ creds
[5] arxiv 2311.15548: Finance LLMs hallucinate concepts & stock prices; few-shot/DoLa/RAG/tool-learning tested
[6] Walters v. OpenAI lawsuit PDF (403'd) — legal consequences of hallucinations cited in article
[7] arxiv 2401.11817: Hallucination is mathematically inevitable — no computable LLM can learn all computable ground-truth functions
[8] arxiv 2401.03205: HaluEval 2.0 benchmark; systematic study on detection, source, and mitigation
[9] arxiv 2306.06085: Tagged context prompts eliminated 98.88% of hallucinations using XML-like tags
[10] github.com/instructlab: Red Hat/IBM open-source LLM fine-tuning via taxonomy curation; recently refactored into separate component repos
[11] Red Hat RAG page: 3-stage pipeline (ETL → chunking/embedding → vector DB retrieval → generation); vLLM for inference, MCP for standardization
[12] Wikipedia: BERT encoder-only transformer; 110M-340M params; backbone for RAG embeddings
[13] arxiv 2201.11903: CoT prompting — 540B PaLM + 8 exemplars → SOTA on GSM8K
[14] arxiv 2005.14165: GPT-3 175B — scaling improves few-shot performance
[15] RHEL AI dev page (403'd) — closing CTA reference in article

TASK: Given Raphael 2.0 is an autonomous AI security framework that generates offensive security code, produces engagement reports, and uses a critic/judge module for self-correction — what practical code-level changes should be made to (a) the critic/judge, (b) code generation pipeline, (c) model selection, and (d) report generation? Be specific about file paths, function signatures, and implementation details."""

MY_ANALYSIS = """## My Analysis

### (a) Critic/Judge — orchestrator/critic.py
Current `judge()` does a single LLM call for validation. Changes needed:
1. **Package verification hook**: After any phase that generates code, extract all import/require statements via regex, call PyPI/NPM JSON API for each. If package doesn't exist in registry → reject the output.
2. **Source grounding cross-check**: Before calling the judge LLM, construct a RAG context from known-good documentation (retrieved via vector DB). The judge prompt must include: "Only accept claims that are explicitly supported by the provided context."
3. **Ensemble judge**: Run validation through 2 models (nemotron-super + kimi). If they disagree → flag for human review rather than auto-accepting.
4. **Confidence threshold**: Add `abstain` return path — if confidence < 0.6, return "CANNOT_VERIFY" instead of forcing a pass/fail.

### (b) Code Generation Pipeline — orchestrator/exploit/pipeline.py
1. **Tagged context wrapping**: Wrap retrieved package manifests/SBOMs in `<verified_packages>` XML tags per [9] before injecting into generation prompt.
2. **Post-generation import scanner**: New function `verify_imports(code: str) -> List[str]` that parses `import X`, `from X import`, `require('X')` and checks each against live registry API.
3. **Typosquatting filter**: Levenshtein distance ≤ 2 against top-10K packages → add warning annotation to output.
4. **Reject Gemini**: If model config resolves to Gemini → refuse and fall back to mistral-large.

### (c) Model Selection
- **Gemini**: Banned from all pipeline roles (64.5% hallucination is unacceptable for a security tool).
- **Critic ensemble**: mistral-large (reasoning-heavy) + kimi (synthesis) with disagreement → human.
- **Code gen**: nemotron-super with RAG grounding; never allow open-loop generation.

### (d) Report Generation
- Every claim tagged: `[VERIFIED]`, `[GROUNDED: source_11]`, `[SPECULATIVE]`, or `[UNKNOWN]`.
- Append "Known Limitations" section referencing [7] — inevitability proof.
- Package recommendations include `[CONFIRMED: pypi.org/project/X]` annotation."""

async def call_one(alias, messages, timeout=120):
    try:
        return await asyncio.wait_for(
            call_model(alias, messages, max_tokens=4096, temperature=0.7),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR: {e}]"

async def main():
    prompt = f"Research corpus:\n\n{CORPUS}\n\nProvide structured analysis covering (a) critic/judge, (b) code gen pipeline, (c) model selection, (d) report generation. Be specific."

    print("[*] Running mistral, kimi, and gemma4 in parallel...")
    results = await asyncio.gather(
        call_one("mistral-large", [{"role": "user", "content": prompt}]),
        call_one("kimi", [{"role": "user", "content": prompt}]),
        call_one("gemma4", [{"role": "user", "content": prompt}]),
        return_exceptions=True
    )
    
    mistral_out = results[0] if not isinstance(results[0], Exception) else str(results[0])
    kimi_out = results[1] if not isinstance(results[1], Exception) else str(results[1])
    gemma4_out = results[2] if not isinstance(results[2], Exception) else str(results[2])
    
    print("=" * 60)
    print(f"MISTRAL-LARGE ({resolve('mistral-large')})")
    print("=" * 60)
    print(mistral_out)
    
    print("\n" + "=" * 60)
    print(f"KIMI ({resolve('kimi')})")
    print("=" * 60)
    print(kimi_out)
    
    print("\n" + "=" * 60)
    print(f"GEMMA4-31B-THINK ({resolve('gemma4')})")
    print("=" * 60)
    print(gemma4_out)
    
    print("\n" + "=" * 60)
    print("ME")
    print("=" * 60)
    print(MY_ANALYSIS)
    
    out = get_base_dir() / "reasoning_team_mistral_kimi_gemma4_me.json"
    out.write_text(json.dumps({
        "mistral-large": mistral_out,
        "kimi": kimi_out,
        "gemma4": gemma4_out,
        "my_analysis": MY_ANALYSIS
    }, indent=2, default=str))
    print(f"\n[*] Saved to {out}")

if __name__ == "__main__":
    asyncio.run(main())
