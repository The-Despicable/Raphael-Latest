#!/usr/bin/env python3
"""Reasoning team analysis of the hallucination corpus + my own synthesis."""
import asyncio, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator.teams import analyze
from config.paths import get_base_dir

CORPUS_SUMMARY = """LLM Hallucination Research Corpus (15 sources from Red Hat article):

[1] Red Hat: Mitigations = fine-tuning(InstructLab) + RAG + CoT/few-shot + guardrails
[2] arxiv 2406.10279: 5.2% comm / 21.7% OSS package hallucination, 205k unique fake packages
[3] Lasso Security: GPT-4 24.2%, GPT-3.5 22.2%, Gemini 64.5%, Cohere 29.1%; 30k real downloads of fake "huggingface-cli"
[4] Wikipedia: Typosquatting — URLs exploiting typos; malware delivery
[5] arxiv 2311.15548: Finance LLMs hallucinate concepts & stock prices
[6] Walters v. OpenAI lawsuit PDF (403'd) — legal consequences of hallucinations
[7] arxiv 2401.11817: Hallucination is mathematically inevitable — no computable LLM can learn all ground-truth
[8] arxiv 2401.03205: HaluEval 2.0 benchmark; detection, source, mitigation study
[9] arxiv 2306.06085: Tagged context prompts eliminated 98.88% of hallucinations
[10] github.com/instructlab: Red Hat/IBM open-source fine-tuning via taxonomy curation
[11] Red Hat RAG page: 3-stage pipeline (ETL → vector DB → generation); vLLM + MCP
[12] Wikipedia: BERT encoder-only transformer; RAG embedding backbone
[13] arxiv 2201.11903: CoT prompting — 540B PaLM + 8 exemplars → SOTA on GSM8K
[14] arxiv 2005.14165: GPT-3 175B — scaling improves few-shot performance
[15] RHEL AI dev page (403'd) — closing CTA reference

TASK: Given Raphael 2.0 is an autonomous AI security framework that generates offensive security code, produces reports, and uses a critic/judge module for self-correction — what practical changes should be made to (a) the critic/judge, (b) code generation pipeline, (c) model selection, and (d) report generation to address the hallucination findings above?"""

MY_ANALYSIS = """## My Analysis (for comparison with reasoning team)

### (a) Critic/Judge Changes
The critic (`orchestrator/critic.py`) currently does a single LLM call to validate phase outputs. Key gaps:
- **No package verification**: After any code-gen phase, extracted package names should hit PyPI/NPM registries (addresses [2][3])
- **No source grounding check**: The critic should cross-check factual claims against retrieved context, not just judge coherence (addresses [9][11])
- **No cross-model consensus**: Run critic through 2 models and flag disagreement (addresses [3] — Gemini 64.5% means single-model critic is unreliable)
- **No "I don't know" pathway**: The critic should be allowed to abstain (addresses [7] — inevitability means forcing an answer is dangerous)

### (b) Code Generation Pipeline
- **Add tagged context wrapping**: Before sending code-gen prompts, wrap retrieved package manifests/sboms in XML tags per [9]
- **Add post-generation verification step**: Parse imports, verify each against registry API, reject unverifiable packages
- **Add typosquatting detection**: Levenshtein distance ≤ 2 from top-10K packages → flag

### (c) Model Selection
- **Reject Gemini for anything in the pipeline** (64.5% is catastrophic for a security tool)
- **Run critic as ensemble**: nemotron-super (reasoning-focused) + kimi (synthesis) — if they disagree, flag for human

### (d) Report Generation
- **Confidence scoring**: Every claim should have a confidence label: VERIFIED | GROUNDED (source attached) | SPECULATIVE | UNKNOWN
- **Source tracing**: Every factual statement should cite which corpus source supports it
- **Explicit uncertainty**: The "Hallucination is Inevitable" [7] result means reports should include a "known limitations" section

### Summary
The tagged context paper [9] is the single highest-impact finding (98.88% reduction) and should be the first thing implemented in Raphael's prompt assembly. The inevitability proof [7] means we should stop trying to eliminate hallucinations and instead architect for detection + graceful degradation."""

async def main():
    print("=" * 60)
    print("REASONING TEAM ANALYSIS")
    print("(nemotron-super → mistral-large → kimi → minimax)")
    print("=" * 60)
    result = await analyze(CORPUS_SUMMARY)
    print(f"\nModel used: {result.get('model', '?')} ({result.get('elapsed', '?')}s)")
    print(f"\nResponse:\n{result.get('response', 'N/A')}")
    
    print("\n" + "=" * 60)
    print("MY ANALYSIS (for comparison)")
    print("=" * 60)
    print(MY_ANALYSIS)
    
    out_path = get_base_dir() / "reasoning_team_analysis.json"
    out_path.write_text(json.dumps({
        "reasoning_team": result,
        "my_analysis": MY_ANALYSIS,
        "corpus_sources": 15,
        "note": "Reasoning team uses nemotron-super primary with mistral-large/kimi/minimax fallbacks"
    }, indent=2, default=str))
    print(f"\n[*] Saved to {out_path}")

if __name__ == "__main__":
    asyncio.run(main())
