#!/usr/bin/env python3
"""
Run Raphael community mode against ALL 15 article-body links (fresh fetch).
"""
import asyncio, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator.modes import community

PROMPT = """You are an expert research analyst. Analyze the following corpus of 15 sources on LLM hallucinations, freshly fetched from the Red Hat article's embedded links.

=== COMPLETE CORPUS (15 SOURCES) ===

[1] RED HAT MAIN ARTICLE: "When LLMs Day-Dream: Hallucinations and How to Prevent Them"
    https://www.redhat.com/en/blog/when-llms-day-dream-hallucinations-how-prevent-them
    Four mitigations: fine-tuning (InstructLab), RAG, advanced prompting (CoT, few-shot), guardrails.

[2] PAPER: "We Have a Package for You!" (cs.SE, USENIX Security 2025) — arxiv 2406.10279
    Authors: Spracklen, Wijewickrama, Sakib, Maiti, Viswanath, Jadliwala
    576k code samples across 16 LLMs. Avg hallucinated packages: 5.2% commercial, 21.7% open-source.
    205,474 unique hallucinated package names. Mitigation strategies can reduce while maintaining code quality.

[3] LASSO SECURITY BLOG: "Diving Deeper into AI Package Hallucinations" — Bar Lanyado (Mar 2024)
    47,803 "how to" questions across Python, Node.js, Go, .NET, Ruby. 4 models tested:
    GPT-4: 24.2% hallucination, 19.6% repetitive. GPT-3.5: 22.2%, 13.6% repetitive.
    Gemini Pro: 64.5%, 14% repetitive. Cohere (Coral): 29.1%, 24.2% repetitive.
    215 packages hallucinated across ALL models. "huggingface-cli" dummy package got 30k+ real downloads.
    Companies like Alibaba referenced it in their READMEs.

[4] WIKIPEDIA: Typosquatting
    Form of cybersquatting exploiting URL typos. Goggle.com example.
    2024 study found typosquatting in blockchain naming systems (ENS, Unstoppable Domains).
    Diesel Vortex phishing campaign (Feb 2026) used lookalike domains — 1,600+ credentials stolen.

[5] PAPER: "Deficiency of LLMs in Finance: An Empirical Examination of Hallucination" — arxiv 2311.15548
    Kang & Liu. LLMs hallucinate financial concepts and stock prices.
    Tested few-shot, DoLa, RAG, prompt-based tool learning. Finding: off-the-shelf LLMs have serious hallucination in finance.

[6] COURTHOUSE NEWS: Walters v. OpenAI (Gwinnett County, 2023) — 403'd (legal complaint PDF)
    Referenced for "potential legal consequences" of hallucinations.
    Unable to fetch — behind access control.

[7] PAPER: "Hallucination is Inevitable: An Innate Limitation of LLMs" — arxiv 2401.11817
    Xu, Jain, Kankanhalli. Formal proof: no computable LLM can learn all computable ground-truth functions.
    Hallucination is mathematically guaranteed for unbounded open-domain generation.

[8] PAPER: "The Dawn After the Dark: An Empirical Study on Factuality Hallucination in LLMs" — arxiv 2401.03205
    Li, Chen, Ren et al. Systematic study on detection, source, mitigation.
    Introduces HaluEval 2.0 benchmark.

[9] PAPER: "Trapping LLM Hallucinations Using Tagged Context Prompts" — arxiv 2306.06085
    Feldman, Foulds, Pan. Tagged context prompts eliminated 98.88% of hallucinations.
    Used generated URLs as test indicators of fabricated data.

[10] GITHUB: InstructLab — github.com/instructlab
    Red Hat/IBM open-source LLM fine-tuning via taxonomy-based curation.
    3.2k followers. Recently refactored into separate component repos (sdg_hub, training_hub).
    Uses LAB paper (Large-Scale Alignment for ChatBots, arxiv 2403.01081).

[11] RED HAT: "What is Retrieval-Augmented Generation?" (NEW — missed in first pass)
    https://www.redhat.com/en/topics/ai/what-is-retrieval-augmented-generation
    RAG explained: links LLM to external resources via vector databases.
    3 stages: Data prep (ETL, chunking, embedding, storage) → Retrieval (vector DB search) → Generation.
    Benefits: accuracy, cost effectiveness, developer control, data sovereignty.
    RAG vs fine-tuning, vs pretraining, vs prompt engineering, vs semantic search.
    Uses vLLM for inference, MCP for data source standardization.
    RAG reduces hallucinations by grounding outputs in retrievable evidence.

[12] WIKIPEDIA: BERT (language model)
    Google's 2018 encoder-only transformer. 110M (BASE) to 340M (LARGE) parameters.
    Masked language modeling + next sentence prediction. Fine-tuned for downstream tasks.
    Variants: RoBERTa, DistilBERT, ALBERT, ELECTRA, DeBERTa.

[13] PAPER: "Chain-of-Thought Prompting Elicits Reasoning in LLMs" — arxiv 2201.11903
    Wei, Wang, Schuurmans et al. CoT improves complex reasoning via intermediate steps.
    540B PaLM with 8 CoT exemplars achieves SOTA on GSM8K math word problems.

[14] PAPER: "Language Models are Few-Shot Learners" (GPT-3) — arxiv 2005.14165
    Brown, Mann, Ryder et al. 175B parameter model.
    Scaling improves few-shot performance. Tasks specified purely via text interaction.

[15] RED HAT DEV: RHEL AI — Try LLMs the Easy Way (403'd)
    https://developers.redhat.com/learn/rhel/rhel-ai-try-llms-easy-way
    Referenced as closing CTA in the hallucinations article. Not accessible.

=== ANALYSIS TASKS ===
Provide analysis covering ALL of these angles:

A) MITIGATION EFFECTIVENESS: Rank all proposed strategies (fine-tuning, RAG, CoT, few-shot, guardrails, tagged context, InstructLab) by evidence strength. What's the optimal combination?

B) FUNDAMENTAL LIMITS: Given the "Hallucination is Inevitable" proof, what upper bound does this place on mitigation? Design implications.

C) PACKAGE HALLUCINATION THREAT MODEL: For Raphael (AI security framework generating code), how to address the 5.2-21.7% package hallucination risk? Concrete verification pipeline.

D) MODEL SELECTION: Given hallucination rates (Gemini 64.5%, GPT-4 24.2%, open-source 21.7%, Cohere 29.1%), which models for which roles? Reject Gemini?

E) RAG VS FINE-TUNING VS PROMPTING: Fresh RAG content from source [11] — when is each appropriate? How do they compose?

F) CRITIC/JUDGE DESIGN: Synthesize all findings into a concrete multi-layer hallucination detection architecture. What signals, what model ensemble, what verification layers?

G) RESEARCH GAPS: What's missing? What follow-up research would be most valuable?

Output in markdown with clear sections. Be specific, cite evidence, give actionable recommendations.
"""

async def main():
    print("[*] Launching community mode on ALL 15 article-body links (fresh corpus)...")
    print(f"[*] Models: w12, w13, w480b, minimaxm3 (2 rounds) → kimi synthesis\n")
    result = await community.handle(PROMPT, rounds=2)
    
    out = Path("/home/yaser/Ultimate skill/raphael-2.0/community_links_report_v2.json")
    out.write_text(json.dumps(result, indent=2, default=str))
    print(f"\n[*] Full output saved to {out}")
    
    final = result.get("final", "N/A")
    print("\n" + "="*60)
    print("KIMI SYNTHESIS")
    print("="*60)
    print(final)
    
    for mid, label in [("w12","W12"),("w13","W13"),("w480b","W480B"),("minimaxm3","MiniMax-M3")]:
        text = result.get("contributions",{}).get(mid, "")
        if text and text != "N/A":
            print(f"\n{label} CONTRIBUTION (first 400 chars):")
            print(str(text)[:400])
    
    print("\n[*] Done.")

if __name__ == "__main__":
    asyncio.run(main())
