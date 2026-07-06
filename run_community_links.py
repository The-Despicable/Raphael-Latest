#!/usr/bin/env python3
"""
Run Raphael community mode against the LLM hallucinations research corpus.
"""
import asyncio, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator.modes import community

PROMPT = """You are an expert research analyst. Analyze the following corpus of LLM hallucination research and produce a multi-perspective synthesis.

=== CORPUS ===

1. MAIN ARTICLE: Red Hat — "When LLMs Day-Dream: Hallucinations and How to Prevent Them"
   https://www.redhat.com/en/blog/when-llms-day-dream-hallucinations-how-prevent-them
   Four mitigation approaches: fine-tuning (InstructLab), RAG, advanced prompting (CoT, few-shot), guardrails.

2. PAPER: "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs" (arxiv 2406.10279)
   5.2% hallucinated packages in commercial models, 21.7% in open-source; 205k unique hallucinated package names; 576k code samples across 16 LLMs.

3. PAPER: Kang & Liu — "Hallucination in Finance LLMs" (arxiv 2311.15548)
   LLMs hallucinate financial concepts/stock prices; tested few-shot, DoLa, RAG, tool learning as mitigations.

4. PAPER: "Hallucination is Inevitable: An Innate Limitation of Large Language Models" (arxiv 2401.11817)
   Proves mathematically that no computable LLM can learn all computable ground-truth functions — hallucination cannot be eliminated.

5. PAPER: "Dawn After the Dark: An Empirical Study on Hallucinations in Large Language Models" (arxiv 2401.03205)
   Systematic study on detection, source, and mitigation; introduces HaluEval 2.0 benchmark.

6. PAPER: "Trapping LLM Hallucinations Using Tagged Context Prompts" (arxiv 2306.06085)
   Tagged context prompts reduced hallucinations by 98.88% in experiments.

7. PAPER: "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models" (arxiv 2201.11903)
   Intermediate reasoning steps improve complex reasoning — foundational CoT paper.

8. PAPER: "Language Models are Few-Shot Learners" (arxiv 2005.14165)
   Original GPT-3 paper showing scaling improves few-shot performance.

9. BLOG: Lasso Security — "AI Package Hallucinations"
   https://www.lasso.security/blog/ai-package-hallucinations
   GPT-4 hallucination rate 24.2%, GPT-3.5 22.2%, Gemini 64.5%, Cohere 29.1%; dummy package "huggingface-cli" got 30k+ real downloads.

10. RED HAT: "What are large language models?"
    https://www.redhat.com/en/topics/ai/what-are-large-language-models
    LLM explainer: transformer architecture, self-attention, MoE, training pipeline, RAG, agentic AI, MCP, LLMs vs SLMs.

11. WIKIPEDIA: Typosquatting
    https://en.wikipedia.org/wiki/Typosquatting
    Form of cybersquatting — relevant to package hallucination risks.

12. WIKIPEDIA: BERT (language model)
    https://en.wikipedia.org/wiki/BERT_(language_model)
    Google's 2018 encoder-only transformer used in RAG pipelines.

13. GITHUB: InstructLab
    https://github.com/instructlab
    Red Hat/IBM open-source LLM fine-tuning via taxonomy-based curation.

14. RED HAT DEV: RHEL AI — Try LLMs the Easy Way (403'd, listed as CTA reference)
    https://developers.redhat.com/learn/rhel/rhel-ai-try-llms-easy-way

=== ANALYSIS TASK ===
Provide analysis covering ALL of these angles (each as a separate section):

A) MITIGATION EFFECTIVENESS: Rank the proposed mitigation strategies (fine-tuning, RAG, CoT, few-shot, guardrails, tagged context) by practical effectiveness based on the evidence. Which combination works best?

B) FUNDAMENTAL LIMITS: Given the "Hallucination is Inevitable" proof, what are the practical implications for building reliable AI systems? What upper bound does this place on mitigation?

C) PACKAGE HALLUCINATION THREAT MODEL: For an AI security framework like Raphael that generates offensive security code, how should package hallucination risk (2406.10279 + Lasso) be addressed? Specific recommendations.

D) MODEL SELECTION GUIDANCE: Based on the hallucination rates found (Gemini 64.5%, GPT-4 24.2%, open-source 21.7%), which models should be preferred/rejected for a critic/judge role? Why?

E) CRITIC/JUDGE DESIGN: Synthesize all findings into concrete recommendations for designing a critic/judge module that detects hallucinations in LLM outputs. What signals should it check? What architecture?

F) RESEARCH GAPS: What is missing from this corpus? What follow-up research would be most valuable?

Output in markdown with clear section headers. Be specific, cite evidence, and give actionable recommendations.
"""

async def main():
    print("[*] Launching community mode analysis on hallucination research corpus...")
    print(f"[*] Models: w12, w13, w480b, minimaxm3 (2 rounds) → kimi synthesis\n")
    result = await community.handle(PROMPT, rounds=2)
    
    out = Path("/home/yaser/Ultimate skill/raphael-2.0/community_links_report.json")
    out.write_text(json.dumps(result, indent=2, default=str))
    print(f"\n[*] Full output saved to {out}")
    
    final = result.get("final", "N/A")
    print("\n" + "="*60)
    print("KIMI SYNTHESIS")
    print("="*60)
    print(final)
    print("\n" + "="*60)
    
    for mid, label in [("w12","W12"),("w13","W13"),("w480b","W480B"),("minimaxm3","MiniMax-M3")]:
        text = result.get("contributions",{}).get(mid, "")
        if text and text != "N/A":
            preview = text[:500].strip()
            print(f"\n{label} CONTRIBUTION (preview):")
            print(preview[:300] + ("..." if len(preview) > 300 else ""))
    
    print("\n[*] Done.")

if __name__ == "__main__":
    asyncio.run(main())
