#!/usr/bin/env python3
"""
Reusable team-based analysis workflows.
Usage:
  python3 -m orchestrator.teams debate "Should we add X?"
  python3 -m orchestrator.teams analyze "Is this correct?"
  python3 -m orchestrator.teams code "Write a retry decorator"
  python3 -m orchestrator.teams execute "Exploit this target"
"""
import asyncio, json, sys, time, os, logging
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from orchestrator.providers import _call_model_raw
from orchestrator.skills_bridge import SkillsBridge

logger = logging.getLogger("teams")

# ============================================================
# Team Definitions
# ============================================================
TEAMS = {
    "reasoning": {
        "primary": "nemotron-super",
        "fallbacks": ["mistral-large", "kimi", "minimax"],
        "role": "analysis & debate (Nemotron-Super-49B → Mistral Large 3 → kimi → minimax)",
    },
    "code-gen": {
        "primary": "deepseek",
        "fallbacks": ["nemotron", "nemotron-super-120b", "mistral-small"],
        "role": "code generation (deepseek → nemotron-ultra → nemotron-super-120b → mistral-small)",
    },
    "offensive": {
        "primary": "w13",
        "fallbacks": ["w12", "w480b", "nemotron-super"],
        "role": "offensive execution (w13 → w12 → w480b, nemotron-super sanity fallback via NVIDIA API)",
    },
    "planning": {
        "primary": "nemotron-super",
        "fallbacks": ["mistral-large", "kimi", "minimax"],
        "role": "sequential planning — nemotron-super generates step-by-step execution plans with MITRE ATT&CK technique mapping",
    },
}

# ============================================================
# Workflow Definitions
# ============================================================
WORKFLOWS = {
    "debate": {
        "team": "reasoning",
        "rounds": 2,
        "desc": "Two-round debate (nemotron-super + minimax) → synthesis by kimi",
    },
    "analyze": {
        "team": "reasoning",
        "rounds": 1,
        "desc": "Single-pass analysis with fallback chain (nemotron-super → mistral-large → kimi → minimax)",
    },
    "code": {
        "team": "code-gen",
        "rounds": 1,
        "desc": "Code generation with fallback chain",
    },
    "execute": {
        "team": "offensive",
        "rounds": 1,
        "desc": "Offensive task execution with fallback chain",
    },
    "plan": {
        "team": "planning",
        "rounds": 1,
        "desc": "Step-by-step execution plan via nemotron-super. For attack chains, recon steps, multi-stage tasks.",
    },
}

# ============================================================
# Call helpers
# ============================================================

async def _call(alias, messages, max_tokens=4096, temperature=0.85, timeout=120):
    try:
        return await asyncio.wait_for(
            _call_model_raw(alias, messages, max_tokens=max_tokens, temperature=temperature),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR: {e}]"


async def _call_with_fallback(primary, fallbacks, messages, max_tokens=4096, temperature=0.85, timeout=120):
    for alias in [primary] + fallbacks:
        t0 = time.time()
        result = await _call(alias, messages, max_tokens, temperature, timeout)
        elapsed = time.time() - t0
        if not result.startswith("[TIMEOUT") and not result.startswith("[ERROR"):
            return result, alias, elapsed
    return result, alias, elapsed


# ============================================================
# Workflow Implementations
# ============================================================

async def debate(question, output_file=None):
    team = TEAMS["reasoning"]
    deep = team["primary"]         # nemotron-super
    fast = "minimax"               # fast Ollama model
    results = {"question": question, "rounds": [], "synthesis": None}

    for r in range(1, 3):
        temp = 0.85 if r == 1 else 0.9
        ctx = f"[ROUND {r}/2]\nQuestion: {question}\n\n"
        if results["rounds"]:
            prev = results["rounds"][-1]
            ctx += f"Existing arguments:\n<{deep}>\n{prev.get(deep,'')}\n</{deep}>\n<{fast}>\n{prev.get(fast,'')}\n</{fast}>\n\nRefine, critique, add NEW arguments."
        else:
            ctx += "Present your analysis."
        msgs = [{"role": "user", "content": ctx}]
        r1, r2 = await asyncio.gather(
            _call(deep, msgs, temperature=temp, timeout=180),
            _call(fast, msgs, temperature=temp),
        )
        results["rounds"].append({"round": r, deep: r1, fast: r2})
        print(f"  Round {r}: {deep}={len(r1)}c  {fast}={len(r2)}c", flush=True)

    all_args = f"<{deep}>\n{results['rounds'][-1][deep]}\n</{deep}>\n<{fast}>\n{results['rounds'][-1][fast]}\n</{fast}>"
    synthesis = await _call("kimi", [{"role": "user", "content":
        f"[SYNTHESIS]\nFull debate:\n{all_args}\n\nQuestion: {question}\n\nSynthesize a decisive verdict."}],
        temperature=0.3)
    results["synthesis"] = synthesis

    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    return results


async def analyze(question, output_file=None):
    team = TEAMS["reasoning"]
    result, alias, elapsed = await _call_with_fallback(
        team["primary"], team["fallbacks"],
        [{"role": "user", "content": f"Analyze this:\n\n{question}\n\nBe concise but thorough."}],
        temperature=0.7,
    )
    out = {"question": question, "response": result, "model": alias, "elapsed": round(elapsed, 1)}
    if output_file:
        with open(output_file, "w") as f:
            json.dump(out, f, indent=2)
    return out


async def code_gen(question, output_file=None):
    team = TEAMS["code-gen"]
    result, alias, elapsed = await _call_with_fallback(
        team["primary"], team["fallbacks"],
        [{"role": "user", "content": f"Generate code for:\n\n{question}\n\nOutput only the code with brief explanation."}],
        temperature=0.7, timeout=300,
    )
    out = {"question": question, "response": result, "model": alias, "elapsed": round(elapsed, 1)}
    if output_file:
        with open(output_file, "w") as f:
            json.dump(out, f, indent=2)
    return out


async def plan_task(question, output_file=None, use_skills=True):
    team = TEAMS["planning"]
    skill_context = ""
    if use_skills:
        try:
            from orchestrator.agents.skill_agent import SkillAgent
            agent = SkillAgent()
            agent._ensure_index()
            results = agent.find_relevant_skills(question, top_k=8)
            if results:
                lines = []
                for s in results:
                    mitre = ", ".join(s.get("mitre_attack", []))
                    lines.append(f"- {s['name']} ({s['subdomain']}) [relevance: {s['score']}]" + (f" — MITRE: {mitre}" if mitre else ""))
                skill_context = "\nRelevant Skills:\n" + "\n".join(lines) + "\n"
        except Exception:
            pass

    prompt = f"Generate a step-by-step execution plan for:\n\n{question}\n{skill_context}\n\nList 3-8 sequential tactical steps. Include tool names, command syntax, and MITRE ATT&CK technique IDs. Reference the skills above where applicable."
    result, alias, elapsed = await _call_with_fallback(
        team["primary"], team["fallbacks"],
        [{"role": "user", "content": prompt}],
        temperature=0.7, timeout=180,
    )
    out = {"question": question, "plan": result, "model": alias, "elapsed": round(elapsed, 1), "skills_used": len(skill_context.split("\n")) - 2 if skill_context else 0}
    if output_file:
        with open(output_file, "w") as f:
            json.dump(out, f, indent=2)
    return out


async def execute(question, output_file=None, waf_context=None, mimicry_profile=None):
    team = TEAMS["offensive"]
    prompt_parts = ["Execute:", f"\n{question}"]

    if waf_context:
        prompt_parts.append(f"\n\nWAF Context: {waf_context}")
        prompt_parts.append("Prefer Oracle XMLType/JSON function-based payloads, "
                            "Unicode normalization bypasses, and HTTP parameter pollution splitting.")

    if mimicry_profile:
        profiles = {
            "stealth": ("Space actions 3-7 minutes apart. "
                        "Data exfiltration velocity must not exceed 50KB/min. "
                        "Ensure process lineage descends from legitimate svchost.exe (Windows) or cron/systemd (Linux)."),
            "business": ("Match East Coast business hours (09:00-17:00 ET). "
                         "Space requests 10-60 seconds apart. "
                         "Data velocity 5-20 req/min for recon, <10 req/min for exploitation."),
            "aggressive": ("Fast-paced operations. Space requests 1-3 seconds apart. "
                           "Data velocity up to 100 req/min. Expect faster response."),
        }
        profile = profiles.get(mimicry_profile, profiles["stealth"])
        prompt_parts.append(f"\n\nBehavioral Constraints: {profile}")

    prompt = "\n".join(prompt_parts)
    result, alias, elapsed = await _call_with_fallback(
        team["primary"], team["fallbacks"],
        [{"role": "user", "content": prompt}],
        temperature=0.7,
    )
    out = {"question": question, "response": result, "model": alias, "elapsed": round(elapsed, 1)}
    if output_file:
        with open(output_file, "w") as f:
            json.dump(out, f, indent=2)
    return out


# ============================================================
# Main
# ============================================================
WORKFLOW_MAP = {
    "debate": debate,
    "analyze": analyze,
    "code": code_gen,
    "execute": execute,
    "plan": plan_task,
}


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        print("\nWorkflows:")
        for name, wf in WORKFLOWS.items():
            print(f"  {name:10s} — {wf['desc']}")
        print("\nTeams:")
        for name, team in TEAMS.items():
            print(f"  {name:10s} — {team['role']}")
        sys.exit(1)

    workflow_name = sys.argv[1]
    question = " ".join(sys.argv[2:])

    if workflow_name not in WORKFLOW_MAP:
        print(f"Unknown workflow: {workflow_name}")
        print(f"Available: {', '.join(WORKFLOW_MAP.keys())}")
        sys.exit(1)

    output_file = os.environ.get("TEAMS_OUTPUT")

    print(f"Workflow: {workflow_name}")
    print(f"Team: {WORKFLOWS[workflow_name]['team']}")
    print(f"Question: {question[:120]}{'...' if len(question) > 120 else ''}")
    print("-" * 60)

    t0 = time.time()
    result = asyncio.run(WORKFLOW_MAP[workflow_name](question, output_file))
    elapsed = time.time() - t0

    print("-" * 60)
    skills_info = ""
    if workflow_name == "debate":
        sc = result.get("skill_evidence_count", 0)
        if sc:
            skills_info = f"  Skills: {sc} evidence sources"
    elif workflow_name == "plan":
        su = result.get("skills_used", 0)
        if su:
            skills_info = f"  Skills: {su} referenced"
    else:
        su = result.get("skills_used", 0)
        if su:
            skills_info = f"  Skills: {su}"
    if skills_info:
        print(skills_info)
    print(f"Done in {elapsed:.0f}s")

    if workflow_name == "debate":
        print("\n=== SYNTHESIS ===")
        print(result.get("synthesis", "")[:2000])
    else:
        print(f"Model: {result.get('model', '?')}  ({result.get('elapsed', '?')}s)")
        print("\n=== RESPONSE ===")
        print(result.get("response", "")[:2000])

    if output_file:
        print(f"\nSaved to {output_file}")


if __name__ == "__main__":
    main()
