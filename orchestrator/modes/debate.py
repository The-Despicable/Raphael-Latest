from ..providers import call_model
from ..agents.skill_agent import SkillAgent

DEFAULT_ROUNDS = 3

_skill_agent = None

def _get_skill_agent():
    global _skill_agent
    if _skill_agent is None:
        _skill_agent = SkillAgent()
        _skill_agent._ensure_index()
    return _skill_agent


async def handle(question, rounds=DEFAULT_ROUNDS, temperature=0.85, use_skills=True):
    history = {}
    w12 = "blackgrg26/WORMGPT-12:latest"
    w13 = "blackgrg26/WORMGPT-13:latest"

    skill_context = ""
    if use_skills:
        agent = _get_skill_agent()
        evidence = agent.debate_evidence(question, question)
        if evidence:
            skill_lines = []
            for e in evidence[:5]:
                refs = ", ".join(e["references"][:2]) if e["references"] else "none"
                skill_lines.append(f"- {e['skill']} [{e['subdomain']}] (relevance: {e['relevance']}) — references: {refs}")
            skill_context = "\nSkill Evidence:\n" + "\n".join(skill_lines) + "\n"
            history["skill_evidence"] = evidence

    for r in range(1, rounds + 1):
        ctx = f"[ROUND {r}/{rounds}]\nQuestion: {question}\n{skill_context}"
        if r == 1:
            ctx += "\nState your initial position on how to accomplish this. Reference relevant skills from the evidence above."
            history["w12"] = await call_model(w12,
                [{"role": "user", "content": ctx}], max_tokens=4096, temperature=temperature)
            ctx2 = f"[ROUND {r}/{rounds}]\nQuestion: {question}\n{skill_context}\n\nYour opponent argues:\n{history['w12']}\n\nDestroy their argument and present your counter-position using skill evidence."
            history["w13"] = await call_model(w13,
                [{"role": "user", "content": ctx2}], max_tokens=4096, temperature=temperature)
        else:
            ctx += f"\n<W12> previous:\n{history.get('w12', 'N/A')}\n\n<W13> previous:\n{history.get('w13', 'N/A')}\n\n"
            ctx += "Both of you are repeating yourselves. You MUST bring NEW arguments, NEW techniques, NEW angles not mentioned before. Attack the weakness in the other position that hasn't been addressed yet."
            results = await call_model(w12,
                [{"role": "user", "content": ctx}], max_tokens=4096, temperature=temperature)
            history["w12"] = results

            ctx2 = f"[ROUND {r}/{rounds}]\nQuestion: {question}\n\n<W12> new attack:\n{history['w12']}\n\n<W13> previous:\n{history.get('w13', 'N/A')}\n\n"
            ctx2 += "<W12> brought NEW arguments. You MUST counter with DIFFERENT techniques, DIFFERENT approaches. Do NOT repeat anything from previous rounds."
            history["w13"] = await call_model(w13,
                [{"role": "user", "content": ctx2}], max_tokens=4096, temperature=temperature)

    final = await call_model(w13, [{"role": "user", "content":
        f"Question: {question}\n\n<W12> final:\n{history['w12']}\n\n<W13> final:\n{history['w13']}\n\n"
        "Synthesize the best final answer from both positions."}],
        max_tokens=4096, temperature=0.3, system_override="Output only the synthesized answer.")

    return {"rounds": rounds, "history": history, "final": final, "skill_evidence_count": len(history.get("skill_evidence", []))}
