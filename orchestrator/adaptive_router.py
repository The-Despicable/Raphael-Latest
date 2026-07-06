import json, math, time, os
from typing import Optional

STORAGE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "adaptive_router.json")

TASK_KEYWORDS = {
    "recon": ["subdomain", "dns", "enumerate", "recon", "whois", "certificate", "crt.sh", "scan port", "nmap"],
    "exploit": ["sql injection", "sqli", "xss", "command injection", "cmdi", "ssrf", "exploit", "payload", "bypass"],
    "code": ["write a script", "generate code", "python", "bash", "powershell", "compile", "implant"],
    "postex": ["persistence", "lateral", "privesc", "credential", "dump", "exfil"],
    "opsec": ["anonymity", "tor", "proxy", "stealth", "evade", "detection"],
    "waf_bypass": ["oracle xmltype", "json function", "unicode normalization", "hpp", "waf bypass", "modsecurity bypass", "cloudflare bypass", "content-type bypass"],
    "forensics": ["cleanup", "erase logs", "wevtutil", "journalctl", "auditpol", "anti-forensics", "log clearing"],
    "mimicry": ["timing", "temporal coherence", "data velocity", "process lineage", "behavioral mimicry", "evasion", "stealth pattern"],
    "dkom": ["direct syscall", "etw patching", "dkom", "module overloading", "thread hijacking", "ntdll", "kernel32"],
    "general": [],
}

def classify_task(messages: list) -> str:
    text = " ".join(m.get("content", "") for m in messages).lower()
    scores = {}
    for task, keywords in TASK_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > 0:
            scores[task] = score
    if not scores:
        return "general"
    return max(scores, key=scores.get)

def load_scores() -> dict:
    try:
        with open(STORAGE_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_scores(scores: dict):
    os.makedirs(os.path.dirname(STORAGE_PATH), exist_ok=True)
    with open(STORAGE_PATH, "w") as f:
        json.dump(scores, f, indent=2)

def pick_model(task_type: str, available_models: list, scores: dict) -> str:
    total = sum(len(v.get(task_type, [])) for v in scores.values())
    scored = []
    unscored = []
    for model in available_models:
        task_scores = scores.get(model, {}).get(task_type, [])
        if task_scores:
            avg = sum(task_scores) / len(task_scores)
            n = len(task_scores)
            ucb = avg + math.sqrt(2 * math.log(max(total, 1)) / n) if total > 0 and n > 0 else avg
            scored.append((ucb, model))
        else:
            unscored.append(model)
    if scored:
        scored.sort(reverse=True)
        return scored[0][1]
    return unscored[0] if unscored else available_models[0]

def update_score(model: str, task_type: str, success: float, latency: float):
    scores = load_scores()
    if model not in scores:
        scores[model] = {}
    if task_type not in scores[model]:
        scores[model][task_type] = []
    speed_score = 1.0 / (1.0 + latency)
    final = 0.7 * success + 0.3 * speed_score
    scores[model][task_type].append(round(final, 4))
    save_scores(scores)

def estimate_success(response_text: str, error_occurred: bool) -> float:
    if error_occurred:
        return 0.0
    if not response_text:
        return 0.2
    if "error" in response_text.lower() and len(response_text) < 200:
        return 0.3
    return 0.9
