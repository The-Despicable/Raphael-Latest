import math, json, os

MEMORY_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "scanner_brain.json")

def _load() -> dict:
    try:
        with open(MEMORY_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"models": {}, "vuln_types": {}}

def _save(data: dict):
    os.makedirs(os.path.dirname(MEMORY_FILE), exist_ok=True)
    with open(MEMORY_FILE, "w") as f:
        json.dump(data, f, indent=2)

def pick_model(vuln_type: str, candidates: list) -> str:
    data = _load()
    scores = {m: data["models"].get(m, {}).get(vuln_type, {}).get("avg", 5.0) for m in candidates}
    return max(scores, key=scores.get)

def record_result(model: str, vuln_type: str, score: float):
    data = _load()
    if model not in data["models"]:
        data["models"][model] = {}
    if vuln_type not in data["models"][model]:
        data["models"][model][vuln_type] = {"runs": [], "avg": 0.0}
    entry = data["models"][model][vuln_type]
    entry["runs"].append(score)
    entry["avg"] = sum(entry["runs"]) / len(entry["runs"])
    if vuln_type not in data["vuln_types"]:
        data["vuln_types"][vuln_type] = {"total_scans": 0}
    data["vuln_types"][vuln_type]["total_scans"] += 1
    _save(data)
