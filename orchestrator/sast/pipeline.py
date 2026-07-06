import json, os
from .pattern_engine import scan_code, Finding
from .llm_analyzer import analyze_finding
from .adaptive_router import pick_model, record_result
from .report_generator import generate_report

ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:3100")
API_KEY = os.getenv("API_KEY", "")

class SastPipeline:
    async def scan(self, code: str, filename: str = "unknown") -> dict:
        findings = scan_code(code, filename)
        if not findings:
            return {
                "filename": filename,
                "findings_count": 0,
                "confirmed_count": 0,
                "report": "No vulnerabilities detected.",
                "details": [],
            }

        analyses = []
        lines = code.splitlines()
        for f in findings:
            start = max(0, f.line - 6)
            end = min(len(lines), f.line + 5)
            context = "\n".join(lines[start:end])
            model = pick_model(f.vuln_type, ["w12", "w13", "wormgpt12", "wormgpt13"])
            analysis = await analyze_finding(f, context, ORCHESTRATOR_URL, API_KEY)
            score = analysis.get("confidence", 0) if analysis.get("confirmed") else 0
            record_result(model, f.vuln_type, score)
            analyses.append(analysis)

        confirmed = [a for a in analyses if a.get("confirmed")]
        report_md = generate_report(filename, findings, analyses)
        return {
            "filename": filename,
            "findings_count": len(findings),
            "confirmed_count": len(confirmed),
            "report": report_md,
            "details": [{"finding": f.__dict__, "analysis": a} for f, a in zip(findings, analyses) if a.get("confirmed")],
        }
