"""
Critic — lightweight post-execution failure detector and scorer.

Analyzes tool output for failure signals, scores execution quality,
and returns structured feedback that feeds into the postmortem/RSI loop.

Usage:
  from orchestrator.critic import judge
  result = judge("nmap scan output...", task="port scan 10.0.0.1")
"""
import re, json
from typing import Optional


def _escape_xml(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def build_tagged_context(output: str, task: str, failures: list, successes: list) -> str:
    """Wrap detected signals in XML tags per arXiv 2306.06085 (tagged context).

    Downstream LLMs consuming the output can use <context>/<signal> tags to
    distinguish verified signal detections from generated interpretation.
    """
    parts = [f'<context type="task">{_escape_xml(task)}</context>']
    if failures:
        parts.append('<signals type="failure">')
        for f in failures:
            parts.append(f'  <signal name="{_escape_xml(f["signal"])}">{_escape_xml(f.get("match", ""))}</signal>')
        parts.append('</signals>')
    if successes:
        parts.append('<signals type="success">')
        for s in successes:
            parts.append(f'  <signal name="{_escape_xml(s["signal"])}">{_escape_xml(s.get("match", ""))}</signal>')
        parts.append('</signals>')
    parts.append(f'<context type="raw_snippet">{_escape_xml(output[:500])}</context>')
    return '\n'.join(parts)

_NEGATION_WORDS = r"\b(?:no|not|without|except|excluding)\s+"

FAILURE_SIGNALS = {
    "timeout": [
        r"timed?\s*out", r"timeout",
        r"connection\s+timed?\s*out",
        r"no\s+route\s+to\s+host", r"deadline\s+exceeded",
    ],
    "access_denied": [
        r"access\s+denied", r"permission\s+denied", r"unauthorized",
        r"authentication\s+failed", r"login\s+failed", r"forbidden",
        r"error\s*:\s*13[0-9]{2}", r"403", r"401",
    ],
    "no_results": [
        r"0\s+hosts?\s+up", r"no\s+(results?|matches?|entries?)",
        r"empty", r"nothing\s+found", r"no\s+output",
        r"failed\s+to\s+identify",
    ],
    "tool_error": [
        r"error\s*:", r"exception\s*:", r"traceback",
        r"failed\s+to\s+(run|execute|start|connect)",
        r"command\s+not\s+found", r"no\s+such\s+file",
        r"segmentation\s+fault", r"core\s+dumped",
    ],
    "partial_output": [
        r"output\s+truncated", r"results\s+may\s+be\s+incomplete",
        r"interrupted", r"killed",
    ],
    "waf_blocked": [
        r"blocked\s+(by\s+)?(WAF|ModSecurity|Cloudflare|Akamai|Imperva|Sucuri)",
        r"Cloudflare.+challenge",
        r"reference.+number.+Ray ID",
        r"just a moment",
        r"checking your browser",
        r"412 precondition failed",
        r"406 not acceptable",
        r"ModSecurity.+id\s+\d{4,}",
    ],
    "behavioral_anomaly": [
        r"(As an AI|I['\u2019]d be happy to|Certainly[!,\s])",
        r"Action completed in exactly \d+ seconds",
        r"completed in precisely \d+",
    ],
}

SUCCESS_SIGNALS = {
    "found_hosts": [r"(\d+)\s+hosts?\s+up", r"Nmap\s+done"],
    "found_open_ports": [r"(\d+)/(tcp|udp)\s+open"],
    "found_vulnerabilities": [
        r"vulnerabilit", r"CVE-\d{4}-\d{4,7}", r"critical",
        r"high\s+severity", r"exploit\s+available",
    ],
    "credentials_found": [
        r"password\s+found", r"hash\s+captured", r"token\s+found",
        r"credential", r"logged\s+in", r"session\s+established",
    ],
    "persistence": [
        r"persistence\s+established", r"backdoor\s+deployed",
        r"scheduled\s+task", r"service\s+installed",
    ],
}


def _is_negated(text: str, match_start: int) -> bool:
    before = text[max(0, match_start - 60):match_start].lower()
    return bool(re.search(_NEGATION_WORDS, before))

def _score_signal(text: str, signals: dict, category: str) -> dict:
    matches = []
    weight = -1 if category == "failure" else 1
    for name, patterns in signals.items():
        for pat in patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                if not _is_negated(text, m.start()):
                    matches.append({"signal": name, "pattern": pat, "match": m.group()})
                    break
    score = len(matches) * weight
    return {"matches": matches, "score": score, "count": len(matches)}


def judge(output: str, task: str = "", tool: str = "", threshold: float = 0.3) -> dict:
    """Analyze execution output and return a structured judgment.

    Returns:
        verdict: "pass" | "fail" | "partial"
        confidence: 0.0-1.0
        failures: list of detected failure signals
        successes: list of detected success signals
        score: net quality score (positive = good, negative = bad)
        summary: human-readable one-liner
    """
    if not output or len(output.strip()) < 10:
        no_output_failures = [{"signal": "no_output", "match": "empty or near-empty output"}]
        return {
            "verdict": "fail",
            "confidence": 0.9,
            "failures": no_output_failures,
            "successes": [],
            "score": -1,
            "summary": "No output produced — tool may have failed silently",
            "tagged_context": build_tagged_context(output, task, no_output_failures, []),
        }

    failure = _score_signal(output, FAILURE_SIGNALS, "failure")
    success = _score_signal(output, SUCCESS_SIGNALS, "success")

    net_score = failure["score"] + success["score"]
    total_signals = failure["count"] + success["count"]
    confidence = min(abs(net_score) / max(total_signals, 1), 1.0) if total_signals > 0 else 0.3

    if failure["count"] > 0 and success["count"] == 0:
        verdict = "fail"
    elif success["count"] > 0 and failure["count"] == 0:
        verdict = "pass"
    elif failure["count"] >= success["count"]:
        verdict = "partial"
    else:
        verdict = "pass"

    fail_summary = ", ".join(f["signal"] for f in failure["matches"][:3])
    success_summary = ", ".join(s["signal"] for s in success["matches"][:2])
    parts = []
    if fail_summary:
        parts.append(f"failures: {fail_summary}")
    if success_summary:
        parts.append(f"successes: {success_summary}")
    summary = f"[{verdict.upper()}] {'; '.join(parts)}" if parts else f"[{verdict.upper()}] no clear signals"

    return {
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "score": net_score,
        "failures": failure["matches"],
        "successes": success["matches"],
        "summary": summary,
        "tagged_context": build_tagged_context(output, task, failure["matches"], success["matches"]),
    }


def summarize_execution_log(log_path: str) -> dict:
    """Read an execution log file and return a critic judgment."""
    try:
        with open(log_path) as f:
            content = f.read()
        return judge(content, task=f"log:{log_path}")
    except Exception as e:
        return {
            "verdict": "error",
            "confidence": 1.0,
            "failures": [{"signal": "read_error", "match": str(e)}],
            "successes": [],
            "score": -99,
            "summary": f"Failed to read log: {e}",
        }
