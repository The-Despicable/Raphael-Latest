import json
from ..providers import call_model

ANALYSIS_PROMPT = """You are a security code reviewer. Analyze the following finding.

Vulnerability Type: {vuln_type} ({cwe})
Code Snippet:
```
{snippet}
```

Context (surrounding lines):
```
{context}
```

Respond with JSON only:
{{
  "confirmed": true/false,
  "confidence": <0-10>,
  "explanation": "<why it is or isn't a real vulnerability>",
  "remediation": "<how to fix it>",
  "severity": "<critical/high/medium/low>"
}}
"""

async def analyze_finding(finding, context: str, orch_url: str, api_key: str) -> dict:
    prompt = ANALYSIS_PROMPT.format(
        vuln_type=finding.vuln_type,
        cwe=finding.cwe,
        snippet=finding.snippet,
        context=context,
    )
    try:
        raw = await call_model("auto", [{"role": "user", "content": prompt}], max_tokens=800, temperature=0.1)
        clean = raw.strip().strip("```json").strip("```").strip()
        return json.loads(clean)
    except Exception as e:
        return {"confirmed": False, "confidence": 0, "explanation": f"LLM analysis failed: {e}", "remediation": "", "severity": finding.severity}
