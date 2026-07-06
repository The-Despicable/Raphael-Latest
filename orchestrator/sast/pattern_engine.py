import ast, re
from dataclasses import dataclass
from typing import List

@dataclass
class Finding:
    vuln_type: str
    severity: str
    line: int
    snippet: str
    cwe: str
    confidence: float

PATTERNS = {
    "sql_injection": {
        "regex": r"""(?:execute|query|cursor|raw)\s*\(.*[\+\%].*\)""",
        "severity": "critical",
        "cwe": "CWE-89",
        "label": "SQL Injection",
    },
    "xss": {
        "regex": r"""(?:innerHTML|outerHTML)\s*=|document\.write\s*\(|\.html\s*\([^)]*[\+\$]|<script\b[^>]*>.*?</script>|on\w+\s*=\s*['\"][^\"']*['\"]|javascript:\s*|src\s*=\s*['\"]?\s*data:text\/html""",
        "severity": "high",
        "cwe": "CWE-79",
        "label": "Cross-Site Scripting",
    },
    "command_injection": {
        "regex": r"""subprocess\.(call|Popen|run)\s*\(.*shell\s*=\s*True""",
        "severity": "critical",
        "cwe": "CWE-78",
        "label": "Command Injection",
    },
    "path_traversal": {
        "regex": r"""open\s*\(.*[\+\%].*\)|Path\(.*[\+\%]|read_text\(.*[\+\%]""",
        "severity": "high",
        "cwe": "CWE-22",
        "label": "Path Traversal",
    },
    "insecure_deserialization": {
        "regex": r"""pickle\.loads\s*\(|yaml\.load\s*\(|marshal\.loads\s*\(""",
        "severity": "high",
        "cwe": "CWE-502",
        "label": "Insecure Deserialization",
    },
    "ssti": {
        "regex": r"""\{\{.*?\}\}|\$\{.*?\}|#set\s*\(|\{%.*?%\}""",
        "severity": "high",
        "cwe": "CWE-94",
        "label": "Server-Side Template Injection",
    },
    "ssrf": {
        "regex": r"""(?:url|uri|link|href|src|action|redirect)\s*=\s*[^)]*(?:http|ftp|gopher|dict)""",
        "severity": "high",
        "cwe": "CWE-918",
        "label": "Server-Side Request Forgery",
    },
    "hardcoded_secret": {
        "regex": r"""(?:api_key|secret|password|token|credential)\s*=\s*['\"][A-Za-z0-9_\-]{16,}""",
        "severity": "critical",
        "cwe": "CWE-798",
        "label": "Hardcoded Secret",
    },
    "weak_crypto": {
        "regex": r"""(?:MD5|md5|SHA1|sha1|DES|des)\s*\(""",
        "severity": "medium",
        "cwe": "CWE-327",
        "label": "Weak Cryptography",
    },
    "no_input_validation": {
        "regex": r"""request\.(GET|POST|args|form|json|data)\[.*\]""",
        "severity": "medium",
        "cwe": "CWE-20",
        "label": "Missing Input Validation",
    },
    "jwt_misconfiguration": {
        "regex": r"""jwt\.(decode|verify|encode)\s*\(.*(?:algorithms\s*=\s*\[|options\s*=\s*\{)""",
        "severity": "critical",
        "cwe": "CWE-347",
        "label": "JWT Misconfiguration",
    },
}

AST_PATTERNS = {
    "eval_usage": {
        "check": lambda node: isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'eval',
        "severity": "critical",
        "cwe": "CWE-95",
        "label": "Eval Usage",
    },
    "exec_usage": {
        "check": lambda node: isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'exec',
        "severity": "critical",
        "cwe": "CWE-95",
        "label": "Exec Usage",
    },
    "assert_usage": {
        "check": lambda node: isinstance(node, ast.Assert),
        "severity": "low",
        "cwe": "CWE-617",
        "label": "Assert Statement",
    },
}

def _scan_regex(code: str, filename: str) -> List[Finding]:
    findings = []
    for vuln_type, pattern in PATTERNS.items():
        for m in re.finditer(pattern["regex"], code, re.IGNORECASE | re.MULTILINE):
            line = code[:m.start()].count("\n") + 1
            snippet = code[max(0, m.start() - 40):m.end() + 40]
            findings.append(Finding(
                vuln_type=vuln_type,
                severity=pattern["severity"],
                line=line,
                snippet=snippet.strip(),
                cwe=pattern["cwe"],
                confidence=0.7,
            ))
    return findings

def _scan_ast(code: str, filename: str) -> List[Finding]:
    findings = []
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            for pname, pconf in AST_PATTERNS.items():
                if pconf["check"](node):
                    findings.append(Finding(
                        vuln_type=pname,
                        severity=pconf["severity"],
                        line=getattr(node, 'lineno', 0),
                        snippet=ast.unparse(node) if hasattr(ast, 'unparse') else "",
                        cwe=pconf["cwe"],
                        confidence=0.8,
                    ))
    except SyntaxError:
        pass
    return findings

def scan_code(code: str, filename: str) -> List[Finding]:
    combined = {}
    for f in _scan_regex(code, filename) + _scan_ast(code, filename):
        key = (f.vuln_type, f.line)
        if key not in combined or f.confidence > combined[key].confidence:
            combined[key] = f
    return list(combined.values())
