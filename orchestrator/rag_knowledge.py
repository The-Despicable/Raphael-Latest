"""
RAG Knowledge Base — grounded endpoint facts for Gemma4 (and other models).

Builds a searchable vector index from the OrbitalCI target's actual routes,
methods, parameters, and vulnerability descriptions. Models query this before
generating exploit code to eliminate endpoint hallucination.

Usage:
  from orchestrator.rag_knowledge import query_rag
  results = query_rag("LDAP injection endpoint")
"""

from typing import List, Optional
from enum import Enum
from dataclasses import dataclass, fields
from pathlib import Path
import json
import numpy as np

DOCUMENTS = []

_CURATED = [
        {"url": "/login", "methods": "GET, POST", "function": "login", "description": "Login form with SQL injection in username field"},
        {"url": "/register", "methods": "GET, POST", "function": "register", "description": "User registration with homoglyph username bypass"},
        {"url": "/reset-password", "methods": "GET, POST", "function": "reset_password", "description": "Password reset with predictable MD5 token"},
        {"url": "/reset-password/confirm", "methods": "POST", "function": "reset_confirm", "description": "Reset confirmation with brute-forceable token window"},
        {"url": "/dashboard", "methods": "GET", "function": "dashboard", "description": "User dashboard, requires auth"},
        {"url": "/directory", "methods": "GET, POST", "function": "directory", "description": "LDAP injection authentication bypass with wildcard password"},
        {"url": "/pipelines", "methods": "GET", "function": "pipelines", "description": "Pipeline listing with IDOR (all users' pipelines)"},
        {"url": "/pipelines/<int:pid>", "methods": "GET", "function": "pipeline_detail", "description": "Pipeline detail view"},
        {"url": "/pipelines/<int:pid>/run", "methods": "POST", "function": "pipeline_run", "description": "Run pipeline — eval() RCE on stored condition_expr"},
        {"url": "/pipelines/<int:pid>/summary", "methods": "GET", "function": "pipeline_summary", "description": "Pipeline summary with stored SSTI in template_name"},
        {"url": "/pipelines/new", "methods": "POST", "function": "pipelines_new", "description": "Create new pipeline with raw template_name and condition_expr"},
        {"url": "/pipelines/search", "methods": "GET", "function": "pipelines_search", "description": "Pipeline search (parameterized — control, not vulnerable)"},
        {"url": "/reports", "methods": "GET", "function": "reports", "description": "Report selection page"},
        {"url": "/reports/render", "methods": "GET", "function": "reports_render", "description": "Report render with LFI path traversal + Jinja2 SSTI"},
        {"url": "/tools", "methods": "GET", "function": "tools", "description": "Tools page"},
        {"url": "/tools/cloud-fetch", "methods": "POST", "function": "tools_cloud_fetch", "description": "SSRF via URL fetch with blocklist bypass"},
        {"url": "/tools/calc", "methods": "POST", "function": "tools_calc", "description": "Calculator (ast.literal_eval — control, not vulnerable)"},
        {"url": "/redirect", "methods": "GET", "function": "open_redirect", "description": "Open redirect — also chains around SSRF blocklist"},
        {"url": "/internal/cloud/latest/meta-data", "methods": "GET", "function": "cloud_metadata", "description": "Mock IMDS metadata endpoint with fake AWS credentials"},
        {"url": "/webhooks/deploy", "methods": "POST", "function": "webhook_deploy", "description": "Webhook deploy with timing-unsafe HMAC comparison"},
        {"url": "/webhooks/notify", "methods": "POST", "function": "webhook_notify", "description": "Webhook notify with constant-time HMAC (control)"},
        {"url": "/api/v3/token", "methods": "POST", "function": "api_v3_token", "description": "Issue JWT — kid header controls signing key file path"},
        {"url": "/api/v3/me", "methods": "GET", "function": "api_v3_me", "description": "Get current user from JWT"},
        {"url": "/api/v3/profile", "methods": "PUT", "function": "api_v3_profile", "description": "Update profile — nested mass-assignment bypass"},
        {"url": "/api/v3/health", "methods": "GET", "function": "api_v3_health", "description": "Health check"},
        {"url": "/api/v1/users", "methods": "GET", "function": "api_v1_users_shadow", "description": "Shadow API — all users with password hashes, no auth"},
        {"url": "/api/v1/pipelines", "methods": "GET", "function": "api_v1_pipelines_shadow", "description": "Shadow API — all pipelines, no auth"},
        {"url": "/api/docs", "methods": "GET", "function": "api_docs", "description": "API documentation page"},
        {"url": "/logout", "methods": "GET", "function": "logout", "description": "Logout and clear session"},
        {"url": "/", "methods": "GET", "function": "index", "description": "Root — redirects to /login"},
        # --- HTB-style challenge patterns ---
        {"url": "/api/options", "methods": "GET", "function": "api_options", "description": "HTB game challenge — returns all valid commands including secret/Easter egg keys that reveal flags"},
        {"url": "/api/monitor", "methods": "POST", "function": "api_monitor", "description": "HTB game challenge — submit a command; returns flag if the secret hidden command is used"},
    ]

WAF_KNOWLEDGE = [
    {"waf": "ModSecurity", "bypass": "Oracle XMLType() payloads", "phase": "exploit",
     "description": "ModSecurity blocks SELECT/UNION keywords. Use XMLType() or JSON_TABLE to wrap SQL"},
    {"waf": "ModSecurity", "bypass": "Unicode normalization (\\u0130, \\u017F)", "phase": "exploit",
     "description": "UTF-8 overlong sequences bypass ModSecurity rule matching on ASCII keywords"},
    {"waf": "ModSecurity", "bypass": "HTTP Parameter Pollution (HPP)", "phase": "exploit",
     "description": "Repeat parameter multiple times: ?id=1&id=2. WAF inspects first; app uses last"},
    {"waf": "Cloudflare", "bypass": "Content-Type mutation", "phase": "exploit",
     "description": "Change Content-Type to multipart/form-data with boundary to bypass Cloudflare WAF"},
    {"waf": "Cloudflare", "bypass": "Origin header injection", "phase": "postex",
     "description": "Set Origin header to internal domain to bypass Cloudflare access rules"},
    {"waf": "Akamai", "bypass": "Case variation + comment injection", "phase": "exploit",
     "description": "Mix case and inject inline comments: Sel/**/ect * Fr/**/om users"},
    {"waf": "Generic", "bypass": "JSON-based payload wrapping", "phase": "exploit",
     "description": "Wrap attack payload in JSON: {\"param\": \"<payload>\"} — WAFs often skip JSON bodies"},
    {"waf": "Generic", "bypass": "Base64/hex encoding on parameter value", "phase": "exploit",
     "description": "Encode parameter value, decode server-side: ?data=<base64>"},
    {"waf": "Generic", "bypass": "IP allowlist spoofing via X-Forwarded-For", "phase": "recon",
     "description": "Set X-Forwarded-For to internal/trusted IP range to bypass IP-based WAF rules"},
]

FORENSICS_KNOWLEDGE = [
    {"platform": "centos", "type": "log_paths", "paths": "/var/log/messages, /var/log/secure, /var/log/httpd/",
     "commands": "journalctl --rotate; truncate -s0 /var/log/*; rm -f /var/log/httpd/access_log"},
    {"platform": "centos", "type": "timestamp", "tool": "touch -t",
     "description": "Timestomping: touch -t 202401010000.00 <file> to backdate log entries"},
    {"platform": "windows", "type": "log_paths", "paths": "C:\\inetpub\\logs\\LogFiles, C:\\Windows\\System32\\winevt\\Logs",
     "commands": "wevtutil cl System; wevtutil cl Security; wevtutil cl Application"},
    {"platform": "windows", "type": "etw", "tool": "ETW patch via DKOM",
     "description": "Patch EtwEventWrite() in ntdll to suppress ETW telemetry. Use direct syscalls to bypass userland hooks"},
    {"platform": "windows", "type": "usn_journal", "commands": "fsutil usn deletejournal /D C:",
     "description": "Delete USN journal to erase NTFS change records"},
    {"platform": "tomcat", "type": "log_paths", "paths": "/var/log/tomcat/catalina.out, /var/log/tomcat/localhost_access_log*",
     "commands": "rm -f /var/log/tomcat/catalina.out; rm -f /var/log/tomcat/localhost_access_log*"},
    {"platform": "tomcat", "type": "jsp_cache", "paths": "/usr/share/tomcat/work/Catalina/localhost/",
     "description": "JSP compilation cache poisoning: replace compiled .class files in work directory"},
    {"platform": "oracle", "type": "audit_trail", "table": "SYS.AUD$",
     "commands": "DELETE FROM SYS.AUD$; ALTER SYSTEM SET audit_trail=NONE SCOPE=SPFILE;",
     "description": "Delete Oracle audit records and disable auditing. Use flashback recovery to restore"},
    {"platform": "oracle", "type": "fga", "commands": "EXEC DBMS_FGA.DROP_POLICY(...)",
     "description": "Disable Fine-Grained Auditing policies to suppress audit generation"},
    {"platform": "mssql", "type": "audit", "commands": "ALTER SERVER AUDIT ... WITH (STATE=OFF); DROP SERVER AUDIT;",
     "description": "Disable and drop MSSQL Server Audit objects"},
    {"platform": "mssql", "type": "error_log", "commands": "EXEC sp_cycle_errorlog; DBCC TRACEOFF(152)",
     "description": "Cycle error log and disable trace flag 152 (xp_cmdshell audit)"},
    {"platform": "linux", "type": "auth_logs", "paths": "/var/log/auth.log, /var/log/syslog, ~/.bash_history",
     "commands": "shred -u ~/.bash_history; > ~/.bash_history; history -c"},
]

MIMICRY_KNOWLEDGE = [
    {"pattern": "temporal_coherence", "description": "Space actions 3-7 minutes apart",
     "details": "Random delay between 180-420s. Uniform distribution, not gaussian (too regular)"},
    {"pattern": "business_hours", "description": "India IST (UTC+5:30) 09:00-17:00, weekdays only",
     "details": "No activity outside business hours. Avoid lunch 12:00-13:00 for higher-value targets"},
    {"pattern": "data_velocity", "recon": "10-50 req/min", "exploit": "<10 req/min", "exfil": "<50KB/min",
     "description": "Match expected traffic patterns. Slow for exploitation, moderate for recon"},
    {"pattern": "process_lineage", "windows": "svchost.exe -> rundll32.exe -> powershell.exe",
     "linux": "systemd -> cron -> python3",
     "description": "Ensure spawned processes descend from legitimate parent chains"},
    {"pattern": "credential_drift", "description": "Rotate credentials after 2-3 uses. Never reuse tokens across sessions",
     "details": "Reuse triggers anomaly detection. Generate fresh session per operation"},
    {"pattern": "user_agent_rotation", "description": "Rotate User-Agent per session, match browser version",
     "details": "Chrome 131 for Windows, Chrome 131 for Linux, Safari 18 for macOS"},
]

DKOM_KNOWLEDGE = [
    {"technique": "ETW Patching", "target": "ntdll!EtwEventWrite",
     "method": "Patch EtwEventWrite() first 8 bytes with RET (0xC3) to suppress ETW telemetry",
     "detection_risk": "Silent room anomaly — missing ETW events detectable by baseline comparison"},
    {"technique": "DKOM", "target": "_EPROCESS",
     "method": "Direct Kernel Object Manipulation via \\Device\\PhysicalMemory. Hide processes by unlinking from PsActiveProcessHead",
     "detection_risk": "Detectable by scanning for double-linked list inconsistencies (EPROCESS flink/blink)"},
    {"technique": "Direct Syscalls", "target": "ntdll!Nt* stubs",
     "method": "Resolve syscall numbers at runtime via HellsGate/HalosGate. Skip userland hooks completely",
     "detection_risk": "Syscall number mismatch across Windows versions. Use Halo's Gate to find valid syscalls via ntoskrnl.exe"},
    {"technique": "Module Overloading", "target": "ntdll.dll",
     "method": "Load a new copy of ntdll.dll from disk, overwrite the hooked .text section with clean code",
     "detection_risk": "Module hash mismatch detectable by integrity scanners (Kaspersky)"},
    {"technique": "Thread Hijacking", "target": "suspended thread in svchost.exe",
     "method": "Open target thread with NtOpenThread, suspend via NtSuspendThread, set context via NtSetContextThread, resume",
     "detection_risk": "Thread start address in suspended thread may point outside known modules"},
    {"technique": "Callback Removal", "target": "ntoskrnl.exe!CmRegisterCallback",
     "description": "Remove registry callback registration to prevent AV/EDR from monitoring registry operations",
     "detection_risk": "Callback array size mismatch — use \\\\.\\Nsi device object to enumerate"},
]


def _build_document_text(route: dict) -> str:
    parts = [
        f"Endpoint: {route['url']}",
        f"Methods: {route['methods']}",
        f"Function: {route['function']}",
    ]
    if route.get("description"):
        parts.append(f"Description: {route['description']}")
    return " | ".join(parts)


def _init_docs():
    global DOCUMENTS
    if DOCUMENTS:
        return
    for r in _CURATED:
        DOCUMENTS.append({"text": _build_document_text(r), "url": r["url"], "methods": r["methods"], "function": r["function"], "description": r.get("description", "")})


# ── Embedding: character n-gram → TF-IDF-like vector ─────────────────────────

NGRAM_RANGE = (2, 5)  # char n-gram size range


def _tokenize(text: str) -> dict:
    """Build char n-gram frequency dict."""
    text = text.lower()
    freqs = {}
    for n in range(NGRAM_RANGE[0], NGRAM_RANGE[1] + 1):
        for i in range(len(text) - n + 1):
            gram = text[i:i + n]
            freqs[gram] = freqs.get(gram, 0) + 1
    return freqs


def _build_vocab(docs: list) -> dict:
    vocab = {}
    for doc in docs:
        for gram in _tokenize(doc["text"]):
            if gram not in vocab:
                vocab[gram] = len(vocab)
    return vocab


def _vectorize(tokens: dict, vocab: dict, vocab_size: int) -> np.ndarray:
    vec = np.zeros(vocab_size, dtype=np.float32)
    for gram, freq in tokens.items():
        if gram in vocab:
            idx = vocab[gram]
            vec[idx] = 1.0 + np.log(freq)
    return vec


def _cosine_sim(a: np.ndarray, b: np.ndarray) -> float:
    denom = (np.linalg.norm(a) * np.linalg.norm(b))
    return float(np.dot(a, b) / denom) if denom > 0 else 0.0


# ── Public API ────────────────────────────────────────────────────────────────

_index_cache = None


def _build_index():
    global _index_cache
    _init_docs()
    vocab = _build_vocab(DOCUMENTS)
    vocab_size = len(vocab)
    matrix = np.zeros((len(DOCUMENTS), vocab_size), dtype=np.float32)
    for i, doc in enumerate(DOCUMENTS):
        toks = _tokenize(doc["text"])
        matrix[i] = _vectorize(toks, vocab, vocab_size)
    _index_cache = {"matrix": matrix, "vocab": vocab, "vocab_size": vocab_size, "docs": DOCUMENTS.copy()}


def query_rag(query: str, top_k: int = 3) -> List[dict]:
    """Search the RAG knowledge base and return top-k matching endpoint docs.

    Returns list of dicts: [{url, methods, function, description, similarity}, ...]
    """
    _init_docs()
    if not DOCUMENTS:
        return [{"text": "No target documents loaded. Run RAG setup first.", "similarity": 0.0}]

    if _index_cache is None:
        _build_index()

    q_toks = _tokenize(query)
    q_vec = _vectorize(q_toks, _index_cache["vocab"], _index_cache["vocab_size"])
    matrix = _index_cache["matrix"]

    sims = [_cosine_sim(q_vec, matrix[i]) for i in range(len(_index_cache["docs"]))]
    top_idx = sorted(range(len(sims)), key=lambda i: sims[i], reverse=True)[:top_k]

    results = []
    for idx in top_idx:
        doc = _index_cache["docs"][idx]
        results.append({
            "url": doc["url"],
            "methods": doc["methods"],
            "function": doc["function"],
            "description": doc.get("description", ""),
            "text": doc["text"],
            "similarity": round(sims[idx], 4),
        })
    return results


def list_all_endpoints() -> List[dict]:
    """Return every known endpoint (no search — for complete context)."""
    _init_docs()
    return [{"url": d["url"], "methods": d["methods"], "function": d["function"], "description": d.get("description", "")} for d in DOCUMENTS]


def _get_corpus(corpus_name: str) -> list:
    corpora = {
        "endpoints": _CURATED,
        "waf": WAF_KNOWLEDGE,
        "forensics": FORENSICS_KNOWLEDGE,
        "mimicry": MIMICRY_KNOWLEDGE,
        "dkom": DKOM_KNOWLEDGE,
    }
    return corpora.get(corpus_name, _CURATED)


def _build_corpus_text(item: dict, corpus: str) -> str:
    if corpus == "endpoints":
        return _build_document_text(item)
    if corpus == "waf":
        return f"WAF: {item.get('waf', '?')} | Bypass: {item.get('bypass', '?')} | Phase: {item.get('phase', '?')} | Description: {item.get('description', '?')}"
    if corpus == "forensics":
        return f"Platform: {item.get('platform', '?')} | Type: {item.get('type', '?')} | Paths: {item.get('paths', '')} | Commands: {item.get('commands', '')} | Description: {item.get('description', '')}"
    if corpus == "mimicry":
        return f"Pattern: {item.get('pattern', '?')} | Description: {item.get('description', '?')} | Details: {item.get('details', '')}"
    if corpus == "dkom":
        return f"Technique: {item.get('technique', '?')} | Target: {item.get('target', '?')} | Method: {item.get('method', '')} | Detection Risk: {item.get('detection_risk', '')}"
    return str(item)


def query_knowledge_base(query: str, corpus: str = "endpoints", top_k: int = 3) -> List[dict]:
    items = _get_corpus(corpus)
    if not items:
        return []
    docs = [{"text": _build_corpus_text(item, corpus), **item} for item in items]
    if not query:
        return docs[:top_k]
    vocab = _build_vocab(docs)
    vocab_size = len(vocab)
    matrix = np.zeros((len(docs), vocab_size), dtype=np.float32)
    for i, doc in enumerate(docs):
        toks = _tokenize(doc["text"])
        matrix[i] = _vectorize(toks, vocab, vocab_size)
    q_toks = _tokenize(query)
    q_vec = _vectorize(q_toks, vocab, vocab_size)
    sims = [_cosine_sim(q_vec, matrix[i]) for i in range(len(docs))]
    top_idx = sorted(range(len(sims)), key=lambda i: sims[i], reverse=True)[:top_k]
    results = []
    for idx in top_idx:
        r = dict(docs[idx])
        r["similarity"] = round(sims[idx], 4)
        results.append(r)
    return results


def query_waf_rag(query: str, top_k: int = 3) -> List[dict]:
    return query_knowledge_base(query, corpus="waf", top_k=top_k)


def query_forensics_rag(query: str, top_k: int = 3) -> List[dict]:
    return query_knowledge_base(query, corpus="forensics", top_k=top_k)


def query_mimicry_rag(query: str, top_k: int = 3) -> List[dict]:
    return query_knowledge_base(query, corpus="mimicry", top_k=top_k)


def query_dkom_rag(query: str, top_k: int = 3) -> List[dict]:
    return query_knowledge_base(query, corpus="dkom", top_k=top_k)


# ============================================================
# V3 WAF Bypass Knowledge Base — Technique-Centric + Multi-Index
# ============================================================

class WAFVendor(Enum):
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    MODSECURITY = "modsecurity"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class BypassTechnique:
    name: str
    description: str
    applicable_wafs: tuple[WAFVendor, ...]
    injection_contexts: tuple[str, ...] = ("query",)
    payload_transforms: tuple[str, ...] = ()
    related_cves: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    success_count: int = 0
    attempt_count: int = 0

    @property
    def efficacy(self) -> float:
        if self.attempt_count == 0:
            return 0.5
        return self.success_count / self.attempt_count

@dataclass(frozen=True)
class WAFProfile:
    vendor: WAFVendor
    detected_rules: tuple[str, ...] = ()
    response_signatures: tuple[str, ...] = ()

class WAFBypassKnowledgeBase:
    def __init__(self, db_path: Optional[str] = None) -> None:
        self._techniques: dict[str, BypassTechnique] = {}
        self._by_waf: dict[WAFVendor, set[str]] = {w: set() for w in WAFVendor}
        self._by_cve: dict[str, set[str]] = {}
        self._by_context: dict[str, set[str]] = {}
        self._version = "1.0"

    def register(self, technique: BypassTechnique) -> None:
        tid = technique.name
        self._techniques[tid] = technique
        for waf in technique.applicable_wafs:
            self._by_waf[waf].add(tid)
        for cve in technique.related_cves:
            self._by_cve.setdefault(cve, set()).add(tid)
        for ctx in technique.injection_contexts:
            self._by_context.setdefault(ctx, set()).add(tid)

    def query(self, *, waf_profile: Optional[WAFProfile] = None, cve: Optional[str] = None, context: Optional[str] = None, min_efficacy: float = 0.3) -> list[BypassTechnique]:
        candidates: set[str] = set(self._techniques.keys())
        if waf_profile:
            candidates &= self._by_waf.get(waf_profile.vendor, set())
        if cve:
            candidates &= self._by_cve.get(cve, set())
        if context:
            candidates &= self._by_context.get(context, set())
        results = [self._techniques[t] for t in candidates if self._techniques[t].efficacy >= min_efficacy]
        results.sort(key=lambda t: t.efficacy, reverse=True)
        return results

    def identify_waf(self, target: str, session=None) -> WAFProfile:
        return WAFProfile(vendor=WAFVendor.UNKNOWN)

    def record_result(self, technique_id: str, success: bool, waf_profile: WAFProfile) -> None:
        tech = self._techniques.get(technique_id)
        if tech:
            new_counts = dict(success_count=tech.success_count + (1 if success else 0), attempt_count=tech.attempt_count + 1)
            self._techniques[technique_id] = BypassTechnique(**{**{f.name: getattr(tech, f.name) for f in fields(tech)}, **new_counts})

    def get_by_cve(self, cve: str) -> list[BypassTechnique]:
        return [self._techniques[t] for t in self._by_cve.get(cve, set()) if t in self._techniques]

    def get_by_waf(self, vendor: WAFVendor) -> list[BypassTechnique]:
        return [self._techniques[t] for t in self._by_waf.get(vendor, set()) if t in self._techniques]

    def get_transform_chain(self, technique_id: str) -> tuple[str, ...]:
        tech = self._techniques.get(technique_id)
        return tech.payload_transforms if tech else ()

    def save(self, path: Optional[str] = None) -> None:
        p = Path(path or "waf_bypass_kb.json")
        data = {
            "version": self._version,
            "techniques": {k: {"name": v.name, "description": v.description,
                              "applicable_wafs": [w.value for w in v.applicable_wafs],
                              "injection_contexts": list(v.injection_contexts),
                              "payload_transforms": list(v.payload_transforms),
                              "related_cves": list(v.related_cves),
                              "success_count": v.success_count, "attempt_count": v.attempt_count} for k, v in self._techniques.items()}
        }
        p.write_text(json.dumps(data, indent=2))

    def load(self, path: str) -> None:
        data = json.loads(Path(path).read_text())
        self._version = data.get("version", "1.0")
        for t in data.get("techniques", {}).values():
            self.register(BypassTechnique(
                name=t["name"], description=t["description"],
                applicable_wafs=tuple(WAFVendor(w) for w in t.get("applicable_wafs", [])),
                injection_contexts=tuple(t.get("injection_contexts", [])),
                payload_transforms=tuple(t.get("payload_transforms", [])),
                related_cves=tuple(t.get("related_cves", [])),
                success_count=t.get("success_count", 0), attempt_count=t.get("attempt_count", 0),
            ))

    def bump_version(self, major: bool = False) -> str:
        parts = self._version.split(".")
        if major:
            self._version = f"{int(parts[0]) + 1}.0"
        else:
            self._version = f"{parts[0]}.{int(parts[1]) + 1}"
        return self._version


def build_rag_context(query: str = "", top_k: int = 3) -> str:
    """Build a tagged-context string formatted for model prompt injection.

    Returns XML-tagged context block with the endpoint docs most relevant to query.
    """
    if query:
        results = query_rag(query, top_k=top_k)
    else:
        docs = list_all_endpoints()[:top_k]
        results = [dict(d, similarity=0.0) for d in docs]

    parts = ['<context type="target_endpoints">']
    for r in results:
        parts.append(f'  <endpoint url="{r["url"]}" methods="{r["methods"]}">')
        parts.append(f'    <description>{r.get("description", "")}</description>')
        parts.append(f'  </endpoint>')
    parts.append('</context>')
    return '\n'.join(parts)


if __name__ == "__main__":
    _init_docs()
    print(f"Loaded {len(DOCUMENTS)} endpoint documents.")
    print()
    tests = ["LDAP injection", "JWT kid path traversal", "SSRF metadata", "eval RCE", "mass assignment"]
    for t in tests:
        print(f"Query: {t}")
        results = query_rag(t)
        for r in results:
            print(f"  [{r['similarity']:.3f}] {r['url']} ({r['methods']}) — {r['description'][:80]}")
        print()
