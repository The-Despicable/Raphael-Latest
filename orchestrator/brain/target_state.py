"""target_state.py — per-target security posture model.

Tracks detected technologies, known CVEs, patch status, detection stack,
and detection incidents. Persisted via neural_memory's target_profiles table.

V3 AttackGraph: NetworkX-based directed graph with Bayesian probabilistic updates.
"""

import re
import json
import time
import math
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime
from typing import Optional

from orchestrator.brain.neural_memory import (
    store_target_profile, get_target_profile, store_semantic, retrieve_semantic,
)

# ============================================================
# V3 Attack Graph — NetworkX Directed Graph + Bayesian Updates
# ============================================================

class TechniqueStatus(Enum):
    PENDING = auto()
    RUNNING = auto()
    SUCCEEDED = auto()
    FAILED = auto()
    BLOCKED = auto()

class CompromiseLevel(Enum):
    NONE = auto()
    RECONNAISSANCE = auto()
    LOW_PRIVILEGE = auto()
    ADMINISTRATIVE = auto()
    DOMINATED = auto()

@dataclass(frozen=True, slots=True)
class Technique:
    technique_id: str
    name: str
    mitre_url: Optional[str] = None
    required_tools: tuple[str, ...] = ()
    stealth_score: float = 0.5
    max_repeats: int = 3

try:
    import networkx as nx
    from networkx.readwrite import json_graph
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


class AttackGraph:
    def __init__(self, target_domain: str) -> None:
        self._target = target_domain
        self._G = nx.DiGraph() if HAS_NETWORKX else None
        self._nodes: dict = {}
        self._edges: list = []

    def add_host(self, host_id: str, *, compromised: bool = False, criticality: float = 0.0) -> None:
        if self._G is not None:
            self._G.add_node(host_id, type="host", compromised=compromised, criticality=criticality, discovered_at=datetime.utcnow().isoformat())
        self._nodes[host_id] = {"type": "host", "compromised": compromised, "criticality": criticality}

    def add_service(self, host_id: str, service_id: str, port: int, version: Optional[str] = None) -> None:
        node_id = f"{host_id}:{service_id}"
        if self._G is not None:
            self._G.add_node(node_id, type="service", port=port, version=version, compromised=False)
            self._G.add_edge(host_id, node_id, relation="runs")
        self._nodes[node_id] = {"type": "service", "port": port, "version": version, "compromised": False}

    def add_technique_edge(
        self, from_state: str, to_state: str, technique: Technique,
        *, preconditions: Optional[set[str]] = None
    ) -> None:
        if self._G is not None:
            self._G.add_edge(
                from_state, to_state, technique=technique,
                status=TechniqueStatus.PENDING, preconditions=preconditions or set(),
                success_prob=0.5, attempts=0, successes=0, history=[],
            )
        self._edges.append({
            "from": from_state, "to": to_state, "technique": technique.technique_id,
            "status": "PENDING", "success_prob": 0.5, "attempts": 0, "successes": 0,
        })

    def update_from_result(self, edge_id: tuple[str, str], success: bool, notes: Optional[str] = None) -> float:
        if self._G is None:
            return 0.5
        edge = self._G.edges[edge_id]
        edge["attempts"] += 1
        if success:
            edge["successes"] += 1
            edge["status"] = TechniqueStatus.SUCCEEDED
        else:
            edge["status"] = TechniqueStatus.FAILED
        alpha = 1 + edge["successes"]
        beta = 1 + (edge["attempts"] - edge["successes"])
        posterior = alpha / (alpha + beta)
        edge["success_prob"] = posterior
        edge["history"].append({"timestamp": datetime.utcnow().isoformat(), "success": success, "notes": notes})
        return posterior

    def get_riskiest_path(self, start: str, goal: str, *, risk_tolerance: float = 0.3, max_depth: int = 10) -> list:
        if self._G is None or not HAS_NETWORKX:
            return []
        try:
            path = nx.shortest_path(self._G, source=start, target=goal)
            result = []
            for i in range(len(path) - 1):
                edge_data = self._G.edges[path[i], path[i + 1]]
                result.append((path[i], path[i + 1], edge_data.get("technique", Technique("T", "unknown"))))
            return result[:max_depth]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def compromise(self, node_id: str, level: CompromiseLevel) -> None:
        if self._G is not None and node_id in self._G:
            self._G.nodes[node_id]["compromised"] = True
            self._G.nodes[node_id]["compromise_level"] = level.name
        if node_id in self._nodes:
            self._nodes[node_id]["compromised"] = True

    def get_optimal_next_step(self, current: str, goals: list[str]) -> Optional[tuple]:
        if self._G is None:
            return None
        best = None
        best_score = -float('inf')
        for goal in goals:
            path = self.get_riskiest_path(current, goal)
            if path and len(path) > 0:
                step = path[0]
                edge = self._G.edges[step[0], step[1]]
                score = edge.get("success_prob", 0.5) * edge.get("technique", Technique("T", "")).stealth_score
                if score > best_score:
                    best_score = score
                    best = step
        return best

    def is_technique_available(self, edge_id: tuple[str, str]) -> bool:
        if self._G is None:
            return True
        edge = self._G.edges.get(edge_id)
        if edge is None:
            return False
        tech: Technique = edge.get("technique", Technique("T", ""))
        return edge["attempts"] < tech.max_repeats and edge["status"] not in (TechniqueStatus.SUCCEEDED, TechniqueStatus.BLOCKED)

    def snapshot(self, path: Path) -> None:
        if self._G is not None and HAS_NETWORKX:
            data = json_graph.node_link_data(self._G)
            path.write_text(json.dumps({"target": self._target, "graph": data}, default=str))

    @classmethod
    def from_snapshot(cls, path: Path) -> "AttackGraph":
        loaded = json.loads(path.read_text())
        instance = cls(loaded["target"])
        if HAS_NETWORKX:
            instance._G = json_graph.node_link_graph(loaded["graph"])
        return instance

    def get_attack_surface(self) -> list[str]:
        if self._G is None:
            return list(self._nodes.keys())
        return [n for n, d in self._G.nodes(data=True) if not d.get("compromised", False)]

    def estimate_time_to_compromise(self, path: list) -> float:
        total_time = 0.0
        if self._G is None:
            return 60.0
        for from_node, to_node, tech in path:
            edge = self._G.edges.get((from_node, to_node), {})
            prob = edge.get("success_prob", 0.5)
            attempts_needed = math.ceil(1.0 / max(prob, 0.01))
            total_time += attempts_needed * 30.0
        return total_time

COMMON_CVES = {
    "apache": {
        2.4: {"CVE-2021-41773": "Path traversal RCE", "CVE-2021-42013": "Path traversal RCE (bypass)"},
        2.2: {"CVE-2017-9798": "Optionsbleed", "CVE-2015-0228": "mod_lua DoS"},
    },
    "tomcat": {
        9.0: {"CVE-2020-1938": "AJP Ghostcat", "CVE-2024-21733": "Session fixation"},
        8.5: {"CVE-2020-1938": "AJP Ghostcat", "CVE-2024-23672": "Open redirect"},
    },
    "openssh": {
        8.0: {"CVE-2024-6387": "regreSSHion RCE (signal handler race)"},
        7.7: {"CVE-2018-15473": "Username enumeration", "CVE-2024-6387": "regreSSHion RCE"},
    },
    "iis": {
        10.0: {"CVE-2021-31166": "HTTP Protocol Stack DoS", "CVE-2023-36434": "Remote code execution"},
        8.5: {"CVE-2015-1635": "MS15-034 HTTP.sys DoS"},
    },
    "oracle": {
        19.0: {"CVE-2024-21161": "Oracle DB pre-authentication RCE", "CVE-2023-21912": "Oracle DB SQL injection"},
        12.2: {"CVE-2023-21827": "Oracle DB PL/SQL RCE"},
    },
    "mssql": {
        2022: {"CVE-2024-3329": "Linked Server RCE", "CVE-2023-21704": "SQL Server sp_configure RCE"},
        2019: {"CVE-2023-21704": "SQL Server sp_configure RCE", "CVE-2022-22947": "Spring Cloud Gateway RCE"},
    },
}

DETECTION_STACK_SIGNATURES = [
    (r'(?i)mod_security|modsecurity|secrule', 'ModSecurity WAF'),
    (r'(?i)cloudflare|__cfduid|cf-ray', 'Cloudflare WAF'),
    (r'(?i)akamai|akamaighost', 'Akamai WAF'),
    (r'(?i)crowdstrike|falcon', 'CrowdStrike EDR'),
    (r'(?i)sentinelone|singularity', 'SentinelOne EDR'),
    (r'(?i)sysmon|sysinternal', 'Sysmon'),
    (r'(?i)defender|microsoft.*edr|mde|microsoft defender', 'Microsoft Defender EDR'),
    (r'(?i)wazuh|ossec', 'Wazuh SIEM'),
    (r'(?i)splunk', 'Splunk SIEM'),
    (r'(?i)elastic|elasticsearch|kibana', 'Elastic SIEM'),
    (r'(?i)qradar|qradar', 'QRadar SIEM'),
    (r'(?i)arcsight', 'ArcSight SIEM'),
    (r'(?i)proofpoint|etpro', 'Proofpoint Email Security'),
]


def _extract_versions(tech_stack: list) -> dict:
    versions = {}
    for item in tech_stack:
        item = item.strip()
        for svc_name in COMMON_CVES:
            if svc_name in item.lower():
                m = re.search(r'(\d+\.\d+)', item)
                if m:
                    versions[svc_name] = float(m.group(1))
                break
    return versions


def _detect_cves(versions: dict) -> list:
    cves = []
    for svc, ver in versions.items():
        svc_data = COMMON_CVES.get(svc, {})
        best_match = None
        for known_ver in sorted(svc_data.keys(), reverse=True):
            if ver >= known_ver:
                best_match = known_ver
                break
        if best_match:
            for cve_id, desc in svc_data[best_match].items():
                cves.append({"cve": cve_id, "description": desc, "version": str(best_match)})
    return cves


def _detect_detection_stack(profile: dict) -> list:
    text = json.dumps(profile).lower()
    detected = []
    for pattern, name in DETECTION_STACK_SIGNATURES:
        if re.search(pattern, text):
            detected.append({"name": name, "source": "recon_signature"})
    return detected


def build_target_state(target: str, profile: dict) -> dict:
    versions = _extract_versions(profile.get("tech_stack", []))
    cves = _detect_cves(versions)
    detections = _detect_detection_stack(profile)
    tech = [t.strip() for t in profile.get("tech_stack", [])]

    state = {
        "target": target,
        "updated_at": time.time(),
        "technologies": tech,
        "versions": versions,
        "cves": cves,
        "patched_cves": [],
        "unpatched_cves": [c["cve"] for c in cves],
        "patch_status": "unknown",
        "detection_stack": detections,
        "detection_count": len(detections),
        "risk_score": _calculate_risk(cves, detections),
        "engagement_incidents": [],
    }

    if cves:
        state["patch_status"] = "likely_unpatched" if len(cves) > 2 else "mixed"
    if detections:
        state["patch_status"] = "unknown"

    store_target_profile(target, {"state": state})
    return state


def _calculate_risk(cves: list, detections: list) -> int:
    score = 5
    score += len(cves) * 2
    if any("RCE" in c["description"] for c in cves):
        score += 5
    score -= len(detections) * 3
    return max(1, min(10, score))


def get_target_state(target: str) -> dict:
    cached = get_target_profile(target)
    if cached and "state" in cached.get("profile", {}):
        return cached["profile"]["state"]
    return {}


def record_detection_incident(target: str, incident: dict):
    state = get_target_state(target)
    if not state:
        return
    if "engagement_incidents" not in state:
        state["engagement_incidents"] = []
    incident["timestamp"] = time.time()
    state["engagement_incidents"].append(incident)
    state["detection_count"] = len(state["engagement_incidents"])
    store_target_profile(target, {"state": state})


def mark_cve_patched(target: str, cve_id: str):
    state = get_target_state(target)
    if not state:
        return
    if cve_id in state.get("unpatched_cves", []):
        state["unpatched_cves"].remove(cve_id)
        state.setdefault("patched_cves", []).append(cve_id)
        state["patch_status"] = "mixed" if state["unpatched_cves"] else "fully_patched"
        store_target_profile(target, {"state": state})


def build_vulnu_state(service: str = "www") -> dict:
    VULNU_PROFILES = {
        "www": {
            "target": "vulnu-lab-www (CentOS 6 / Apache 2.2 / PHP 5.6)",
            "tech_stack": [
                "apache 2.2.15",
                "php 5.6.31",
                "centos 6",
                "mysql 5.7",
            ],
            "vulnerabilities": [
                {"type": "sqli", "endpoint": "/login.php", "param": "username", "method": "POST", "severity": "critical", "flag": "FLAG{user_db_sqli}"},
                {"type": "sqli", "endpoint": "/search.php", "param": "q", "method": "GET", "severity": "high"},
                {"type": "lfi", "endpoint": "/page.php", "param": "file", "method": "GET", "severity": "high", "path": "/etc/passwd"},
                {"type": "file_upload", "endpoint": "/profile/avatar.php", "param": "avatar", "method": "POST", "severity": "critical", "extension": ".php"},
                {"type": "info_disclosure", "endpoint": "/db_backup.sql", "method": "GET", "severity": "medium"},
                {"type": "directory_listing", "endpoint": "/admin/", "method": "GET", "severity": "low"},
                {"type": "directory_listing", "endpoint": "/backup/", "method": "GET", "severity": "low"},
            ],
        },
        "www-flask": {
            "target": "vulnu-lab-www-flask (Python Flask CMS)",
            "tech_stack": [
                "python 3.9",
                "flask",
                "sqlite",
            ],
            "vulnerabilities": [
                {"type": "sqli", "endpoint": "/login", "param": "username", "method": "POST", "severity": "critical", "flag": "FLAG{user_db_sqli}"},
                {"type": "sqli", "endpoint": "/search", "param": "q", "method": "GET", "severity": "high"},
                {"type": "lfi", "endpoint": "/page", "param": "file", "method": "GET", "severity": "high"},
                {"type": "file_upload", "endpoint": "/upload", "param": "file", "method": "POST", "severity": "critical"},
            ],
        },
        "ums": {
            "target": "vulnu-lab-ums-flask (Python Flask UMS)",
            "tech_stack": [
                "python 3.9",
                "flask",
            ],
            "vulnerabilities": [
                {"type": "idor", "endpoint": "/students/view", "param": "id", "method": "GET", "severity": "high", "note": "No auth check, iterable IDs"},
                {"type": "mass_assignment", "endpoint": "/api/profile/update", "method": "POST", "severity": "medium", "note": "No field whitelist"},
                {"type": "info_disclosure", "endpoint": "/api/health", "method": "GET", "severity": "low", "note": "Debug endpoint leaks config"},
            ],
        },
        "nertu": {
            "target": "vulnu-lab-nertu (Tomcat 9 / Oracle JSP)",
            "tech_stack": [
                "tomcat 9.0",
                "oracle 21",
                "java 11",
            ],
            "vulnerabilities": [
                {"type": "sqli", "endpoint": "/res07/2025.jsp", "param": "id", "method": "GET", "severity": "critical", "db": "Oracle XE"},
                {"type": "ghostcat", "endpoint": "ajp://host:8009/", "cve": "CVE-2020-1938", "severity": "critical"},
            ],
        },
    }

    profile_data = VULNU_PROFILES.get(service, VULNU_PROFILES["www"])
    state = build_target_state(profile_data["target"], profile_data)
    state["vulnu_service"] = service
    state["vulnu_vulnerabilities"] = profile_data["vulnerabilities"]
    state["risk_score"] = max(7, state["risk_score"])
    return state


def list_vulnu_services() -> list:
    return ["www", "www-flask", "ums", "nertu"]


def summarize_target_state(target: str) -> str:
    state = get_target_state(target)
    if not state:
        return f"No state data for {target}"

    lines = [f"Target: {target}"]
    lines.append(f"  Technologies ({len(state.get('technologies', []))}):")
    for t in state.get("technologies", [])[:8]:
        lines.append(f"    - {t}")
    if state.get("versions"):
        lines.append(f"  Detected versions: {state['versions']}")
    lines.append(f"  CVEs: {len(state.get('cves', []))} found, {len(state.get('patched_cves', []))} patched")
    for cve in state.get("cves", [])[:5]:
        lines.append(f"    {cve['cve']}: {cve['description']} (v{cve['version']})")
    lines.append(f"  Detection stack ({state.get('detection_count', 0)}):")
    for d in state.get("detection_stack", []):
        lines.append(f"    {d['name']}")
    lines.append(f"  Risk score: {state.get('risk_score', '?')}/10")
    if state.get("engagement_incidents"):
        lines.append(f"  Engagements: {len(state['engagement_incidents'])} incidents")
    vuln_vulns = state.get("vulnu_vulnerabilities", [])
    if vuln_vulns:
        lines.append(f"  VulnU vulnerabilities ({len(vuln_vulns)}):")
        for v in vuln_vulns[:8]:
            lines.append(f"    {v['type']} @ {v['endpoint']} [{v['severity']}]")
    return "\n".join(lines)
