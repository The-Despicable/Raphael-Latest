import json, os, subprocess, yaml, sys
from pathlib import Path
from typing import Optional

SKILLS_REPO = Path(os.environ.get("SKILLS_REPO", "/tmp/Anthropic-Cybersecurity-Skills"))
SKILLS_INDEX = SKILLS_REPO / "index.json"
SKILLS_DIR = SKILLS_REPO / "skills"

STRIX_SKILLS_DIR = Path(os.environ.get("STRIX_SKILLS_DIR", "/tmp/strix/strix/skills"))

STRIX_SUBDOMAIN_MAP = {
    "cloud": "cloud-security",
    "coordination": "red-teaming",
    "custom": "penetration-testing",
    "frameworks": "web-application-security",
    "protocols": "web-application-security",
    "scan_modes": "penetration-testing",
    "technologies": "cloud-security",
    "tooling": "penetration-testing",
    "reconnaissance": "threat-intelligence",
    "vulnerabilities": "web-application-security",
}

PIPELINE_MAP = {
    "exploit":     ["web-application-security", "vulnerability-management", "penetration-testing"],
    "scanners":    ["cloud-security", "network-security", "threat-intelligence"],
    "postex":      ["red-teaming", "identity-access-management", "malware-analysis"],
    "proxy_guard": ["network-security", "soc-operations"],
    "anti_forensics": ["digital-forensics", "incident-response"],
    "brain":       ["threat-hunting", "threat-intelligence"],
    "phishing":    ["red-teaming", "identity-access-management"],
    "exfil":       ["cloud-security", "network-security"],
}

def _parse_strix_skill(category: str, file_path: Path) -> dict:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    meta = {"name": file_path.stem, "description": "", "subdomain": STRIX_SUBDOMAIN_MAP.get(category, "unknown"), "tags": [category], "mitre_attack": [], "nist_csf": [], "source": "strix"}
    if content.startswith("---"):
        _, frontmatter, _ = content.split("---", 2)
        fm = yaml.safe_load(frontmatter) or {}
        meta["name"] = fm.get("name", file_path.stem)
        meta["description"] = fm.get("description", "")
        meta["tags"] = [category] + fm.get("tags", [])
    return meta


def _parse_skill_meta(skill_dir: Path) -> dict:
    md_path = skill_dir / "SKILL.md"
    if not md_path.exists():
        return {"name": skill_dir.name, "description": "", "subdomain": "unknown", "tags": [], "mitre_attack": [], "nist_csf": []}
    content = md_path.read_text(encoding="utf-8", errors="replace")
    if not content.startswith("---"):
        return {"name": skill_dir.name, "description": "", "subdomain": "unknown", "tags": [], "mitre_attack": [], "nist_csf": []}
    _, frontmatter, _ = content.split("---", 2)
    meta = yaml.safe_load(frontmatter) or {}
    return {
        "name": meta.get("name", skill_dir.name),
        "description": meta.get("description", ""),
        "subdomain": meta.get("subdomain", "unknown"),
        "tags": meta.get("tags", []),
        "mitre_attack": meta.get("mitre_attack", []),
        "nist_csf": meta.get("nist_csf", []),
    }


class SkillsBridge:
    def __init__(self, repo_path: Optional[Path] = None, strix_path: Optional[Path] = None):
        self.repo_path = Path(repo_path) if repo_path else SKILLS_REPO
        self._raw_index: list[dict] = []
        self._by_subdomain: dict[str, list[dict]] = {}
        self._parsed: dict[str, dict] = {}
        self._strix_enabled = strix_path is not None or STRIX_SKILLS_DIR.exists()
        self._load_index()

    def _load_index(self):
        if SKILLS_INDEX.exists():
            raw = json.loads(SKILLS_INDEX.read_text())
            self._raw_index = raw.get("skills", [])
        else:
            self._raw_index = [{"name": d.name, "path": str(d)} for d in SKILLS_DIR.iterdir() if d.is_dir()]
        if self._strix_enabled:
            self._load_strix_skills()
        for pipeline_name, subdomains in PIPELINE_MAP.items():
            self._by_subdomain[pipeline_name] = []
            for sd in subdomains:
                matched = [s for s in self._raw_index
                           if s.get("subdomain") == sd]
                self._by_subdomain[pipeline_name].extend(matched)

    def _load_strix_skills(self):
        strix_dir = STRIX_SKILLS_DIR
        if not strix_dir.exists():
            return
        for category_dir in strix_dir.iterdir():
            if not category_dir.is_dir() or category_dir.name.startswith("."):
                continue
            for md_file in sorted(category_dir.glob("*.md")):
                if md_file.name == "README.md":
                    continue
                meta = _parse_strix_skill(category_dir.name, md_file)
                strix_name = f"strix:{category_dir.name}/{md_file.stem}"
                self._raw_index.append({
                    "name": strix_name,
                    "description": meta["description"],
                    "domain": "cybersecurity",
                    "path": str(md_file),
                    "source": "strix",
                    "strix_meta": meta,
                })

    def _ensure_parsed(self, name: str) -> dict:
        if name not in self._parsed:
            if name.startswith("strix:"):
                for entry in self._raw_index:
                    if entry.get("name") == name and entry.get("source") == "strix":
                        meta = entry.get("strix_meta", {})
                        self._parsed[name] = {
                            "name": name,
                            "description": meta.get("description", ""),
                            "subdomain": meta.get("subdomain", "unknown"),
                            "tags": meta.get("tags", []),
                            "mitre_attack": meta.get("mitre_attack", []),
                            "nist_csf": meta.get("nist_csf", []),
                            "source": "strix",
                            "path": entry.get("path", ""),
                        }
                        return self._parsed[name]
            skill_dir = SKILLS_DIR / name
            if not skill_dir.exists():
                self._parsed[name] = {"name": name, "subdomain": "unknown", "tags": [], "mitre_attack": [], "nist_csf": []}
            else:
                self._parsed[name] = _parse_skill_meta(skill_dir)
                self._parsed[name]["path"] = str(skill_dir)
        return self._parsed[name]

    def _build_subdomain_index(self):
        self._by_subdomain = {}
        for entry in self._raw_index:
            name = entry.get("name") or Path(entry.get("path", "")).name
            meta = self._ensure_parsed(name)
            sd = meta["subdomain"]
            self._by_subdomain.setdefault(sd, []).append(meta)

    @property
    def subdomain_index(self) -> dict[str, list[dict]]:
        self._build_subdomain_index()
        return self._by_subdomain

    def total_skills(self) -> int:
        return len(self._raw_index)

    def subdomain_counts(self) -> dict[str, int]:
        return {sd: len(skills) for sd, skills in self.subdomain_index.items()}

    def get_subdomains(self) -> dict[str, int]:
        counts = {}
        for entry in self._raw_index:
            name = entry.get("name") or Path(entry.get("path", "")).name
            meta = self._ensure_parsed(name)
            sd = meta.get("subdomain", "unknown")
            counts[sd] = counts.get(sd, 0) + 1
        return counts

    def get_skills_for_subdomain(self, subdomain: str) -> list[dict]:
        return self.subdomain_index.get(subdomain, [])

    def get_skills_for_pipeline(self, pipeline: str) -> list[dict]:
        subdomains = PIPELINE_MAP.get(pipeline, [])
        results = []
        for entry in self._raw_index:
            name = entry.get("name") or Path(entry.get("path", "")).name
            meta = self._ensure_parsed(name)
            if meta.get("subdomain") in subdomains:
                results.append(meta)
        return results

    def get_skills_for_mitre(self, technique_id: str) -> list[dict]:
        matches = []
        for entry in self._raw_index:
            name = entry.get("name") or Path(entry.get("path", "")).name
            meta = self._ensure_parsed(name)
            if technique_id in meta.get("mitre_attack", []):
                matches.append(meta)
        return matches

    def find_skills(self, query: str) -> list[dict]:
        q = query.lower()
        matches = []
        for entry in self._raw_index:
            name = entry.get("name") or Path(entry.get("path", "")).name
            if q in name.lower():
                meta = self._ensure_parsed(name)
                matches.append(meta)
        return matches

    def execute_skill(self, name: str, targets: list[str], script: str = "agent.py") -> Optional[dict]:
        if name.startswith("strix:"):
            return {"note": f"Strix skill '{name}' is knowledge-only (no executable script)", "knowledge_only": True}
        skill_dir = SKILLS_DIR / name
        script_path = skill_dir / "scripts" / script
        if not script_path.exists():
            return None
        try:
            r = subprocess.run(
                [sys.executable, str(script_path)] + targets,
                capture_output=True, text=True, timeout=120
            )
            out = r.stdout.strip()
            if out:
                return json.loads(out)
            return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
        except subprocess.TimeoutExpired:
            return {"error": f"skill {name} timed out"}
        except json.JSONDecodeError:
            return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
        except Exception as e:
            return {"error": str(e)}

    def list_pipelines(self) -> list[str]:
        return list(PIPELINE_MAP.keys())
