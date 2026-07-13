import json
import logging
import re
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger("compliance_mapper")

# Regulation control mappings: finding type → control IDs per regulation
REGULATION_MAP = {
    "nist_sp_800_53": {
        "sql_injection": "SI-10, SI-11, SI-16",
        "xss": "SI-10, SI-15",
        "ssrf": "SC-7, SC-23",
        "command_injection": "SI-10, SI-16",
        "open_port": "CM-8, CA-8",
        "credential": "IA-5, AC-2, AC-6",
        "privesc": "AC-6, AC-3",
        "ssti": "SI-10",
        "file_inclusion": "AC-6, SI-10",
        "shell": "AC-6, AC-3",
        "rce": "SI-10, SI-16",
        "default": "RA-5, CA-8",
    },
    "nist_csf_2_0": {
        "sql_injection": "PR.PS-01, DE.CM-04",
        "xss": "PR.PS-01, DE.CM-04",
        "ssrf": "PR.AC-05, DE.CM-04",
        "command_injection": "PR.PS-01, DE.CM-04",
        "open_port": "ID.AM-01, PR.AC-05",
        "credential": "PR.AC-01, PR.AC-03",
        "privesc": "PR.AC-01, PR.AC-06",
        "shell": "PR.AC-01, DE.CM-04",
        "rce": "PR.PS-01, DE.CM-04",
        "default": "ID.RA-01, ID.RA-05",
    },
    "nist_ai_rmf": {
        "prompt_injection": "MAP-1, GOV-2, MEAS-2",
        "memory_poisoning": "MAP-1, GOV-2, MAN-3",
        "skill_poisoning": "MAP-1, GOV-2, MAN-3",
        "intent_drift": "MAP-1, GOV-2, MEAS-2",
        "stealth_command": "MAP-1, GOV-2, MAN-3",
        "default": "MAP-1, GOV-2",
    },
    "eu_ai_act": {
        "prompt_injection": "Art 6, Art 9, Art 15",
        "memory_poisoning": "Art 6, Art 12, Art 15",
        "skill_poisoning": "Art 6, Art 12, Art 15",
        "intent_drift": "Art 6, Art 12, Art 14",
        "stealth_command": "Art 6, Art 15",
        "sql_injection": "Art 6, Annex III",
        "xss": "Art 6, Annex III",
        "ssrf": "Art 6, Annex III",
        "rce": "Art 6, Annex III",
        "default": "Art 6",
    },
    "owasp_asvs_4_0": {
        "sql_injection": "V2.3, V5.1, V5.3",
        "xss": "V5.1, V5.2",
        "ssrf": "V11.1, V12.3",
        "command_injection": "V2.3, V11.1",
        "ssti": "V5.1, V5.5",
        "file_inclusion": "V12.1, V12.3",
        "rce": "V2.3, V11.1",
        "default": "V1.1, V4.1",
    },
    "pci_dss_4_0": {
        "sql_injection": "Req 6.2.4, Req 6.2.4.1",
        "xss": "Req 6.2.4, Req 6.2.4.2",
        "ssrf": "Req 1.2.1, Req 6.2.4",
        "command_injection": "Req 6.2.4",
        "open_port": "Req 1.2.1, Req 1.3.1",
        "credential": "Req 8.3.6, Req 8.2.1",
        "default": "Req 6.2.4, Req 11.3.1",
    },
    "iso_27001_2022": {
        "sql_injection": "A.8.25, A.8.26",
        "xss": "A.8.25, A.8.26",
        "ssrf": "A.8.20, A.8.21",
        "command_injection": "A.8.25",
        "open_port": "A.8.8, A.8.9",
        "credential": "A.5.15, A.5.16",
        "privesc": "A.8.2, A.8.3",
        "shell": "A.8.2, A.8.25",
        "rce": "A.8.25",
        "default": "A.8.8, A.8.25",
    },
    "gdpr": {
        "credential": "Art 5, Art 32, Art 33",
        "sql_injection": "Art 32, Art 33",
        "exfil": "Art 5, Art 32, Art 33",
        "shell": "Art 32",
        "default": "Art 32",
    },
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

CONTROL_SOURCES = [
    {
        "id": "NIST SP 800-53 Rev. 5",
        "jurisdiction": "US Federal",
        "description": "Security and Privacy Controls for Information Systems and Organizations",
    },
    {
        "id": "NIST CSF 2.0",
        "jurisdiction": "US (cross-sector)",
        "description": "Cybersecurity Framework — identify, protect, detect, respond, recover",
    },
    {
        "id": "NIST AI RMF 1.0",
        "jurisdiction": "US (AI systems)",
        "description": "AI Risk Management Framework — map, govern, measure, manage",
    },
    {
        "id": "EU AI Act",
        "jurisdiction": "EU",
        "description": "Regulation laying down harmonised rules on artificial intelligence",
    },
    {
        "id": "OWASP ASVS 4.0",
        "jurisdiction": "Global (application security)",
        "description": "Application Security Verification Standard",
    },
    {
        "id": "PCI DSS 4.0",
        "jurisdiction": "Global (payment card industry)",
        "description": "Payment Card Industry Data Security Standard",
    },
    {
        "id": "ISO/IEC 27001:2022",
        "jurisdiction": "Global (ISMS)",
        "description": "Information Security Management System requirements",
    },
    {
        "id": "GDPR",
        "jurisdiction": "EU/EEA",
        "description": "General Data Protection Regulation",
    },
]

AI_ACT_ARTICLES = {
    "prompt_injection": [
        {"article": "Art. 6", "title": "Classification Rules for High-Risk AI Systems",
         "status": "triggered — injection attacks directly impact model behaviour"},
        {"article": "Art. 9", "title": "Risk Management System",
         "status": "triggered — insufficient input validation controls"},
        {"article": "Art. 15", "title": "Accuracy, Robustness and Cybersecurity",
         "status": "triggered — adversarial input robustness gap"},
    ],
    "memory_poisoning": [
        {"article": "Art. 6", "title": "Classification Rules for High-Risk AI Systems",
         "status": "triggered — memory integrity affects high-risk classification"},
        {"article": "Art. 12", "title": "Record-Keeping and Logging",
         "status": "triggered — no integrity verification on memory writes"},
        {"article": "Art. 15", "title": "Accuracy, Robustness and Cybersecurity",
         "status": "triggered — memory poisoning degrades system accuracy"},
    ],
    "skill_poisoning": [
        {"article": "Art. 6", "title": "Classification Rules for High-Risk AI Systems",
         "status": "triggered — skill modifications affect all downstream decisions"},
        {"article": "Art. 12", "title": "Record-Keeping and Logging",
         "status": "triggered — skill modifications not logged or verified"},
        {"article": "Art. 15", "title": "Accuracy, Robustness and Cybersecurity",
         "status": "triggered — poisoned skills compromise system robustness"},
    ],
    "intent_drift": [
        {"article": "Art. 6", "title": "Classification Rules for High-Risk AI Systems",
         "status": "triggered — scope drift changes operational boundary of high-risk system"},
        {"article": "Art. 12", "title": "Record-Keeping and Logging",
         "status": "triggered — scope boundary checks not logged on each action"},
        {"article": "Art. 14", "title": "Human Oversight",
         "status": "triggered — scope drift bypasses intended human oversight triggers"},
    ],
    "default": [
        {"article": "Art. 6", "title": "Classification Rules for High-Risk AI Systems",
         "status": "applicable — system may meet high-risk criteria"},
    ],
}


class ComplianceMapper:
    """Maps security findings to regulatory compliance controls.

    Given a list of findings from any phase, produces a compliance evidence
    package covering NIST 800-53, CSF 2.0, AI RMF, EU AI Act, OWASP ASVS,
    PCI DSS, ISO 27001, and GDPR.
    """

    def __init__(self, target_info: dict):
        self.target_info = target_info
        self._mapped_findings: list[dict] = []

    def map_findings(self, findings: list[dict]) -> dict:
        """Map a list of findings to compliance controls.

        Args:
            findings: List of finding dicts, each with at least:
                - type (str): finding type (sql_injection, xss, etc.)
                - severity (str): critical/high/medium/low/info
                - description (str): finding description
                - evidence (str, optional): supporting evidence

        Returns:
            Compliance evidence package dict with regulation_breakdown,
            ai_act_assessment, and mapped_findings.
        """
        self._mapped_findings = []

        for f in findings:
            ftype = f.get("type", "default").lower().replace(" ", "_")
            mapped = self._map_single(f, ftype)
            if mapped:
                self._mapped_findings.append(mapped)

        regulation_breakdown = self._build_regulation_breakdown()
        ai_act_assessment = self._build_ai_act_assessment()
        evidence_summary = self._build_evidence_summary()

        return {
            "regulation_breakdown": regulation_breakdown,
            "ai_act_assessment": ai_act_assessment,
            "evidence_summary": evidence_summary,
            "mapped_findings": self._mapped_findings,
            "control_sources": CONTROL_SOURCES,
        }

    def _map_single(self, finding: dict, ftype: str) -> Optional[dict]:
        controls = []
        for reg_name, type_map in REGULATION_MAP.items():
            control_id = type_map.get(ftype, type_map.get("default", ""))
            if control_id:
                controls.append({
                    "regulation": reg_name,
                    "control_id": control_id,
                })

        if not controls:
            return None

        return {
            "finding": {
                "type": finding.get("type", "unknown"),
                "severity": finding.get("severity", "medium"),
                "description": (finding.get("description", "") or "")[:300],
                "evidence": (finding.get("evidence", "") or "")[:500],
            },
            "compliance_controls": controls,
        }

    def _build_regulation_breakdown(self) -> dict:
        breakdown = {}
        for mf in self._mapped_findings:
            finding = mf.get("finding", {})
            severity = finding.get("severity", "medium").lower()
            sev_idx = SEVERITY_ORDER.get(severity, 3)

            for cc in mf.get("compliance_controls", []):
                reg = cc["regulation"]
                if reg not in breakdown:
                    breakdown[reg] = {
                        "total_controls_affected": 0,
                        "critical_findings": 0,
                        "high_findings": 0,
                        "medium_findings": 0,
                        "low_findings": 0,
                        "affected_controls": set(),
                    }
                breakdown[reg]["total_controls_affected"] += 1
                for cid in cc["control_id"].split(", "):
                    breakdown[reg]["affected_controls"].add(cid)
                if sev_idx <= 0:
                    breakdown[reg]["critical_findings"] += 1
                elif sev_idx == 1:
                    breakdown[reg]["high_findings"] += 1
                elif sev_idx == 2:
                    breakdown[reg]["medium_findings"] += 1
                elif sev_idx >= 3:
                    breakdown[reg]["low_findings"] += 1

        for reg, data in breakdown.items():
            data["affected_controls"] = sorted(data["affected_controls"])
        return breakdown

    def _build_ai_act_assessment(self) -> dict:
        ai_types = {"prompt_injection", "memory_poisoning", "skill_poisoning",
                     "intent_drift", "stealth_command"}
        triggered = []
        for mf in self._mapped_findings:
            ftype = mf.get("finding", {}).get("type", "").lower().replace(" ", "_")
            if ftype in ai_types:
                triggered.append(ftype)

        articles_triggered = []
        for t in triggered:
            articles = AI_ACT_ARTICLES.get(t, AI_ACT_ARTICLES["default"])
            articles_triggered.extend(articles)

        # If no AI-specific findings, add default analysis
        if not articles_triggered:
            articles_triggered = list(AI_ACT_ARTICLES["default"])

        # Deduplicate
        seen = set()
        unique = []
        for a in articles_triggered:
            key = a["article"]
            if key not in seen:
                seen.add(key)
                unique.append(a)

        risk_level = self._assess_ai_risk()
        return {
            "risk_category": risk_level,
            "articles_triggered": unique,
            "assessment_notes": (
                "System performs autonomous vulnerability research and exploitation "
                "on authorized targets. If findings include AI-specific attack vectors "
                "(injection, poisoning, drift), the system itself may be a high-risk "
                "AI system under EU AI Act Annex III."
            ),
        }

    def _assess_ai_risk(self) -> str:
        ai_types = {"prompt_injection", "memory_poisoning", "skill_poisoning",
                     "intent_drift", "stealth_command"}
        for mf in self._mapped_findings:
            ftype = mf.get("finding", {}).get("type", "").lower().replace(" ", "_")
            if ftype in ai_types:
                return "high-risk"
        return "limited-risk"

    def _build_evidence_summary(self) -> list[dict]:
        by_regulation: dict[str, list[dict]] = {}
        for mf in self._mapped_findings:
            for cc in mf.get("compliance_controls", []):
                reg = cc["regulation"]
                if reg not in by_regulation:
                    by_regulation[reg] = []
                by_regulation[reg].append({
                    "control_id": cc["control_id"],
                    "finding_type": mf["finding"]["type"],
                    "finding_severity": mf["finding"]["severity"],
                    "finding_description": mf["finding"]["description"][:100],
                })

        return [
            {
                "regulation": reg,
                "controls_affected": len(items),
                "evidence_items": items[:10],
            }
            for reg, items in sorted(by_regulation.items())
        ]
