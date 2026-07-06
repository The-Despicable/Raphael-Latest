from datetime import datetime

def generate_report(filename: str, findings: list, analyses: list) -> str:
    lines = []
    lines.append(f"# SAST Report: {filename}")
    lines.append(f"**Generated:** {datetime.now().isoformat()}")
    lines.append(f"**Total Findings:** {len(findings)}")
    lines.append(f"**Confirmed:** {sum(1 for a in analyses if a.get('confirmed'))}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| # | Type | Severity | Line | Confirmed | Confidence |")
    lines.append("|---|------|----------|------|-----------|------------|")
    for i, (f, a) in enumerate(zip(findings, analyses), 1):
        confirmed = "✅" if a.get("confirmed") else "❌"
        conf = a.get("confidence", "N/A")
        lines.append(f"| {i} | {f.vuln_type} | {a.get('severity', f.severity)} | {f.line} | {confirmed} | {conf} |")
    lines.append("")
    lines.append("## Details")
    lines.append("")
    for i, (f, a) in enumerate(zip(findings, analyses), 1):
        lines.append(f"### {i}. {f.vuln_type} (Line {f.line})")
        lines.append(f"**CWE:** {f.cwe}")
        lines.append(f"**Severity:** {a.get('severity', f.severity)}")
        lines.append(f"**Confirmed:** {a.get('confirmed', False)}")
        lines.append(f"**Confidence:** {a.get('confidence', 'N/A')}/10")
        lines.append("")
        lines.append("```")
        lines.append(f.snippet)
        lines.append("```")
        lines.append("")
        if a.get("explanation"):
            lines.append(f"**Explanation:** {a['explanation']}")
        if a.get("remediation"):
            lines.append(f"**Remediation:** {a['remediation']}")
        lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)
