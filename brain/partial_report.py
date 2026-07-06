"""Zero-token partial report synthesis from existing engagement artifacts."""

import json, logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from brain.engagement_state import ResumeManager

logger = logging.getLogger("partial_report")


def compose_partial_report(eng_dir: Path) -> Optional[str]:
    """Compose an interim report.md from existing artifacts without LLM calls.
    Returns the report text, or None if engagement directory is invalid."""
    scope_path = eng_dir / "scope.json"
    findings_path = eng_dir / "findings.md"
    intel_path = eng_dir / "intel.md"
    db_path = eng_dir / "cases.db"
    surfaces_path = eng_dir / "surfaces.jsonl"

    if not scope_path.exists():
        logger.warning("Cannot compose partial report: no scope.json")
        return None

    scope = json.loads(scope_path.read_text())
    target = scope.get("target", "unknown")
    status = scope.get("status", "unknown")
    phase = scope.get("current_phase", "unknown")
    phases_completed = scope.get("phases_completed", [])
    start_time = scope.get("start_time", "unknown")

    # Count findings
    finding_count = 0
    findings_content = ""
    if findings_path.exists():
        text = findings_path.read_text()
        finding_count = text.count("[FINDING-") or text.count("## Finding") or text.count("**Finding")
        findings_content = text.strip()

    # Intel summary
    intel_content = ""
    if intel_path.exists():
        intel_content = intel_path.read_text().strip()

    # Pipeline stats
    pipeline_stats = {}
    if db_path.exists():
        try:
            from recon_pipeline.case_store import CaseStore
            store = CaseStore(str(db_path))
            stats = store.stats()
            store.close()
            pipeline_stats = stats.get("by_stage", {})
        except Exception:
            pipeline_stats = {"error": "could not read stats"}

    # Surface coverage
    surface_count = 0
    if surfaces_path.exists():
        surface_count = sum(1 for _ in surfaces_path.open())

    now = datetime.now().isoformat()

    report = f"""# Engagement Report (PARTIAL — interim snapshot)
> ⚠️ Auto-composed interim report assembled by Raphael partial_report.py
> from existing artifacts. This is NOT the final polished report.

## Engagement Metadata
- **Target:** {target}
- **Start Time:** {start_time}
- **Composed At:** {now}
- **Status:** {status}
- **Current Phase:** {phase}
- **Phases Completed:** {', '.join(phases_completed) if phases_completed else 'none'}
- **Findings Count:** {finding_count}
- **Surface Entries:** {surface_count}

## Pipeline Status
| Stage | Count |
|-------|-------|
"""
    for stage, count in sorted(pipeline_stats.items()):
        report += f"| {stage} | {count} |\n"

    report += f"""
## Findings
"""
    if findings_content:
        report += findings_content + "\n\n"
    else:
        report += "No findings recorded yet.\n\n"

    report += f"""## Intelligence Summary
"""
    if intel_content:
        report += intel_content + "\n\n"
    else:
        report += "No intelligence collected yet.\n"

    # Write report
    report_path = eng_dir / "report.md"
    report_path.write_text(report)
    (eng_dir / "report.md.partial").write_text(now)
    logger.info("Composed partial report for %s (%d findings)", target, finding_count)
    return report


def should_compose_partial(eng_dir: Path) -> bool:
    """Check if partial report should be composed (after 5+ new findings)."""
    partial_marker = eng_dir / "report.md.partial"
    findings_path = eng_dir / "findings.md"

    if not findings_path.exists():
        return False

    finding_count = findings_path.read_text().count("[FINDING-") or findings_path.read_text().count("## Finding")
    if finding_count == 0:
        return False

    if not partial_marker.exists():
        return finding_count >= 3

    # Only compose if findings grew since last partial
    try:
        last_partial_text = findings_path.read_text()
        last_partial_count = last_partial_text.count("[FINDING-") or last_partial_text.count("## Finding")
        return last_partial_count >= finding_count + 3
    except Exception:
        return False
