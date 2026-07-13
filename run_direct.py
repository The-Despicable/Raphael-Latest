#!/home/yaser/raphael-2.0/.venv/bin/python3
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator.modes.autonomous import handle


async def main():
    if len(sys.argv) < 2:
        print("Usage: python run_direct.py <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    phases = ["direct_exploit", "privesc", "flag_capture"]

    print(f"{'='*60}")
    print(f"  Raphael 2.0 — Direct Exploit")
    print(f"  Target: {target}")
    print(f"  Phases: {', '.join(phases)}")
    print(f"{'='*60}\n")

    result = await handle(target, phases=phases, no_proxy=True)

    print(f"\n{'='*60}")
    print(f"  ENGAGEMENT COMPLETE")
    print(f"{'='*60}\n")

    flags = result.get("flags", {})
    if flags.get("all_flags_captured"):
        print(f"  BOTH FLAGS CAPTURED!")
    elif flags.get("user_flag_found"):
        print(f"  USER FLAG FOUND, ROOT FLAG MISSING")
    elif flags.get("root_flag_found"):
        print(f"  ROOT FLAG FOUND, USER FLAG MISSING")
    else:
        print(f"  NO FLAGS FOUND")

    if flags.get("user_flag"):
        print(f"\n  USER FLAG: {flags['user_flag']}")
    if flags.get("root_flag"):
        print(f"  ROOT FLAG: {flags['root_flag']}")

    print(f"\n  Phases run: {list(result['phases'].keys())}")
    for phase_name, phase_data in result["phases"].items():
        if not isinstance(phase_data, dict):
            continue
        status = "OK" if phase_data.get("success") else "FAIL"
        summary = phase_data.get("summary", "no summary")[:100]
        latency = phase_data.get("latency", 0)
        err = phase_data.get("error", "")
        if err:
            summary += f" | error: {err[:80]}"
        print(f"  [{status}] {phase_name}: {summary} ({latency:.1f}s)")

    print(f"\n  Total findings: {result.get('total_findings', 0)}")

    output_file = f"raphael_{target}_direct.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"  Results saved to: {output_file}")

    if flags.get("user_flag") or flags.get("root_flag"):
        return 0
    return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
