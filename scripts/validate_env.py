#!/usr/bin/env python3
"""Validate .env configuration for security-critical values.

Rejects weak/default credentials and missing required keys.
Exit codes: 0 = OK, 1 = warnings, 2 = errors
"""

import os
import re
import sys

WEAK_PATTERNS = [
    "changeme", "change-me", "change_me", "password", "secret",
    "raphael-dev", "sk-omniroute-local", "raphael-layer5",
    "default", "test", "dev-key",
]

MIN_PASS_LENGTH = 16
MIN_API_KEY_LENGTH = 32

ERRORS = []
WARNINGS = []

dotenv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
if not os.path.exists(dotenv_path):
    print(f"  [!] .env not found at {dotenv_path}")
    print("  [*] Copy .env.example to .env and configure your keys.")
    sys.exit(2)

env_vars = {}
with open(dotenv_path) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        env_vars[key.strip()] = val.strip()


def check(var, label, required=False, min_length=0, reject_weak=True):
    val = env_vars.get(var, "")
    if required and not val:
        ERRORS.append(f"{var} ({label}): required but empty")
        return
    if not val:
        WARNINGS.append(f"{var} ({label}): empty (may be OK if not using this feature)")
        return
    if min_length and len(val) < min_length:
        ERRORS.append(f"{var} ({label}): too short ({len(val)} chars, min {min_length})")
        return
    if reject_weak:
        lower = val.lower()
        for pat in WEAK_PATTERNS:
            if pat in lower:
                ERRORS.append(f"{var} ({label}): contains weak/default pattern '{pat}'")
                return


def main():
    print("=" * 60)
    print("  Raphael 2.0 — Environment Validation")
    print("=" * 60)
    print()

        # NVIDIA_API_KEY removed — access NVIDIA models through opencode CLI (oc-* aliases)
    check("OPENAI_API_KEY", "OpenAI API key", required=False, min_length=8)
    check("TOR_CONTROL_PASS", "Tor control password", required=True, min_length=MIN_PASS_LENGTH)
    check("API_KEY", "API gateway key", required=True, min_length=MIN_API_KEY_LENGTH)
    check("GOPHISH_API_KEY", "Gophish API key", required=False, min_length=MIN_API_KEY_LENGTH)
    check("NEO4J_PASS", "Neo4j password", required=True, min_length=MIN_PASS_LENGTH)
    check("OMNIROUTE_API_KEY", "OmniRoute API key", required=False, min_length=8)

    print()
    if ERRORS:
        print(f"  [{chr(10060)}] {len(ERRORS)} ERRORS:")
        for e in ERRORS:
            print(f"      - {e}")
        print()
    if WARNINGS:
        print(f"  [{chr(9888)}] {len(WARNINGS)} WARNINGS:")
        for w in WARNINGS:
            print(f"      - {w}")
        print()

    if not ERRORS:
        print(f"  [{chr(10004)}] All required secrets pass validation.")
        print()

    return 2 if ERRORS else (1 if WARNINGS else 0)


if __name__ == "__main__":
    sys.exit(main())
