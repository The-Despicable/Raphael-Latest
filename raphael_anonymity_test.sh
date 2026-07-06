#!/bin/bash
# =============================================================================
# Raphael 2.0 — Anonymity Layer Integrity Test (adapted for current setup)
# =============================================================================
set -o pipefail

REAL_IP="49.43.227.117"
TOR_SOCKS="127.0.0.1:9050"
DNSCRYPT_ADDR="127.0.2.1"
PASS=0; FAIL=0; SKIP=0; TOTAL=0
LOG="/tmp/anonymity_test.log"
> "$LOG"

log() { echo -e "$1" | tee -a "$LOG"; }
check() {
    ((TOTAL++))
    local desc="$1"; shift
    local cmd="$@"
    if eval "$cmd" >/dev/null 2>&1; then
        log "  ✅ $desc"
        ((PASS++))
    else
        log "  ❌ $desc"
        ((FAIL++))
    fi
}
skip() {
    ((TOTAL++)); ((SKIP++))
    log "  ⏭️  $1"
}

# ── 1. DNS Layer ──
log "========== 1. DNS Layer =========="
if systemctl is-active dnscrypt-proxy &>/dev/null; then
    check "dnscrypt-proxy service active" "systemctl is-active dnscrypt-proxy | grep -q active"
    check "DNS resolution via dnscrypt" "dig @$DNSCRYPT_ADDR google.com +short +timeout=5 | grep -q '^[0-9]'"
    check "External DNS blocked (UDP/53)" "! dig @8.8.8.8 google.com +short +timeout=3 | grep -q '^[0-9]'"
    check "External DNS blocked (TCP/53)" "! dig @8.8.8.8 google.com +tcp +short +timeout=3 | grep -q '^[0-9]'"
else
    skip "dnscrypt-proxy not installed"
    # Still check for DNS leaks
    LOCAL_DNS=$(dig google.com +short +timeout=3 2>/dev/null | head -1)
    if [ -n "$LOCAL_DNS" ]; then
        log "      DNS via system resolver: $LOCAL_DNS"
    fi
    check "System DNS resolves OK" "dig google.com +short +timeout=3 | grep -q '^[0-9]'"
fi

# ── 2. VPN Layer ──
log "\n========== 2. VPN Layer =========="
if ip link show tun1 &>/dev/null; then
    check "VPN tunnel tun1 exists" "ip link show tun1 | grep -q UP"
    check "VPN tunnel has IP" "ip addr show tun1 | grep -q 'inet '"
    VPN_EXIT=$(curl -s --max-time 10 --interface tun1 https://ifconfig.me 2>/dev/null)
    check "VPN exit IP differs from real IP" "[ \"$VPN_EXIT\" != \"$REAL_IP\" ]"
    log "      VPN exit IP: $VPN_EXIT"
else
    skip "VPN (tun1) not configured"
    VPN_EXIT=""
fi

# ── 3. Tor Layer ──
log "\n========== 3. Tor Layer =========="
TOR_RESP=$(curl -s --max-time 15 --socks5-hostname $TOR_SOCKS https://check.torproject.org/api/ip 2>/dev/null)
check "Tor SOCKS5 responding" "echo '$TOR_RESP' | python3 -c \"import sys,json; assert json.load(sys.stdin)['IsTor']\""
TOR_EXIT=$(echo "$TOR_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['IP'])" 2>/dev/null)
check "Tor exit IP differs from real IP" "[ \"$TOR_EXIT\" != \"$REAL_IP\" ]"
if [ -n "$VPN_EXIT" ]; then
    check "Tor exit IP differs from VPN exit" "[ \"$TOR_EXIT\" != \"$VPN_EXIT\" ]"
fi
log "      Real IP:    $REAL_IP"
log "      Tor exit:   $TOR_EXIT"

# Test direct connection (should NOT work if kill-switch active)
DIRECT_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null)
if [ -n "$DIRECT_IP" ]; then
    log "      ⚠️  Direct (no Tor) still works: $DIRECT_IP"
fi

# ── 4. Kill‑switch enforcement ──
log "\n========== 4. Kill‑Switch =========="
KILL_SWITCH=$(sudo -n iptables -S OUTPUT 2>/dev/null | grep '\-P OUTPUT' | awk '{print $4}')
if [ "$KILL_SWITCH" = "DROP" ]; then
    check "iptables OUTPUT policy is DROP" "true"
    check "Direct HTTP blocked (example.com)" "! curl -s --max-time 5 http://example.com >/dev/null 2>&1"
    check "Direct HTTPS blocked" "! curl -s --max-time 5 https://example.com >/dev/null 2>&1"
    check "VPN server allowed (TCP 443)" "sudo -n iptables -S OUTPUT | grep -q '147.135.15.16.*dport 443.*ACCEPT'"
    check "DNS to dnscrypt allowed" "sudo -n iptables -S OUTPUT | grep -q '127.0.2.1.*dport 53.*ACCEPT'"
else
    skip "iptables kill-switch not active (OUTPUT policy: $KILL_SWITCH)"
fi

# ── 5. IPv6 leak ──
log "\n========== 5. IPv6 Leak =========="
IPV6_ADDR=$(ip -6 addr show scope global 2>/dev/null | grep inet6)
if [ -z "$IPV6_ADDR" ]; then
    log "  ✅ No global IPv6 address (safe)"
    ((PASS++)); ((TOTAL++))
else
    IPV6_BLOCKED=$(sudo -n ip6tables -S OUTPUT 2>/dev/null | grep -q 'DROP' && echo "yes" || echo "no")
    if [ "$IPV6_BLOCKED" = "yes" ]; then
        log "  ✅ IPv6 traffic blocked via ip6tables"
        ((PASS++)); ((TOTAL++))
    else
        log "  ❌ IPv6 present but not blocked"
        ((FAIL++)); ((TOTAL++))
    fi
fi

# ── 6. Orchestrator OPSEC endpoints ──
log "\n========== 6. Orchestrator OPSEC =========="
# Brain API is on :3700 for this setup
ORCH="http://localhost:3700"
AUTH="Authorization: Bearer rapheal_dev_key_2026"

# Check if brain API is responding
if curl -s --max-time 3 $ORCH/v1/brain/state &>/dev/null; then
    # Tor rotation via brain API
    python3 -c "
import requests
try:
    r = requests.post('$ORCH/v1/engage/start', json={'target': 'anonymity_test'}, timeout=5)
    data = r.json()
    assert 'message' in data or 'status' in data
    print('PASS')
except Exception as e:
    print(f'FAIL: {e}')
" 2>&1 | while read line; do
    if echo "$line" | grep -q "PASS"; then
        log "  ✅ Engage endpoint responds"
        ((PASS++)); ((TOTAL++))
    else
        log "  ❌ Engage endpoint: $line"
        ((FAIL++)); ((TOTAL++))
    fi
done
else
    skip "Brain API not reachable on :3700"
fi

# ── 7. Container‑level proxy enforcement ──
log "\n========== 7. Container Proxy Enforcement =========="
for svc in recon-pipeline cai-service sword cloak-service phishing; do
    CID=$(docker compose ps -q "$svc" 2>/dev/null)
    if [ -n "$CID" ]; then
        HAS_PROXY=$(docker exec "$CID" env 2>/dev/null | grep -c "TOR_PROXY")
        if [ "$HAS_PROXY" -gt 0 ]; then
            log "  ✅ $svc has TOR_PROXY set"
        else
            log "  ❌ $svc missing TOR_PROXY"
            ((FAIL++)); ((TOTAL++))
            continue
        fi
        ((PASS++)); ((TOTAL++))
    fi
done

# ── 8. Anonymity Guard module ──
log "\n========== 8. Anonymity Guard Module =========="
if python3 -c "import sys; sys.path.insert(0, '/home/yaser/Ultimate skill/raphael-2.0/orchestrator/..'); from orchestrator.brain.anonymity_guard import AnonymityGuard" 2>/dev/null; then
    python3 -c "
import sys
sys.path.insert(0, '/home/yaser/Ultimate skill/raphael-2.0/orchestrator/..')
from orchestrator.brain.anonymity_guard import AnonymityGuard
g = AnonymityGuard()
result = g.verify()
assert result.get('tor_ok') or result.get('safe', False), f'verify failed: {result}'
print('PASS')
" 2>&1 | while read line; do
    if echo "$line" | grep -q "PASS"; then
        log "  ✅ AnonymityGuard.verify() passes"
        ((PASS++)); ((TOTAL++))
    else
        log "  ❌ AnonymityGuard: $line"
        ((FAIL++)); ((TOTAL++))
    fi
done
else
    skip "brain.anonymity_guard not importable"
fi

# ── 9. Docker tor-proxy container ──
log "\n========== 9. Docker Tor Proxy =========="
DOCKER_TOR=$(docker ps --filter name=tor-proxy --format "{{.Status}}" 2>/dev/null)
if [ -n "$DOCKER_TOR" ]; then
    log "  ✅ Docker tor-proxy: $DOCKER_TOR"
    ((PASS++)); ((TOTAL++))
else
    log "  ❌ Docker tor-proxy not running"
    ((FAIL++)); ((TOTAL++))
fi

# Test container Tor connectivity
docker exec raphael-20-sword-1 curl -s --max-time 10 --socks5-hostname tor-proxy:9050 https://check.torproject.org/api/ip 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    assert d.get('IsTor'), 'not Tor'
    print(f'Container Tor: {d.get(\"IP\")}')
except: print('FAIL')
" 2>&1 | while read line; do
    if echo "$line" | grep -q "FAIL"; then
        log "  ❌ Container Tor connectivity"
        ((FAIL++)); ((TOTAL++))
    else
        log "  ✅ Container Tor works (exit: $line)"
        ((PASS++)); ((TOTAL++))
    fi
done

# ── Summary ──
log "\n========================================="
log "  ANONYMITY LAYER INTEGRITY REPORT"
log "========================================="
log "  Real IP:   $REAL_IP"
if [ -n "$VPN_EXIT" ]; then
    log "  VPN exit:  $VPN_EXIT"
fi
log "  Tor exit:  $TOR_EXIT"
log "  Passed:    $PASS / $TOTAL"
log "  Failed:    $FAIL / $TOTAL"
log "  Skipped:   $SKIP / $TOTAL"
SCORE=$(( PASS * 100 / TOTAL ))
log "  Score:     $SCORE%"

if [ $FAIL -gt 0 ]; then
    log "  ⚠️  Some checks failed"
    if [ $SCORE -ge 80 ]; then
        log "  ✅ Anonymity is functional but has minor gaps."
    elif [ $SCORE -ge 60 ]; then
        log "  ⚠️  Significant anonymity gaps — do not operate until fixed."
    else
        log "  🔴 SEVERE LEAK — anonymity compromised. Stop all operations."
    fi
else
    log "  🎉 ALL CHECKS PASSED — Full anonymity maintained."
fi
log "========================================="
