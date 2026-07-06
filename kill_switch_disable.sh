#!/bin/bash
# Raphael 2.0 Kill Switch Disable — Restores normal traffic

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash kill_switch_disable.sh"
    exit 1
fi

echo "[*] Disabling kill switch..."

# If we saved rules, restore them
if [ -f /tmp/iptables-before-killswitch ]; then
    iptables-restore < /tmp/iptables-before-killswitch
    echo "[+] Previous iptables rules restored"
else
    # Otherwise flush and set to ACCEPT defaults
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    echo "[+] iptables reset to defaults"
fi

# Restore IPv6
ip6tables -F OUTPUT 2>/dev/null || true
ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
echo "[+] IPv6 restored"

echo "[+] Kill switch DISABLED"
