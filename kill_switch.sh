#!/bin/bash
# Raphael 2.0 Kill Switch — Blocks all non-VPN traffic
# Docker-aware: allows Docker containers to route through VPN
# Run as: sudo bash kill_switch.sh

set -e

# Must run as root
if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash kill_switch.sh"
    exit 1
fi

VPN_IF=$(ip route show default | grep -oP "dev \K\S+" || echo "tun0")
VPN_SERVER="147.135.15.16"  # VPNBook server IP
DNS_IP="127.0.2.1"
DOCKER_BRIDGE="br-15ae1bb2985c"  # Raphael docker bridge
DOCKER_NET="172.19.0.0/16"

echo "[*] Enabling kill switch..."

# Save current rules (for restoration if needed)
iptables-save > /tmp/iptables-before-killswitch 2>/dev/null || true

# === FLUSH only our chains — preserve Docker chains ===
iptables -F INPUT
iptables -F OUTPUT

# === INPUT (incoming) ===
# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
# Allow established/related
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Allow Docker bridge (container responses)
iptables -A INPUT -i $DOCKER_BRIDGE -j ACCEPT
# Drop everything else
iptables -P INPUT DROP

# === OUTPUT (outgoing) ===
# Allow loopback
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established/related connections
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow VPN tunnel traffic (tun1)
iptables -A OUTPUT -o $VPN_IF -j ACCEPT

# Allow Docker bridge traffic (containers route through VPN or internally)
iptables -A OUTPUT -o $DOCKER_BRIDGE -j ACCEPT

# Allow traffic to VPN server (so tunnel can establish/maintain)
iptables -A OUTPUT -d $VPN_SERVER -p tcp --dport 443 -j ACCEPT

# Allow DNS only to dnscrypt-proxy
iptables -A OUTPUT -p udp -d $DNS_IP --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -d $DNS_IP --dport 53 -j ACCEPT

# Block ALL other DNS to prevent leaks
iptables -A OUTPUT -p udp --dport 53 -j DROP
iptables -A OUTPUT -p tcp --dport 53 -j DROP

# Block all other eth0 traffic
iptables -A OUTPUT -o eth0 -j DROP

# Default policy: DROP anything not explicitly allowed
iptables -P OUTPUT DROP

echo "[+] Kill switch ENABLED"
echo ""
echo "Traffic rules:"
echo "  ✓ VPN tunnel (tun1)         → ALLOW"
echo "  ✓ Docker bridge (br-*)      → ALLOW"
echo "  ✓ VPN server (TCP 443)      → ALLOW"
echo "  ✓ DNS (127.0.2.1:53)        → ALLOW"
echo "  ✗ Direct eth0 traffic       → DROP"
echo "  ✗ External DNS leaks        → DROP"
