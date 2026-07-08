#!/bin/bash
# Raphael 2.0 — iptables kill-switch
set -e

# WARNING: Remove hardcoded password. Run as root directly: sudo bash setup_killswitch.sh
# SUDO is empty when running as root. For non-root, the user must have NOPASSWD sudo.
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

$SUDO iptables -F OUTPUT
$SUDO iptables -F INPUT

$SUDO iptables -P OUTPUT DROP

# Established/related
$SUDO iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$SUDO iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Loopback
$SUDO iptables -A OUTPUT -o lo -j ACCEPT
$SUDO iptables -A INPUT -i lo -j ACCEPT

# dnscrypt-proxy
$SUDO iptables -A OUTPUT -d 127.0.2.1 -p udp --dport 53 -j ACCEPT
$SUDO iptables -A OUTPUT -d 127.0.2.1 -p tcp --dport 53 -j ACCEPT

# Tor SOCKS + Control (host)
$SUDO iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 9050 -j ACCEPT
$SUDO iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 9051 -j ACCEPT
# Host Tor (privacy config, ExcludeNodes)
$SUDO iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 9060 -j ACCEPT
$SUDO iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 9061 -j ACCEPT
# dnscrypt-proxy
$SUDO iptables -A OUTPUT -d 127.0.2.1 -p udp --dport 53 -j ACCEPT
$SUDO iptables -A OUTPUT -d 127.0.2.1 -p tcp --dport 53 -j ACCEPT
# FreeLLMAPI
$SUDO iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 3001 -j ACCEPT
# Ollama
$SUDO iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 11434 -j ACCEPT

# Docker bridge networks (host ↔ containers, container ↔ container)
for net in 172.17.0.0/16 172.18.0.0/16 172.19.0.0/16 172.20.0.0/16; do
    $SUDO iptables -A OUTPUT -d "$net" -j ACCEPT
done

# VPNBook server (specific IP from script)
$SUDO iptables -A OUTPUT -d 147.135.15.16 -p tcp --dport 443 -j ACCEPT

# ICMP (ping, for debugging)
$SUDO iptables -A OUTPUT -p icmp -j ACCEPT

# ── IPv6 Isolation ──
$SUDO ip6tables -F OUTPUT 2>/dev/null || true
$SUDO ip6tables -F INPUT 2>/dev/null || true
$SUDO ip6tables -P OUTPUT DROP 2>/dev/null || true
$SUDO ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
$SUDO ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
echo "[+] IPv6 blocked (ip6tables OUTPUT DROP)"
echo "net.ipv6.conf.all.disable_ipv6 = 1" > /etc/sysctl.d/99-raphael-disable-ipv6.conf 2>/dev/null || true

echo "[+] Kill-switch applied"
echo "[+] $($SUDO iptables -S OUTPUT 2>/dev/null | grep '\-P')"
