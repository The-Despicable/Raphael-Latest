#!/bin/bash
# Check kill switch and DNS leak status

echo "=== KILL SWITCH STATUS ==="
echo ""
echo "iptables OUTPUT rules:"
sudo iptables -L OUTPUT -n --line-numbers 2>/dev/null || echo "  Not available (need sudo)"

echo ""
echo "=== DNS LEAK TEST ==="
# Quick DNS test - should only work through dnscrypt
echo "Testing DNS through dnscrypt-proxy (127.0.2.1:53)..."
dig @127.0.2.1 google.com +short 2>/dev/null | head -1 || echo "  Failed"

echo ""
echo "=== VPN INTERFACE ==="
ip link show tun1 2>/dev/null || echo "  tun1 not found"

echo ""
echo "=== TRAFFIC TESTS ==="
# Through Tor
echo "Tor exit IP:"
curl -s --socks5-hostname 127.0.0.1:9050 --max-time 5 https://check.torproject.org/api/ip 2>/dev/null || echo "  Failed"
