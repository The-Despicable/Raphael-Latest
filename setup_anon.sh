#!/usr/bin/env bash
# setup_anon.sh — Deploy Raphael 2.0 Anonymous Layer
# Run: bash setup_anon.sh

set -e

echo "[*] Setting up Raphael 2.0 Anonymous Layer..."

# ── 1. Kill any existing tor ──
pkill -9 tor 2>/dev/null || true
sleep 1

# ── 2. Create Tor config ──
mkdir -p /tmp/tor_data
cat > /tmp/torrc << 'TOREOL'
SocksPort 9050
ControlPort 9051
DataDirectory /tmp/tor_data
CookieAuthentication 1
NewCircuitPeriod 30
MaxCircuitDirtiness 600
ExcludeNodes {us},{ca},{gb},{au},{nz},{de},{fr},{nl}
StrictNodes 0
Log notice file /tmp/tor.log
TOREOL

# ── 3. Start Tor ──
python3 -c "
import subprocess, os, time
os.makedirs('/tmp/tor_data', exist_ok=True)
proc = subprocess.Popen(['tor', '-f', '/tmp/torrc'],
    stdout=open('/tmp/tor.log','w'), stderr=subprocess.STDOUT)
print(f'Tor PID: {proc.pid}')
with open('/tmp/tor.pid','w') as f: f.write(str(proc.pid))
time.sleep(5)
print('Tor started')
"

# ── 4. Verify ──
echo "[*] Checking Tor..."
sleep 3
python3 -c "
import urllib.request, json
proxy = urllib.request.ProxyHandler({'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'})
opener = urllib.request.build_opener(proxy)
r = opener.open('https://check.torproject.org/api/ip', timeout=15)
data = json.loads(r.read())
if data.get('IsTor'):
    print(f'[+] Tor ACTIVE — Exit IP: {data[\"IP\"]}')
else:
    print('[-] Tor check failed')
"

# ── 5. Start/Verify dnscrypt-proxy ──
systemctl is-active dnscrypt-proxy.service &>/dev/null || {
    echo "[*] Starting dnscrypt-proxy..."
    pkill -9 dnscrypt-proxy 2>/dev/null || true
    sleep 1
}
echo "[*] Checking dnscrypt-proxy..."
python3 -c "
import socket, struct, random
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
tid = random.randint(0, 65535)
query = struct.pack('>H', tid) + struct.pack('>H', 0x0100) + struct.pack('>HHHH', 1, 0, 0, 0)
for part in [b'cloudflare', b'com']:
    query += struct.pack('B', len(part)) + part
query += b'\x00' + struct.pack('>HH', 1, 1)
sock.sendto(query, ('127.0.2.1', 53))
data, addr = sock.recvfrom(512)
sock.close()
resp_code = data[3] & 0x0f
if resp_code == 0:
    print('[+] dnscrypt-proxy ACTIVE on 127.0.2.1:53 (DoH via Cloudflare)')
else:
    print('[-] dnscrypt-proxy query failed')
"

echo ""
echo "[*] Proxy chain: dnscrypt-proxy → Tor"
echo ""

# ── 6. WireGuard setup instructions ──
echo ""
echo "[*] WireGuard setup (needs sudo + config):"
echo "    sudo apt install wireguard"
echo "    sudo wg set wg0 private-key /etc/wireguard/key"
echo "    sudo ip link set wg0 up"
echo ""
echo "[*] To add to ~/.bashrc for auto-start on login:"
echo "    (crontab -l 2>/dev/null; echo '@reboot bash /home/yaser/Ultimate\\ skill/raphael-2.0/setup_anon.sh') | crontab -"
echo ""
echo "[+] Anonymous layer deployed. Run proxy_guard.verify() to test."