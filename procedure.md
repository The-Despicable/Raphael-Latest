# PROCEDURE.MD — Raphael 2.0 Pre-Flight Protocol
### Mandatory Checks Before Every Operation

> Authored after the 26 June 2026 Osmania recon incident —
> a bare-IP scan that burned the operator to every log on the target.
> This procedure exists to ensure it never repeats.

---

## 0. THE RULE

> **Every operation that touches a target — test or not, deep or shallow — goes through the full proxy chain. There is no "just this once."**

The AI must refuse to execute any operation that violates this rule. If proxy enforcement cannot be verified, abort.

---

## 1. PROXY CHAIN VERIFICATION

### 1.1 Tor Daemon

```
Check: Is Tor running on 127.0.0.1:9050?
Command: curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
Expected: JSON response with "IsTor: true"
Failure: Do not proceed. Start Tor.
```

### 1.2 Tor Control Port

```
Check: Is Tor control port accessible on 127.0.0.1:9051?
Required for: Per-target circuit isolation
Command: echo -e "AUTHENTICATE\r\nSIGNAL NEWNYM\r\n" | nc -w 2 127.0.0.1 9051
Expected: "250" response
Failure: Continue with degraded isolation (can't rotate circuits per target)
```

### 1.3 WireGuard Tunnel

```
Check: Is the VPN tunnel established?
Command: wg show wg0
Expected: "interface: wg0", "latest handshake: ... seconds ago"
Failure: Do not proceed. Reconnect VPN.
```

### 1.4 FlareTunnel (Cloudflare Workers)

```
Check: Is the CF Worker proxy pool responding?
Command: curl http://127.0.0.1:8080/status
Expected: 200 OK
Failure: Continue with degraded coverage (Tor alone still masks IP)
```

### 1.5 Exit IP Confirmation

```
Check: Is the exit IP different from the real IP?
Command: 
  EXIT_IP=$(curl --socks5-hostname 127.0.0.1:9050 -s https://ifconfig.me)
  REAL_IP=$(curl -s https://ifconfig.me)
  echo "Real: $REAL_IP | Exit: $EXIT_IP"
Expected: Exit IP ≠ Real IP
Failure: CRITICAL — proxy is not routing. Do not proceed. Fix proxy chain.
```

### 1.6 DNS Leak Test

```
Check: Is DNS resolving through the proxy or leaking?
Command: curl --socks5-hostname 127.0.0.1:9050 -s https://ipleak.net/json/
Expected: "dns" field shows the proxy's DNS servers, not ISP's
Failure: Do not proceed. Configure /etc/resolv.conf to use localhost or disable
         systemd-resolved. Ensure all tools use SOCKS5h (not SOCKS5).
```

```
Check: Make a test DNS lookup — does it leak to ISP resolvers?
Command: dig +short @1.1.1.1 target.com  (should fail if DNS is blocked at iptables)
         dig +short target.com                  (should fail if resolv.conf is localhost)
Expected: Direct lookups fail (blocked by iptables or pointing to localhost)
Failure: Add iptables rule: sudo iptables -A OUTPUT -p udp --dport 53 -j DROP
```

---

## 2. NETWORK LEAK PREVENTION

### 2.1 IPv6

```
Check: Is IPv6 disabled?
Command: cat /proc/sys/net/ipv6/conf/all/disable_ipv6
Expected: "1"
Failure: sudo sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6'
         sudo sh -c 'echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6'
Rationale: Many systems have IPv6 enabled by default. If the proxy chain
           only covers IPv4 but the OS prefers IPv6, traffic bypasses Tor
           entirely. The operator won't notice because IPv4 checks pass.
```

### 2.2 WebRTC

```
Check: Does the browser leak the real IP via WebRTC?
Not relevant: All recon is CLI-based. Never use a browser for recon.
If browser is required: Use Tor Browser only. Disable WebRTC in about:config
                        (media.peerconnection.enabled = false).
```

### 2.3 Default Identifying Headers

```
Check: Is the HTTP client revealing identity?

  python-requests/2.x.x     → TRACKABLE. Never use stock requests without header override.
  python-urllib/3.x         → TRACKABLE. Same problem.
  Go-http-client/2.0        → TRACKABLE. Custom User-Agent required.
  curl/8.x                  → TRACKABLE. Use --user-agent with browser string.
  libcurl/8.x               → TRACKABLE. Same.
  Default browser TLS       → Fine if it matches a real browser. But every request
    fingerprints (JA3/JA4)    must use the SAME browser version to avoid inconsistency.

Fix: Always override User-Agent + randomize Accept/Accept-Language/Accept-Encoding
     order. Rotate per session, not per request (consistency within a session is
     more normal than random per-request).
```

### 2.4 TLS Fingerprint

```
Check: Is the TLS ClientHello unique or browser-matching?
  python-requests uses urllib3 which uses OpenSSL — the TLS stack has a
  distinct JA3 fingerprint that is NOT the same as any browser.

Risk: Blue teams correlate JA3 fingerprints across targets. If the same
      JA3 hits Osmania and then another university, they connect the dots.

Fix: Use a TLS spoofing library (tls-client, uTLS) that produces exact
     browser fingerprints (Chrome 131, Firefox 133, Safari 18).

Minimal mitigation: Ensure the exit IP changes per target (circuit isolation)
                    so JA3 correlation can't link sessions across targets.
```

---

## 3. CIRCUIT ISOLATION

### 3.1 Per-Target Tor Circuit

```
Rule:  ONE CIRCUIT PER TARGET. Never reuse the same Tor circuit for
       different targets.

Rationale: If the operator scans two universities from the same exit IP,
           and one of them reports the IP to a threat intel feed, both
           scans are linked to the same operator.

Procedure:
  1. Before starting a new target, issue NEWNYM signal:
     echo -e "AUTHENTICATE\r\nSIGNAL NEWNYM\r\n" | nc 127.0.0.1 9051
  2. Wait 3 seconds for circuit rotation
  3. Confirm new exit IP:
     curl --socks5-hostname 127.0.0.1:9050 -s https://ifconfig.me
  4. Log: "Circuit rotated for target: <target> → Exit: <new_ip>"
```

### 3.2 Per-Target User-Agent

```
Rule:  Use a different User-Agent for each target. Never repeat the same
       UA across different targets.

Rationale: If NERTU and UMS both report traffic with "Chrome/131" from
           adjacent IPs at adjacent times, correlation is trivial.

Procedure:
  - Pick randomly from a curated pool of 10+ browser UAs
  - Stay consistent within a session (don't change UA mid-session)
  - Change for next target
```

### 3.3 Per-Target Timing Profile

```
Rule:  Each target should see a different request timing pattern.

Rationale: If the operator scans 10 targets and every scan has exactly
           2.5s ± 0.3s between requests, the pattern is identifiable
           as the same tool.

Procedure:
  - Randomize the delay range per target:
    Target A: 1.0s-3.0s  (fast scan, low-value target)
    Target B: 3.0s-8.0s  (slow scan, high-value target — noise minimization)
    Target C: 0.5s-1.5s  (burst scan, time-sensitive)
  - Use Markov-chain delays, not uniform random (see proxy_guard.py TimingEngine)
```

---

## 4. RECON STAGING

### 4.1 Passive First

```
Order of operations. NEVER skip to active recon without exhausting passive:

  Level 1 — OSINT (zero target contact):
    □ crt.sh / CertSpotter (certificate transparency logs)
    □ Shodan   (search: "org:Osmania University" or "hostname:osmania.ac.in")
    □ Censys   (search: services.http.response.html_title:"Osmania")
    □ Wayback Machine / CommonCrawl (historical endpoints, JS files, comments)
    □ GitHub   (search: "osmania.ac.in" for leaked creds/configs)
    □ Google dorks (site:osmania.ac.in filetype:pdf | filetype:xls | inurl:admin)
    □ Whois / RDAP (registrar, nameservers, tech contacts)
    □ SecurityTrails / AlienVault OTX (passive DNS history)

  Level 2 — Semi-passive (third-party resolution, no touch):
    □ DNS brute-force through third-party resolver (not direct)
    □ Certificate transparency monitoring (fresh certs = new subdomains)
    □ BuiltWith / Wappalyzer (tech stack via cached data)

  Level 3 — Active with proxy (contact required):
    □ Port scanning (but only after Level 1-2 are exhausted)
    □ Directory brute-force (one target at a time, slow)
    □ Vulnerability probing (only on clearly exposed endpoints)
```

### 4.2 Target Triage

```
Before sending a single packet, classify each target:

  Priority A — Immediately valuable (no scan needed):
    □ .git/config exposed?
    □ .env exposed?
    □ admin panels with default creds?
    □ Actuator endpoints /health /info /env /heapdump?
    □ Swagger UI / OpenAPI docs?
    □ SOAP/WSDL endpoints?

  Priority B — Scan if passive recon suggests weakness:
    □ Old Apache (2.2.x, pre-2015)?
    □ Old Tomcat (pre-9.0)?
    □ IIS with ASP.NET (UMS profile)?
    □ FTP open on 21?
    □ MSSQL on 1433 (admissions profile)?
    □ MySQL/PostgreSQL on standard ports (NERTU profile)?

  Priority C — Observe only (high detection risk, low reward):
    □ Google Workspace (mail)
    □ Cloudflare-protected sites
    □ WAF-429 responses (already triggered)
```

### 4.3 Rate Limiting

```
  □ < 1 request per second for directory brute-force
  □ < 5 DNS queries per second for subdomain enumeration
  □ < 100 ports per 10 seconds for port scanning
  □ Minimum 2 second pause between different target IPs
  □ Never scan more than 1 target IP concurrently

Rationale: The 26 June scan did 48 paths + 50 ports + 90 DNS queries
           in under 2 minutes. That speed itself is a detection signature
           regardless of the proxy. Slow down.
```

---

## 5. FAIL-SAFES

### 5.1 Kill Switch

```
Before any operation, confirm the kill switch is armed:

  □ Dead Man timer active (10 second heartbeat)
    If the monitoring process dies, all connections drop and
    cleanup runs automatically.
  
  □ Circuit Break threshold configured (3 failures = abort)
    If the proxy fails 3 consecutive requests, trigger fail-dead.

  □ Remote Kill accessible (mTLS-authenticated command)
    Someone else can kill the operation if the operator goes dark.
```

### 5.2 Fail-Dead Mechanism

```
If at ANY point the proxy chain fails mid-operation:

  1. IMMEDIATELY kill all in-flight connections
     - Close all open sockets
     - Terminate all subprocesses (curl, nmap, nuclei, sqlmap)
     - Do NOT let them fall back to direct connection

  2. Do NOT retry the request
     - The retry itself could leak: "First request timed out → retry
       direct → now the target has both a proxy request and a direct
       request from the same operator, proving it's the same person."

  3. Log the failure with exact timestamp
     - What was being requested?
     - Which hop failed? (Tor / WG / FlareTunnel)
     - How many requests already completed?

  4. Alert the operator immediately
     - Do NOT continue. Do NOT "finish the current scan."
     - The operator must manually re-verify the proxy chain before
       any further target contact.
```

### 5.3 Emergency Teardown

```
If compromise is suspected (any of these triggers):

  Trigger A: Target returns unexpected content (honeypot / redirect to law enforcement)
  Trigger B: Exit IP appears on a blocklist mid-operation
  Trigger C: Unusual network latency patterns (traffic shaping / interception)
  Trigger D: Operator receives any communication related to the operation

  Teardown procedure:
    1. Kill all connections immediately
    2. Shred any temporary files: shred -fzu /tmp/recon_* 2>/dev/null
    3. Tor circuit rotation: echo "SIGNAL NEWNYM" | nc 127.0.0.1 9051
    4. WireGuard down: wg-quick down wg0
    5. FlareTunnel stop: flare-tunnel stop
    6. Power cycle the operator machine if possible
    7. Wait 24+ hours before any operation from the same physical location
```

---

## 6. LOGGING

### 6.1 What to Log

Every request must log, in append-only JSONL format:

```json
{
  "timestamp": "2026-06-26T22:13:44Z",
  "target": "nertu.osmania.ac.in",
  "method": "GET",
  "path": "/res07/20250403.jsp?id=1",
  "status": 406,
  "exit_ip": "185.220.101.x",
  "circuit_id": "a3f8c91e2b4d",
  "user_agent": "Mozilla/5.0 (Win...) Chrome/131",
  "duration_ms": 1247,
  "proxy_chain": "tor:9050 → wg0 → flaretunnel"
}
```

### 6.2 What NOT to Log

```
  □ Real IP        — NEVER written to any file
  □ Authentication — NEV ER written to any file
  □ Payloads       — Not unless explicitly authorized
  □ Session tokens  — Never in plaintext, ephemeral key only
```

### 6.3 Log Storage

```
  □ Memory-only during operation (tmpfs, not disk)
  □ Encrypted at rest with ephemeral key
  □ Key destroyed on operation completion
  □ Logs shredded 24h after operation end
```

---

## 7. AI-SPECIFIC INSTRUCTIONS

### 7.1 The AI Must Refuse

If the user asks the AI to run any operation against any target, the AI must FIRST verify the proxy chain. If the proxy chain is not confirmed, the AI must refuse and explain why.

```
User: "Scan example.com for open ports"
AI:   "Before I can do that, I need to verify the proxy chain.
       Run this check first: curl --socks5-hostname 127.0.0.1:9050 https://ifconfig.me
       If that returns a different IP than your real IP, I can proceed."
```

### 7.2 The AI Must Verify Before Execute

The AI must perform these checks in order before sending any packet to a target:

```
□ Step 1: Verify proxy chain (Tor on 9050, exit IP ≠ real IP)
□ Step 2: Verify DNS leak prevention (direct DNS blocked or localhost)
□ Step 3: Verify IPv6 disabled
□ Step 4: New circuit for this target (NEWNYM)
□ Step 5: Log target, circuit ID, exit IP
□ Step 6: Execute with timing delays, User-Agent override, no identifying headers
```

If any step fails, the operation does not proceed.

### 7.3 The AI Must Not Override

There is no override flag. There is no `--no-proxy` equivalent. There is no "just this once." If the AI has the ability to bypass the proxy guard, it must treat that capability as a bug and never use it.

The only way to bypass proxy enforcement is to modify the source code of `proxy_guard.py`. If the AI is asked to do that, it must refuse with a reference to the 26 June 2026 incident.

### 7.4 The AI Must Report

After any operation, the AI must report:

```
Operation Summary:
  Target:     osmania.ac.in (nertu subdomain)
  Circuit:    a3f8c91e2b4d
  Exit IP:    185.220.101.x (different from real IP ✓)
  Requests:   47 total, 0 failed
  Duration:   4m 32s
  Timing:     1.2s-3.8s between requests
  Log file:   recon_log_202606.jsonl
  Status:     Complete. Proxy chain intact throughout. No leaks detected.
```

If anything went wrong, the report must include a postmortem:

```
Postmortem:
  Incident:   Circuit break triggered at 22:15:03 (3 consecutive failures)
  Cause:      Tor circuit timeout (exit node unresponsive)
  Response:   Fail-dead executed. 3 in-flight requests killed.
  Recovery:   New circuit established. Operation resumed after verification.
  Lesson:     Increase connection timeout for slow exit nodes.
```

---

## 8. PRE-OPERATION CHECKLIST (Quick Reference)

Copy this into every operation plan:

```
□ Real IP known (check: curl -s https://ifconfig.me)
□ Tor running (check: curl --socks5-hostname 127.0.0.1:9050 -s https://ifconfig.me)
□ Exit IP ≠ Real IP
□ WireGuard up (check: wg show wg0)
□ FlareTunnel responding (optional but preferred)
□ DNS blocked from direct resolution (check: dig target.com @1.1.1.1 should fail)
□ IPv6 disabled (check: cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
□ New Tor circuit for this target
□ User-Agent randomized (not default python-requests)
□ Timing profile set (not machine-gun)
□ Kill switch armed
□ Log file initialized
□ Target triage complete (started passive, moving to active only if necessary)
```

---

## 9. CONSEQUENCES OF VIOLATION

| Violation | Consequence |
|-----------|-------------|
| Skip proxy check | IP burned against target (see 26 June 2026) |
| Skip DNS leak check | ISP DNS logs link operator to target |
| Skip IPv6 check | IPv6 traffic bypasses Tor entirely, real IP exposed |
| Skip circuit isolation | Multiple targets linked to same exit IP |
| Skip timing randomization | Scan pattern identifies tool across targets |
| Skip User-Agent override | "python-requests/2.x" fingerprints operator globally |
| Fail-dead not triggered | Proxy drops mid-scan → retry without proxy → double exposure |
| No kill switch | Operation runs uncontrolled if operator loses access |

---

## APPENDIX: Incident Reference — 26 June 2026

**What happened:** A Python recon script scanned `osmania.ac.in` with `PROXY = None`. All 7 subdomains, 6 IPs, 50+ ports, and 48 directory paths were hit from the operator's real IP.

**Evidence left:** Apache access_log, WAF logs, IIS logs, Tomcat access_log, firewall/IDS logs, Google DNS cache — all from a single source IP within 2 minutes.

**What was learned:**
1. Even "test runs" need the proxy chain
2. Documentation is not enforcement — `PROXY = None` should have been impossible
3. Passive recon (Shodan/Censys/Wayback) should exhaust before active scanning
4. The proxy guard must be code, not a reminder
5. `proxy_guard.py` was written in response — it now enforces all of the above

**This procedure exists because of that mistake. Follow it.**
