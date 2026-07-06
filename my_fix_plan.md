# My Fix Plan — Raphael 2.0 Security Remediation

**Philosophy:** Minimum viable changes. No new heavy dependencies (Vault, mmap). Fix each vulnerability at its root with the simplest correct change. Order = exploitability first.

---

## CRITICAL (do now)

### C3 — shell=True RCE in `telegram mcp/mcp_server.py:39-41`
**Change:** Replace `subprocess.run(cmd, shell=True)` with `subprocess.run(cmd_list, shell=False)` using `shlex.split()` for the grep commands. Add input validation on pattern/path/file_ext.
**Why this instead of Vault/whitelist:** The fix is one line change + one regex validation. The reasoning team's CSP-style whitelist is correct but over-engineered for 5 MCP tools that take text input. `shell=False` with args list and a simple `re.match(r'^[a-zA-Z0-9_.\-@:/]+$')` on pattern kills the RCE entirely.

### C4 — Python code injection in `spiderfoot_wrapper.py:53-105`
**Change:** Instead of generating `.py` files with f-string interpolation, write a JSON config file and parse it on the other side. The f-string `f"dns.resolver.resolve('{target}', '{qtype}')"` becomes `json.dumps({"target": target, "qtype": qtype})` read by a generic executor.
**Why:** Similar outcome (no arbitrary code execution) but 1/10th the code of the reasoning team's command dispatcher. JSON can't execute code.

### C6 — TLS bypass in `proxy_guard.py:222-223,467`
**Change:** Remove `urllib3.disable_warnings()` and `s.verify = False`. Replace with `s.verify = certifi.where()`.
**Why:** One-liner. The reasoning team's SSLContext adapter is correct but unnecessary — the platform already uses `requests` which defaults to `verify=True`.

### C1/C2 — Live credentials
**Change:** 
1. Rotate both keys immediately (user action)
2. Move secrets from `.env` to environment variables passed at container runtime
3. Add `.env` to `.gitignore`
**Why:** Vault is ideal but adds operational complexity. Docker secrets (env vars at runtime) remove the file-based exposure without infrastructure changes. The reasoning team's Vault approach requires running a Vault server — that's a separate project.

### C5 — Forensic countermeasures
**Change:** 
1. Add `tmpfs` mounts in `docker-compose.yml` for `/tmp` and `/var/tmp`
2. Add forensic cleanup to `anti_forensics.py` to actually execute `shred` and `srm`
3. Add an `atexit` handler that wipes `brain.db`, `recon_log_*.jsonl` on shutdown
**Why:** The reasoning team's mmap-based secure storage is over-engineered. tmpfs + atexit shredding achieves "memory-only" with 20 lines of config and 30 lines of Python.

### C7 — 9/10 containers as root
**Change:** Add `USER 1000:1000` and `groupadd`/`useradd` to all 9 Dockerfiles that lack it. Add `cap_drop: ALL` to all services in `docker-compose.yml`.
**Why:** One line per Dockerfile. No architecture change.

### C8 — Evidence on disk
**Change:** Forensic wipe script that targets: `brain.db`, `recon_log_*.jsonl`, `/tmp/tor_data/`, `/tmp/anonymity_test.log`, all sqlmap temp dirs. Integrated as a Docker shutdown hook.
**Why:** The reasoning team has this too. No disagreement.

---

## HIGH (do this week)

### H4 — Hardcoded sudo password
**Change:** Remove `echo 23532231 | sudo -S` from `setup_killswitch.sh`. Use sudo NOPASSWD for the specific iptables commands, or prompt interactively.
**Why:** One line change. The reasoning team's approach is the same.

### H5 — Typo in kill_switch_disable.sh:21
**Change:** `AC` → `ACCEPT`
**Why:** One character fix.

### H6 — No IPv6 isolation
**Change:** Add `ip6tables` rules mirroring all IPv4 rules. Add `sysctl -w net.ipv6.conf.all.disable_ipv6=1` to kill switch.
**Why:** The reasoning team's approach is identical.

### H7 — DNS leak
**Change:** In `proxy_guard.py:697`, route DNS through Tor's `DNSPort` (localhost:5353) instead of `1.1.1.1`. Add `DNSPort 5353` to torrc.
**Why:** One URL change.

### H2/H3 — `--no-anonymity` bypass
**Change:** Don't remove the flag (legitimate use for dev). Do add a confirmation prompt: "WARNING: Anonymity disabled. Continue? [y/N]" when the flag is set. Log the bypass to a WARNING-level, non-optional log.
**Why:** The reasoning team might over-engineer this. A confirmation + audit log is 5 lines.

### H1 — Default credentials
**Change:** Generate random defaults at first run instead of hardcoded `changeme` values. Use `secrets.token_urlsafe(24)`.
**Why:** 1 line per credential. The reasoning team's Vault approach is overkill for dev defaults.

### H8 — API cost controls
**Change:** Add a simple token counter in `providers.py` that tracks `total_tokens` per API call. Add a `MAX_SPEND_TOKENS` env var that stops calls when exceeded.
**Why:** The reasoning team's approach is similar. A dict + counter is ~30 lines.

### H9 — sanitize_prompt safety-filter evasion
**Change:** No change. This is intentional functionality for the platform's purpose (offensive security research). Document it as WARN in the code instead of hiding it.
**Why:** The reasoning team would advocate removing it — but that breaks the platform's core value proposition with safety-filtered models. This is a design tradeoff, not a bug.

### H10 — Memory-only unchecked items
**Change:** Add a `checklist_audit.py` script that iterates the 26 design doc items and reports which are implemented vs not. Integrate as a pre-flight check.
**Why:** Not a code fix — a process fix.

### H11/H12 — OpSec logs and IPs on disk
**Change:** Encrypt log entries that contain IPs (at-rest AES using a derived key from session token). Add immediate log rotation + shredding. Remove `/tmp/anonymity_test.log` creation entirely.
**Why:** The reasoning team's HMAC-anonymization is good — I'd adopt that.

---

## Summary of key differences from reasoning team

| Area | Reasoning Team | My Plan |
|------|---------------|---------|
| Secrets | Vault + mmap | Runtime env vars + Docker secrets |
| Code injection | Full command dispatcher + CSP | JSON config files |
| shell=True | Whitelist + arg validators | shell=False + shlex + regex |
| Forensic | mmap + secure workspace | tmpfs + atexit + shred |
| Safety-evasion | Remove it | Document as intentional |
| --no-anonymity | Architectural rewrite | Confirmation prompt |
| Non-root containers | Per-Dockerfile USER | Same (no disagreement) |

My plan requires ~50% less code, no external infrastructure (Vault), and achieves the same security outcomes for the stated threats.
