# HTB Insane Walkthrough Knowledge Base — For Raphael Brain Training

Compiled from walkthroughs of 18 Insane machines. Each entry distills the exact technique chain, tools, and what Raphael needs to replicate it.

---

## WINDOWS / AD MACHINES

---

### Sizzle
**Walkthroughs:** https://0xrick.github.io/hack-the-box/sizzle/ | https://pointedsec.github.io/writeups/sizzle---hackthebox/

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | SCF file drop on writable SMB share | Responder | ✅ |
| 2 | Crack NetNTLMv2 hash | john/hashcat | ✅ |
| 3 | AD CS certificate enrollment via web | openssl + certsrv HTTP | ❌ manual cert workflow |
| 4 | WinRM with client cert auth | Ruby winrm gem | ❌ evil-winrm doesn't support cert auth |
| 5 | AppLocker bypass via MSBuild | MSBuild.exe inline task | ❌ |
| 6 | Kerberoast mrlky | GetUserSPNs.py (impacket) | ✅ |
| 7 | DCSync → Admin | secretsdump.py | ✅ |

**Critical Raphael Gap:** AD CS web enrollment automation (submit CSR, download cert, convert to PFX, auth via cert). Need `openssl` scripting + cert workflow module.

---

### APT
**Walkthrough:** https://0xdf.gitlab.io/2021/04/10/htb-apt.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | OXID resolver → leak IPv6 | rpcmap.py + IOXIDResolver | ❌ |
| 2 | IPv6 scan reveals full DC | nmap -6 | ✅ |
| 3 | SMB backup backup.zip download | smbclient | ✅ |
| 4 | Crack PKZIP hash | zip2john + hashcat -m 17220 | ❌ zip2john |
| 5 | Parse ntds.dit offline | secretsdump.py -system -ntds LOCAL | ✅ |
| 6 | Brute 2000 hashes vs Kerberos | pyKerbrute (modified) | ❌ |
| 7 | Remote registry read | reg.py (impacket) | ❌ |
| 8 | NTLMv1 downgrade → crack.sh | RoguePotato + custom ntlmrelayx + Responder --lm | ❌ RoguePotato, crack.sh sub |

**Critical Gap:** IPv6 enumeration (OXIDResolver), PKZIP cracking, NTLMv1 coercion chain.

---

### Mist
**Walkthrough:** https://0xdf.gitlab.io/2024/10/26/htb-mist.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | Pluck CMS file disclosure CVE-2024-9405 | curl PoC | ❌ |
| 2 | Upload malicious Pluck module | zip + PHP webshell | ✅ partial |
| 3 | AppLocker/AMSI bypass | PS variable rename | ❌ |
| 4 | LNK shortcut hijacking on SMB share | PowerShell | ❌ |
| 5 | BloodHound collection | SharpHound.exe | ❌ need Windows upload |
| 6 | Certify.exe enumerate vulnerable templates | Certify.exe | ❌ |
| 7 | PetitPotam → coerce auth | PetitPotam.exe | ❌ |
| 8 | NTLM relay to LDAP | ntlmrelayx.py | ❌ not in impacket set |
| 9 | Shadow Credentials | pywhisker.py | ❌ |
| 10 | gMSA password read | bloodyAD / gMSADumper | ❌ |
| 11 | ADCS ESC13 template abuse | Certipy | ✅ partially (v4) |
| 12 | KeePass crack | keepass2john + hashcat -m 13400 + kpcli | ❌ |

**Critical Gap:** Pluck CMS exploit, PetitPotam, pywhisker, ntlmrelayx relay server.

---

### Hercules
**Walkthrough:** https://havocsec.dev/pentesting/hackthebox/hercules-hackthebox

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | Kerberos user enumeration | kerbrute | ❌ |
| 2 | Blind LDAP injection char-by-char | Custom Python | ❌ |
| 3 | Password spray discovered | netexec/nxc | ❌ |
| 4 | LFI → web.config machineKey leak | curl/wfuzz | ✅ partial |
| 5 | .ASPXAUTH cookie decryption/forge | aspnetCryptTools | ❌ |
| 6 | Malicious ODT upload → SMB capture | Responder | ✅ |
| 7 | BloodHound paths | bloodhound-python | ✅ |
| 8 | Shadow Creds / RBCD / ESC3 | certipy + bloodyAD | ❌ partial |
| 9 | DCSync | secretsdump.py | ✅ |

**Critical Gap:** kerbrute, LDAP injection toolkit, ASP.NET cookie crypto tools, bloodyAD.

---

### Hackback
**Walkthrough:** https://0xdf.gitlab.io/2019/07/06/htb-hackback.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | GoPhish default creds → vhost discovery | wfuzz/gobuster | ❌ |
| 2 | ROT13 JS deobfuscation | tio.run/beautifier | ❌ |
| 3 | PHP log poisoning | curl + PHP injection | ❌ |
| 4 | PHP disabled_functions bypass | file_put_contents + base64 | ❌ |
| 5 | reGeorg ASPX tunnel upload | reGeorg | ❌ |
| 6 | WinRM through SOCKS | proxychains + evil-winrm | ✅ partial |
| 7 | UserLogger service abuse | sc.exe + ADS syntax | ❌ |
| 8 | DiagHub DLL sideload | Custom C++ exploit | ❌ |

**Critical Gap:** PHP filesystem shell, reGeorg tunnel, UserLogger/DiagHub exploits.

---

### University
**Walkthrough:** https://0xdf.gitlab.io/2025/08/09/htb-university.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | ReportLab RCE via PDF Bio field | CVE-2023-33733 | ❌ |
| 2 | CA key theft → certificate forgery | openssl + forge | ❌ |
| 3 | Malicious .url file → NTLM capture | Responder | ✅ |
| 4 | mitm6 WPAD poisoning | mitm6 | ❌ |
| 5 | NTLM relay to LDAP | ntlmrelayx.py | ❌ |
| 6 | RBCD on WS-3 | addcomputer.py + Rubeus | ❌ |
| 7 | Unconstrained delegation → TGT capture | Rubeus monitor | ❌ |
| 8 | gMSA password read | bloodyAD | ❌ |
| 9 | RBCD to DC → DCSync | secretsdump.py | ✅ |

**Critical Gap:** ReportLab exploit, mitm6, Rubeus, addcomputer.py, PowerView.

---

### P.O.O.
**Walkthrough:** https://0xdf.gitlab.io/2020/06/08/endgame-poo.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | .DS_Store directory leak | ds_store_exp | ❌ |
| 2 | IIS 8.3 ShortName enum | IIS_shortname_Scanner | ❌ |
| 3 | MSSQL linked server double-hop | OPENQUERY chains | ❌ |
| 4 | sp_execute_external_script RCE | mssqlclient.py | ❌ not automated |
| 5 | WinRM over IPv6 | evil-winrm | ✅ |
| 6 | Kerberoast with MS Cache v2 | Invoke-Kerberoast + hashcat -m 2100 | ❌ |
| 7 | PowerView Add-DomainGroupMember | PowerView.ps1 | ❌ |

**Critical Gap:** .DS_Store parser, shortname scanner, MSSQL linked-server double-hop automation, PowerView.

---

### Odyssey
**Walkthrough:** (FullPwn GCSB 2026, machine still active — partial public info)

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | WebAuthn bypass via NoSQL injection | NoSQLMap | ❌ |
| 2 | Prototype pollution → template escape | Custom JS | ❌ |
| 3 | LaTeX → file read via pandoc | pandoc injection | ❌ |
| 4 | CVE-2025-1302 RCE | PoC | ❌ |
| 5 | Linux root via sudo group | sudo | ✅ |
| 6 | MSSQL BULK INSERT NTLM coercion | Responder + automation | ❌ |
| 7 | SeImpersonate → JuicyPotato/GodPotato | GodPotato | ❌ |
| 8 | Shadow Credentials / dMSA Ouroboros | certipy | ✅ partial |
| 9 | YAML deserialization on .NET pipe | ysoserial.net | ❌ |

**Critical Gap:** NoSQL injection, prototype pollution, LaTeX escape, Potato variants, YAML deserialization.

---

## LINUX MACHINES

---

### Stacked
**Walkthrough:** https://0xdf.gitlab.io/2022/03/19/htb-stacked.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | XSS in Referer header → proxy JS | Custom Python | ❌ |
| 2 | Exfil internal mail via victim | JavaScript proxy | ❌ |
| 3 | LocalStack AWS API abuse | AWS CLI | ❌ |
| 4 | CVE-2021-32090 LocalStack RCE | PoC | ❌ |
| 5 | Docker escape via mount | docker CLI | ❌ |
| 6 | Docker TLS cert theft | cp | ❌ |

**Critical Gap:** AWS CLI, LocalStack exploitation, Docker CLI for escape.

---

### Laser
**Walkthrough:** https://0xdf.gitlab.io/2020/12/19/htb-laser.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | PJL printer protocol → extract jobs | PRET | ❌ |
| 2 | NVRAM dump → AES key extraction | PRET | ❌ |
| 3 | Decrypt print job (AES-256-CBC) | PyCryptodome | ❌ |
| 4 | Reverse gRPC protobuf from PDF | protoc + grpcio | ❌ |
| 5 | gRPC SSRF → internal port scan | Python gRPC client | ❌ |
| 6 | Gopher tunnel → Apache Solr | gopher URL | ❌ |
| 7 | CVE-2019-0193 Solr RCE | custom HTTP | ❌ |
| 8 | SSH race-condition pivot via socat | socat | ❌ |

**Critical Gap:** PRET toolkit, protobuf/RPC tools, Solr exploit, socat.

---

### Smasher2
**Walkthrough:** https://0xdf.gitlab.io/2019/12/14/htb-smasher2.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | DNS zone transfer (AXFR) | dig | ❌ |
| 2 | Basic auth brute force | hydra | ❌ |
| 3 | Python C extension reverse engineering | Ghidra | ❌ |
| 4 | WAF evasion (backslash splitting) | manual | ❌ |
| 5 | Kernel module mmap handler exploit | gcc custom | ❌ |

**Critical Gap:** dig, hydra, Ghidra/RE tools, kernel exploit compilation.

---

### Zero
**Walkthrough:** https://0xdf.gitlab.io/2025/08/12/htb-zero.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | SFTP creds from web signup | paramiko | ❌ |
| 2 | .htaccess exploit for file read | Python + requests | ❌ |
| 3 | MySQL creds from file read | mysql client | ✅ |
| 4 | Apache config injection via process name spoofing | perl + apxs | ❌ |
| 5 | Malicious Apache module → SetUID | gcc | ❌ |

**Critical Gap:** paramiko/SFTP automation, Apache config injection.

---

### Frolic
**Walkthrough:** https://0xdf.gitlab.io/2019/04/06/htb-frolic.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | Multi-encoding puzzle (base64/brainfuck/Ook!) | offline decode | ❌ |
| 2 | PlaySMS CVE-2017-9101 RCE | custom exploit | ❌ |
| 3 | MySQL creds → SSH | mysql | ✅ |
| 4 | SUID binary ret2libc | gdb + python ROP | ❌ |

**Critical Gap:** Encoding puzzle solver, PlaySMS exploit, ROP chain builder.

---

### Reddish
**Walkthrough:** https://0xdf.gitlab.io/2020/02/22/htb-reddish.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | Node-RED flow injection | HTTP API | ❌ |
| 2 | socat/chisel multi-hop tunnel | socat + chisel | ✅ chisel |
| 3 | rsync wildcard exploit | rsync | ❌ |
| 4 | Docker socket mount escape | docker CLI | ❌ |

**Critical Gap:** Node-RED exploitation, rsync wildcard attack.

---

### Sorcery
**Walkthrough:** https://0xdf.gitlab.io/2026/04/25/htb-sorcery.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | Gitea public repository enumeration | curl/gitea API | ❌ |
| 2 | Cypher injection (Neo4j) | custom exploit | ❌ |
| 3 | SSRF from Cypher → internal services | curl | ✅ |
| 4 | Stored XSS → admin session hijack | JavaScript | ❌ |
| 5 | Kafka RCE | kcat/kafka tools | ❌ |
| 6 | Xvfb screen dump | import/xdotool | ❌ |
| 7 | FreeIPA identity abuse | IPA tools | ❌ |

**Critical Gap:** Neo4j/Cypher injection, Kafka tools, FreeIPA abuse.

---

### WhiteRabbit
**Walkthrough:** https://0xdf.gitlab.io/2024/08/24/htb-whiterabbit.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | VHOST fuzzing | ffuf/wfuzz | ❌ |
| 2 | Uptime Kuma JWT forge | jwt_tool | ❌ |
| 3 | WikiJS → EJS injection | RCE template | ❌ |
| 4 | n8n workflow abuse | HTTP API | ❌ |
| 5 | HMAC-signed SQL injection | sqlmap --eval | ✅ partial |
| 6 | Restic backup abuse | restic CLI | ❌ |

**Critical Gap:** ffuf, JWT toolkit, EJS injection, n8n API, restic.

---

### MagicGardens
**Walkthrough:** (Search for "HTB Magic Gardens walkthrough" — older box)

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | Django SECRET_KEY leak via SSRF | curl | ✅ |
| 2 | Pickle deserialization RCE | custom Python | ❌ |
| 3 | cap_sys_module → kernel module load | insmod | ❌ |
| 4 | Custom LKM reverse shell | gcc + kernel headers | ❌ |

**Critical Gap:** Django pickle deserialization, kernel module template.

---

---

### Pterodactyl
**Walkthrough:** https://0xdf.gitlab.io/2026/05/16/htb-pterodactyl.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | Subdomain fuzzing (panel.pterodactyl.htb) | ffuf | ❌ |
| 2 | Pterodactyl Panel 1.11.10 directory traversal | CVE-2025-49132 | ❌ |
| 3 | LFI via /locales/locale.json + locale/namespace params | curl | ✅ |
| 4 | pearcmd.php -> config-create -> PHP webshell | PEAR argv injection | ❌ |
| 5 | Webshell RCE | curl system() | ❌ |
| 6 | Read DB creds via LFI (config/database.php) | directory traversal | ✅ |
| 7 | Crack bcrypt hash from panel DB | hashcat -m 3200 | ✅ |
| 8 | SUSE PAM env abuse -> Polkit console bypass | PAM environment variable | ❌ |
| 9 | libblockdev/udisks -> CVE-2025-6018/6019/8067 | crafted XFS image + setuid | ❌ |
| 10 | Loop device + dbus | udisksctl / dbus-send | ❌ |

**Critical Gap:** ffuf, Pterodactyl panel exploit, PEAR argv injection technique, openSUSE-specific PAM/Polkit/udisks exploitation.

---

### Absolute
**Walkthrough:** https://0xdf.gitlab.io/2023/05/27/htb-absolute.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | Image metadata → full names | exiftool | ✅ |
| 2 | Username format generation | username-anarchy | ❌ |
| 3 | Kerberos user enumeration | kerbrute | ❌ |
| 4 | AS-REP roast → crack creds | GetNPUsers.py + hashcat -m 18200 | ✅ |
| 5 | LDAP enumeration (Kerberos auth) | ldapsearch -Y GSSAPI | ❌ |
| 6 | BloodHound with Kerberos | bloodhound-python -k | ✅ |
| 7 | SMB share enumeration (Kerberos) | smbclient.py -k | ✅ |
| 8 | Nim binary dynamic analysis | Wireshark + DNS setup | ❌ Wireshark not in tools |
| 9 | ACL abuse via dacledit.py | dacledit.py (impacket PR #1291) | ❌ |
| 10 | net rpc group addmem (Kerberos) | net (samba) --use-kerberos=required | ❌ |
| 11 | Shadow Credential via certipy | certipy shadow auto | ✅ partial |
| 12 | WinRM with Kerberos ticket | evil-winrm -r DOMAIN | ✅ |
| 13 | KrbRelay → relay to LDAP | KrbRelay / KrbRelayUp | ❌ |

**Critical Gap:** NTLM-disabled (Kerberos-only) environment handling, dacledit.py, kerbrute, username-anarchy, KrbRelay.

---

### MonitorsFour
**Walkthrough:** https://0xdf.gitlab.io/2026/05/23/htb-monitorsfour.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | Subdomain fuzzing | ffuf | ❌ |
| 2 | PHP type juggling → user DB dump | curl | ✅ |
| 3 | Crack MD5 hashes | CrackStation / hashcat | ✅ |
| 4 | .env file exposure | curl | ✅ |
| 5 | Cacti 1.2.28 authenticated RCE | CVE-2025-24367 | ❌ |
| 6 | Newline injection in rrdtool graph args | manual HTTP | ❌ |
| 7 | rrdtool create + graph → PHP webshell | rrdtool CLI | ❌ |
| 8 | Bash reverse shell from webshell | curl revshell | ✅ |
| 9 | Docker Desktop WSL2 API via container | CVE-2025-9074 | ❌ |
| 10 | Docker API → create mount container | curl | ❌ |

**Critical Gap:** ffuf, Cacti rrdtool injection exploit, Docker API abuse without docker CLI.

---

### Overwatch
**Walkthrough:** https://0xdf.gitlab.io/2026/05/09/htb-overwatch.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | Guest SMB → software$ share | netexec --shares | ✅ |
| 2 | Reverse engineer .NET binary | DotPeek / dnSpy | ❌ |
| 3 | Hardcoded SQL creds from decompile | mssqlclient.py | ✅ |
| 4 | MSSQL linked server enumeration | mssqlclient.py | ✅ |
| 5 | CREATE_CHILD DNS zone abuse | bloodyAD add dnsRecord | ❌ |
| 6 | Fake SQL07 DNS → Responder capture | Responder | ✅ |
| 7 | WinRM as sqlmgmt | evil-winrm-py | ✅ |
| 8 | WCF service enumeration (http.sys) | netsh http show servicestate | ❌ |
| 9 | PowerShell injection via KillProcess | Raw SOAP / WebServiceProxy | ❌ |
| 10 | Local admin via net localgroup | PowerShell via WCF | ❌ |

**Critical Gap:** .NET reverse engineering, DNS record injection (bloodyAD), WCF/SOAP interaction tools.

---

### DarkCorp
**Walkthrough:** https://0xdf.gitlab.io/2025/10/18/htb-darkcorp.html

| Step | Technique | Tool | Raphael Has? |
|------|-----------|------|-------------|
| 1 | Subdomain fuzzing | ffuf | ❌ |
| 2 | RoundCube XSS (CVE-2024-42009) | Python Flask exfil server | ❌ |
| 3 | Email exfil → dev subdomain | XSS + JavaScript | ❌ |
| 4 | Password reset via contact form | curl | ✅ |
| 5 | PostgreSQL SQLi (stacked queries) | manual SQL | ❌ |
| 6 | RCE via COPY TO PROGRAM (CHR bypass) | CHR(67) trick | ❌ |
| 7 | Crack ebelford hash from logs | CrackStation | ✅ |
| 8 | SSH tunnel to internal net | ssh -D 1080 | ✅ |
| 9 | Internal host discovery via SSH | ping sweep / nmap | ✅ |
| 10 | NTLM relay / DNS add / PrinterBug | ntlmrelayx.py + krbrelayx | ❌ |
| 11 | Silver ticket from relay | impacket-ticketer | ❌ |
| 12 | Scheduled task creds → DPAPI | DonPAPI / netexec dpapi | ❌ |
| 13 | Password spray | netexec | ❌ |
| 14 | Shadow Credential / UPN spoofing | certipy + bloodyAD | ❌ |
| 15 | SSSD cache extraction → AD creds | ldbsearch / hashcat | ❌ |
| 16 | GPO abuse → Domain Admin | pyGPOAbuse / SharpGPOAbuse | ❌ |

**Critical Gap:** ffuf, full XSS + exfil infrastructure, PostgreSQL RCE techniques, PrinterBug, silver ticket, DPAPI, GPO abuse tooling.

---

## RECURRING PATTERNS SUMMARY

### AD Pattern (60% of Windows Insane)
```
kerbrute userenum → password spray → foothold
  → BloodHound → ADCS ESC1/3/8/13
  → PetitPotam/Coercer → NTLM relay → LDAP
  → Shadow Credentials → RBCD → DCSync
```

### Linux Pattern (40% of Linux Insane)
```
Webapp vuln (XSS/SQLi/SSRF/RCE) → foothold
  → Internal pivot (SSRF/gRPC/k8s/Docker)
  → Container escape or kernel exploit → root
```

### Container / Docker Pattern (2025+ machines increasingly use this)
```
Webapp vuln → container shell
  → Docker API exposed internally (2375)
  → Create privileged container with host mount
  → Read host filesystem → escalate
```

### Kerberos-Only Auth Pattern (emerging)
```
NTLM disabled → all tools must support -k/-kerberos
  → kinit / getTGT.py for ticket first
  → ldapsearch -Y GSSAPI, smbclient.py -k, certipy -k
  → KrbRelay for privilege escalation
```

### Top Missing Tools (by frequency)
| Tool | Needed In |
|------|-----------|
| pywhisker / Shadow Creds | Mist, Hercules, University, Odyssey |
| kerbrute | APT, Hercules, P.O.O., Absolute |
| Rubeus | Mist, University, P.O.O., Absolute |
| Coercer / PetitPotam | Mist, APT, DarkCorp |
| ntlmrelayx.py relay server | Mist, University, APT, DarkCorp |
| ffuf/wfuzz | Stacked, Hackback, WhiteRabbit, MonitorsFour, DarkCorp |
| bloodyAD | Mist, Hercules, University, Overwatch, DarkCorp |
| pspy64 | Stacked, Laser, Zero |
| mitm6 | University |
| reGeorg ASPX/PHP tunnel | Hackback |
| hydra | Smasher2, general |
| KrbRelay/KrbRelayUp | Absolute |
| DonPAPI / DPAPI tools | DarkCorp |
| pyGPOAbuse / SharpGPOAbuse | DarkCorp |
| PrinterBug (py) | DarkCorp |
| dacledit.py (impacket PR #1291) | Absolute |
| username-anarchy | Absolute |
