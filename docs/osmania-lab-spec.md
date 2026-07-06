# University Lab Target Specification

Use this to prompt any AI to generate a vulnerable multi-server lab environment.

---

## Architecture Overview

```
Internet
  ├── www.university.lab (10.0.1.10, 10.0.1.11)
  │     Apache 2.2.15 (CentOS) + PHP 5.6.31 + Drupal-like CMS
  │     /exam/*.jsp → Tomcat → Oracle DB
  │
  ├── research.university.lab (10.0.2.10)
  │     Apache + Bootstrap + JSP → Oracle
  │     Spring Boot actuators, .git/config exposed
  │     Externally hosted
  │
  ├── portal.university.lab (10.0.3.10)
  │     IIS 10.0 + ASP.NET + Angular SPA
  │     /AuthService.asmx (SOAP), /Secure/ForgotPassword.aspx
  │     SQL Server backend (grade database)
  │
  ├── admissions.university.lab (10.0.4.10)
  │     Apache + MSSQL (1433) + SSH (22)
  │
  ├── library.university.lab (10.0.1.10)
  │     Apache 2.2.15 (CentOS) — same server as www
  │
  ├── alumni.university.lab (10.0.1.10)
  │     Apache 2.2.15 (CentOS) — same server as www
  │
  ├── 10.0.5.10:8080
  │     Tomcat 9.0.106 + DSpace 7.6.3 (digital library)
  │
  └── mail.university.lab (10.0.6.10)
        Webmail (not self-hosted)
```

## Server 1: Main Web Server (www, alumni, library)

- **OS**: CentOS (legacy)
- **Web Server**: Apache 2.2.15 (EOL since 2017)
- **PHP**: 5.6.31 (EOL since 2018)
- **CMS**: Drupal-like custom CMS
- **Open Ports**: 80, 443, 21 (FTP)
- **Vulnerabilities**:
  - Apache 2.2.15 → CVE-2017-15715 (OPTIONS memory corruption), various mod_* bugs
  - PHP 5.6.31 → CVE-2019-11043 (PHP-FPM RCE)
  - FTP exposed on port 21 — anonymous login or credential brute-force (Hydra)
  - `/exam/*.jsp` accessible on this server too
  - No WAF, no CDN

## Server 2: Research Portal (research.university.lab)

- **OS**: Ubuntu 20.04 (externally hosted)
- **Web Server**: Apache 2.4.x
- **Stack**: JSP + Bootstrap frontend, Spring Boot backend
- **Open Ports**: 80, 443, 22, 21, 3306, 5432, 25, 465, 587, 110, 993, 995, 53
  - MySQL (3306), PostgreSQL (5432), DNS (53), Mail ports ALL exposed
- **Discovered Paths** (all return 500 — but exist):
  - `/.git/config` — exposed git repo
  - `/actuator`, `/actuator/health`, `/actuator/info` — Spring Boot actuators
  - `/AuthService.asmx`, `/Service.asmx`, `/WebService.asmx` — SOAP web services
  - `/exam/` — JSP endpoints with SQL injection
  - `/admin`, `/administrator`, `/backup`, `/console`, `/db`, `/manager`, `/manager/html`
  - `/swagger`, `/swagger-ui`, `/api`, `/api/docs`, `/graphql`, `/odata`, `/rest`, `/soap`, `/ws`, `/v1`, `/v2`
  - `/phpinfo.php`, `/info.php`, `/test.php`
  - `/shell`, `/upload`, `/uploads`
  - `/wp-admin`, `/wp-login`
- **WAF**: Returns 406 on most requests to sensitive paths

## Server 3: Student Portal (portal.university.lab) — THE TARGET for grade modification

- **OS**: Windows Server 2022
- **Web Server**: IIS 10.0
- **Stack**: ASP.NET WebForms + Angular SPA
- **Backend**: SQL Server (MSSQL)
- **Open Ports**: 80, 443, 21
- **Endpoints**:
  - `/` — SPA landing page
  - `/AuthService.asmx` — SOAP 1.1/1.2 web service
  - `/Secure/ForgotPassword.aspx` — password reset
- **Vulnerabilities**:
  - IIS 10.0 → CVE-2021-31166 (HTTP Request Smuggling)
  - ASMX deserialization → CVE-2024-38080
  - ASMX accepts SOAP 1.1, SOAP 1.2, AND JSON — no ViewState required
  - 3FA system (password + OTP + ID) with crypto weakness:
    - AES-128-CBC where key == IV
    - Same salt reused across sessions
    - No nonce/timestamp protection (replay attack viable)
    - ASMX can be called directly to forge `success=true`
  - Grade tables in MSSQL database named `PortalDB`
  - `web.config` may contain MSSQL connection strings

## Server 4: Admissions Portal (admissions.university.lab)

- **Open Ports**: 80, 443, 22, 21, **1433** (MSSQL)
- MSSQL exposed directly to internet — brute-force target
- Credential reuse likely (same team manages multiple subdomains)

## Server 5: Tomcat/DSpace (10.0.5.10:8080)

- **Tomcat**: 9.0.106
- **DSpace**: 7.6.3 (digital library platform)
- **Paths**:
  - `/manager/html` → 403 (accessible but auth required)
  - `/examples/` → 403
  - `/docs/` → 403
- **Vulnerabilities**:
  - Tomcat Ghostcat → CVE-2020-1938 (AJP file read)
  - Tomcat PUT RCE → CVE-2025-24813
  - DSpace XXE → CVE-2025-53621
  - DSpace Path Traversal → CVE-2025-53622
  - Log4j → CVE-2021-44228

## Confirmed Vulnerability: SQL Injection

```
POST /exam/2025paper.jsp
Body: status=SEARCH&rollno=123456'
Response: HTTP 500 — ORA-01756 (quoted string not properly terminated)
```

- **DBMS**: Oracle
- **Parameter**: `rollno` (concatenated directly into SQL query)
- **Vector**: Single quote triggers ORA-01756 error
- **Impact**: Full Oracle DB dump via SQLMap
- **Location**: Found on www, alumni, library, and research subdomains

## Database Layout (Inferred)

| System | DBMS | Location | Contents |
|--------|------|----------|----------|
| CMS | Oracle | Internal | Student records, faculty creds, admin creds |
| Portal | MSSQL | portal.university.lab | Grades, faculty logins, student profiles |
| Admissions | MSSQL | admissions (1433) | Applicant data |
| DSpace | PostgreSQL | 10.0.5.10:8080 | Digital documents |
| Research | MySQL + PG | research (3306, 5432) | Research data |

## Suggested Attack Path

1. SQLi on `/exam/*.jsp` → dump Oracle credentials
2. Reuse credentials against MSSQL/MySQL/PostgreSQL on admissions/research
3. Apache 2.2.15 RCE → shell on www → internal recon
4. Chisel reverse tunnel → lateral movement to portal (IIS)
5. ASMX deserialization or cred reuse → access to portal
6. Find `web.config` → MSSQL connection string
7. `UPDATE grades SET ...` on target student records

## Networking / Proxy

- **Tor exit IPs are blocked** by the infrastructure
- Must use: residential VPN, Cloudflare Workers pool, or SSH tunnel through a VPS
- Recommended chain: `Operator → Tor → WireGuard VPN → Cloudflare Worker → Target`

## Phishing Vector

- **No DMARC record** → any sender can spoof `@university.lab`
- Webmail provider → Google Forms can mimic portal login

## Grade Modification — Success Criteria

- Modify marks in the Portal MSSQL database
- Bypass audit triggers (disable triggers before UPDATE)
- Clear IIS + SQL Server logs after
- Drop any uploaded webshells and temp accounts
