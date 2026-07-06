# Osmania University Target Profile — Build Prompt

## Goal
Generate a detailed target profile for Osmania University (`osmania.ac.in`) to be used in Raphael 2.0's `target_state.py`. This profile should model what a real penetration test engagement would discover.

## Output Format
Generate a JSON object matching the structure below. Place it in `/home/yaser/Ultimate skill/raphael-2.0/orchestrator/brain/target_state.py` as a new function `build_osmania_state()`.

## Required Information

### Known Infrastructure (from previous recon)
Based on the VulnU-Lab design and real Osmania fingerprint:

| Service | Version | Notes |
|---------|---------|-------|
| Apache | 2.2.15 | EOL, Optionsbleed vulnerable |
| PHP | 5.6.31 | EOL, multiple CVEs |
| IIS | 10.0 | Windows Server |
| Tomcat | 9.0.106 | AJP Ghostcat vulnerable |
| Oracle | 19c | Pre-auth RCE vulnerable |
| MSSQL | 2019 | Linked server RCE |
| DSpace | 7.6.3 | Solr RCE, path traversal |
| ModSecurity | CRS 3.x | WAF — blocks UNION/SELECT |
| OpenSSH | (check version) | regreSSHion candidate |

### Target Endpoints (synthetic — based on typical Indian university portal)
- `/` — Main portal
- `/login.php` — Student/faculty login (SQLi)
- `/search.php?q=` — Course/search (SQLi)
- `/page.php?file=` — Content pages (LFI)
- `/profile/avatar.php` — Profile picture upload (unrestricted upload)
- `/admissions/apply.php` — Application form
- `/results/view.php?rollno=` — Exam results (IDOR)
- `/exam/schedule.php` — Exam timetable
- `/library/search.php?q=` — Library catalogue (SQLi)
- `/research/papers/view.jsp?id=` — Research papers (JSP SQLi)
- `/faculty/profile.php?id=` — Faculty directory (IDOR)
- `/admin/` — Admin panel (directory listing)
- `/backup/` — Backup files (directory listing)
- `/db_backup.sql` — Database backup (info disclosure)
- `/campuslife/gallery.php` — Photo gallery
- `/events/calendar.php` — Events calendar
- `/api/exam/results` — REST API endpoint
- `/api/student/profile` — Student profile API

### Adversary Assumptions
- **Profile**: Academic pentest / red team engagement
- **Business hours**: IST 9:00-18:00, Monday-Friday
- **Geo origin**: India (UTC+5:30)
- **Data velocity**: 10-50KB/min (stealth)
- **Engagement type**: Black box, no credentials

## Required CVE Mappings
Ensure the profile matches against these CVEs from `COMMON_CVES` dict:

| CVE | Service | Description | Severity |
|-----|---------|-------------|----------|
| CVE-2021-41773 | Apache 2.4.49 | Path traversal RCE | Critical |
| CVE-2017-9798 | Apache 2.2.x | Optionsbleed | Medium |
| CVE-2020-1938 | Tomcat 9.0 | AJP Ghostcat | Critical |
| CVE-2024-21733 | Tomcat 9.0 | Session fixation | Medium |
| CVE-2024-21161 | Oracle 19c | Pre-auth RCE | Critical |
| CVE-2023-21704 | MSSQL 2019 | sp_configure RCE | High |
| CVE-2021-31166 | IIS 10.0 | HTTP Protocol DoS | High |
| CVE-2024-6387 | OpenSSH | regreSSHion RCE | Critical |

## Function Signature to Create

```python
def build_osmania_state() -> dict:
    """
    Returns a pre-built target state for Osmania University
    based on known infrastructure fingerprint.
    """
```

The returned dict must have:
- `target`: "Osmania University (osmania.ac.in)"
- `technologies`: list of 10+ technology strings (e.g. "apache 2.2.15", "php 5.6.31", "iis 10.0", etc.)
- `versions`: auto-extracted from technology strings
- `cves`: matched from COMMON_CVES dict
- `unpatched_cves`: list of CVE IDs
- `patch_status`: "likely_unpatched"
- `detection_stack`: list of detected defenses (ModSecurity, Cloudflare if detected)
- `risk_score`: calculated (should be 8-10/10)
- `osmania_endpoints`: list of 15+ endpoint dicts with type, url, param, method, severity
- `osmania_domains`: ["osmania.ac.in", "www.osmania.ac.in", "admissions.osmania.ac.in", "results.osmania.ac.in"]
- `engagement_notes`: str with operational considerations

## Endpoint Format
```python
{
    "type": "sqli",
    "endpoint": "/login.php",
    "param": "username",
    "method": "POST",
    "severity": "critical",
    "note": "Direct string interpolation in SQL query",
    "mitigation": "Parameterized queries / prepared statements",
}
```

## What to Include
- 5 SQLi endpoints (login, search, library, research, API)
- 2 LFI endpoints (page.php, file download)
- 2 File upload endpoints (avatar, document submission)
- 3 IDOR endpoints (results, faculty, student profile)
- 1 Info disclosure (db_backup, debug endpoint)
- 2 Directory listings (admin, backup)
- 1 JSP SQLi endpoint (research papers)
- 1 API endpoint with mass assignment

## What NOT to Include
- Do NOT include working exploit code
- Do NOT invent CVE IDs not in COMMON_CVES
- Do NOT use placeholder versions — use real versions from the fingerprint
- Do NOT mark services as patched when they're EOL
