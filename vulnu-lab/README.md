# VulnU-Lab Final - Raphael 2.0 Test Target

## Setup
docker compose up -d --build

## Vulnerabilities
- SQLi in www/login.php and search.php
- LFI in page.php
- Unrestricted upload in profile/avatar.php
- IDOR and mass assignment in ums-flask
- WAF bypass training via proxy

Air-gapped training lab only. For educational use.