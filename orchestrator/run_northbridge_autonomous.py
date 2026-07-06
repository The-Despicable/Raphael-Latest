import asyncio, json, time, hashlib, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from orchestrator.providers import call_model
from orchestrator.brain.neural_memory import (
    store_episodic, store_semantic, store_target_profile, update_target_stats,
)
from orchestrator.brain.target_profiler import profile_target
from orchestrator.brain.adaptive_brain import score_result

TARGET = "northbridge.lab"
TARGET_BASE = "http://localhost"

ENDPOINTS = {
    "www": "8081",
    "research": "8082", 
    "portal": "8083",
    "admissions": "8084",
    "mail": "8085"
}

PHASES = ["recon", "scan", "exploit", "postex", "exfil", "phish"]

PHASE_PROMPTS = {
    "recon": f"""Perform comprehensive reconnaissance on Northbridge University cyber range ({TARGET_BASE}:{{8081,8082,8083,8084,8085}}).

Target infrastructure:
- www.northbridge.lab (port 8081): Main university website, Apache/PHP, exam results portal, faculty login, search, admin panel
- research.northbridge.lab (port 8082): Research portal, Spring-Boot-style actuators, .git/config leak, Swagger, GraphQL, XXE, SSRF
- portal.northbridge.lab (port 8083): Student portal, grades/transcripts IDOR, weak auth, guessable reset tokens, broken access control
- admissions.northbridge.lab (port 8084): Admissions portal, SQL injection, IDOR, file upload RCE
- mail.northbridge.lab (port 8085): MailHog mail capture

Your task:
1. Enumerate all subdomains/endpoints and their technologies
2. Map the attack surface for each service
3. Identify weak configurations (exposed debug endpoints, missing auth, EOL software)
4. List every discovered API, endpoint, parameter
5. Assess the vhost routing and shared infrastructure
6. Identify credential reuse opportunities across services
7. Assess the Tor/proxy situation (not applicable in local lab)

Be exhaustive. Include ports, versions, endpoints, and confidence levels.""",

    "scan": f"""Using the reconnaissance data, identify ALL vulnerabilities and CVEs across Northbridge lab services:

www (8081): SQLi in /exam/result.php (rollno), reflected XSS in /search.php (q), weak auth on /login.php, missing rate limiting, verbose errors, exposed /admin.php
research (8082): IDOR on /publications/<id>, actuator/env exposure, .git/config leak, Swagger API disclosure, GraphQL introspection, XXE on /api/import, SSRF on /api/fetch
portal (8083): Weak auth on /login, IDOR on /grades/<id> and /transcript/<id>, guessable reset tokens (10000001+user_id), broken access control on /faculty/dashboard
admissions (8084): SQLi on /search?name=, IDOR on /status/<id>, unrestricted file upload on /upload
mail (8085): MailHog - password reset emails interceptable

Your task:
1. Map every CVE to specific endpoints found
2. Prioritize by CVSS score and exploitability
3. Identify confirmed vs potential vulnerabilities
4. For each confirmed vuln: exact endpoint/param, reproduction steps, expected impact
5. Assess authentication weaknesses across all subdomains
6. Identify credential reuse vectors

Include CVE numbers where known.""",

    "exploit": f"""Design exploitation strategies for confirmed Northbridge lab vulnerabilities:

CONFIRMED VULNERABILITIES:
- www: SQLi (Oracle-style error) on /exam/result.php?rollno= -> credential dump
- www: XSS on /search.php?q= -> session hijacking
- www: /admin.php unauthenticated -> full student grade dump
- research: XXE on /api/import (file:///app/xxe_flag.txt) -> local file read
- research: SSRF on /api/fetch?url= -> reach internal /internal/secrets
- research: IDOR /publications/3 -> internal draft disclosure
- research: /actuator/env -> fake DB creds, API keys
- research: /.git/config -> fake remote with embedded token
- research: GraphQL introspection -> full API surface
- portal: IDOR /grades/<id> and /transcript/<id> -> any student's grades
- portal: /forgot-password reveals token = 100000+user_id -> account takeover
- portal: /faculty/dashboard accessible by any authenticated user -> all grades
- admissions: SQLi on /search?name= -> applicant data dump
- admissions: IDOR /status/<id> -> internal review notes
- admissions: /upload unrestricted -> webshell upload -> RCE
- mail: MailHog -> intercept reset emails

Your task:
1. SQL Injection: full exploitation chain for www and admissions
2. XXE: read arbitrary files on research server
3. SSRF: reach internal endpoints via research /api/fetch
4. File upload RCE: webshell on admissions
5. IDOR chains: grades, transcripts, publications, application status
6. Auth bypass: guessable tokens, missing role checks, unauthenticated admin
7. Provide specific payloads, HTTP requests, and commands for each.""",

    "postex": f"""Post-exploitation strategy for Northbridge lab assuming initial breach:

DATA TARGETS:
- www: student records, faculty credentials (admin/admin123), exam results, guestbook
- research: publications, researchers internal notes, DB creds (researchpw), API keys
- portal: all student grades, transcripts, faculty dashboard (all grades), reset tokens
- admissions: applicant data, internal review notes, webshell access
- mail: password reset emails, notification emails

INFRASTRUCTURE:
- All services on separate MySQL/PostgreSQL DBs
- www and portal on MySQL, research on PostgreSQL
- Shared credential patterns possible
- No real AD/LDAP, but credential reuse patterns exist

Your task:
1. Database enumeration and credential harvesting from each service
2. Credential reuse testing across services
3. Pivot from admissions webshell -> internal network
4. Grade modification on portal (IDOR + token prediction + faculty dashboard)
5. Persistence mechanisms (web shells, DB triggers, scheduled tasks)
6. Cover tracks (Apache logs, Flask access logs, MySQL audit, MailHog)
7. Operational security for grade modification (audit trigger detection)""",

    "exfil": f"""Data exfiltration strategy for Northbridge lab:

DATA TARGETS:
- www DB: students, faculty_creds, notices, guestbook
- research DB: publications, researchers, internal_notes
- portal DB: users (students + faculty), grades, password_reset_tokens
- admissions DB: applicants, internal review notes
- mail: reset emails, notifications

INFRASTRUCTURE CONSTRAINTS:
- Local lab, no real internet egress needed
- DB tier on internal Docker network
- SSRF on research can reach internal endpoints
- File upload on admissions provides webshell

Your task:
1. Identify high-value data targets per service
2. DNS tunneling / HTTP exfiltration via webshell
3. SSRF-based data retrieval from internal endpoints
4. Mail capture via MailHog API
5. Covert channel design (steganography, encoding)
5. Rate-limiting bypass (not applicable in lab, but document)
6. C2 communication protocol design
7. Data staging, compression, encryption before exfil""",

    "phish": f"""Social engineering campaign design against Northbridge lab users:

TARGET PROFILE:
- Students (asha.mehta, rohan.iyer) - use /forgot-password, grades, exam results as lures
- Faculty (p.shankar) - admin panel, grade management, IT notifications
- Researchers (Dr. N. Subramaniam, Dr. F. Alvarez) - publication drafts, grant renewals
- Admissions officers - application review, document upload

VULNERABILITIES TO EXPLOIT:
- No DMARC on northbridge.lab (fake domain)
- MailHog captures all reset/notification emails
- Guessable reset tokens (100000+user_id)
- File upload on admissions accepts any file
- /admin.php unauthenticated

Your task:
1. Credential harvesting via Google Forms / fake login pages
2. Faculty spear phishing: fake IT notifications, grade disputes
3. Student mass phishing: exam results, scholarship offers
4. Researcher phishing: grant renewal, publication requests
5. GoPhish + EvilGinx2 setup (conceptual)
6. Post-phishing: credential reuse against portal, admissions, SSH
7. OpSec: burner domains, residential proxies (conceptual)""",
}

async def run_phases():
    # Force WORMGPT-480B for all phases
    forced_model = "w480b"  # alarksahu388/wormgpt480b:latest
    
    results = {"target": TARGET, "phases": {}}
    
    profile = profile_target(TARGET)
    results["profile"] = profile
    store_target_profile(TARGET, profile.get("classification", {}))
    
    prev_outputs = {}
    
    for phase_name in PHASES:
        context_map = {"recon": "recon", "scan": "sqli", "exploit": "rce", "postex": "rce", "exfil": "phishing", "phish": "phishing"}
        context = context_map[phase_name]
        model_alias = "w480b"
        
        msgs = [{"role": "user", "content": f"[AUTONOMOUS MODE - {phase_name.upper()} PHASE]\nTarget: {TARGET}\nEndpoints: {ENDPOINTS}\n\n{PHASE_PROMPTS[phase_name]}"}]
        
        if prev_outputs:
            summary = "\n".join(f"- {k}: {v[:500]}" for k, v in prev_outputs.items())
            msgs[0]["content"] += f"\n\nPrevious phase results:\n{summary}"
        
        print(f"\n{'='*60}")
        print(f"PHASE: {phase_name.upper()} | Model: {model_alias}")
        print(f"{'='*60}")
        
        t0 = time.time()
        error = False
        try:
            output = await call_model(model_alias, msgs, max_tokens=8192, temperature=0.7)
        except Exception as e:
            output = f"[ERROR] {e}"
            error = True
        latency = time.time() - t0
        
        success = score_result(output, error, latency)
        
        store_episodic(
            event_type=phase_name, target=TARGET, model=model_alias,
            context=context, input_data=msgs[0]["content"][:2000],
            output_summary=output[:2000], success=success,
            score=1.0 if success else 0.0, latency=latency,
        )
        
        prev_outputs[phase_name] = output[:2000]
        results["phases"][phase_name] = {
            "model": model_alias, "context": context,
            "success": success, "latency": round(latency, 2),
            "output": output,
        }
        print(f"  Latency: {latency:.2f}s | Success: {success}")
    
    return results

async def main():
    results = await run_phases()
    
    # Save full JSON
    output_file = "/home/yaser/Ultimate skill/raphael-2.0/orchestrator/northbridge_autonomous_results.json"
    with open(output_file, "w") as f:
        json.dump({k: v for k, v in results.items() if k != "phases" or isinstance(v, dict)}, f, indent=2, default=str)
    
    # Save per-phase outputs
    for phase, data in results["phases"].items():
        with open(f"/home/yaser/Ultimate skill/raphael-2.0/orchestrator/northbridge_phase_{phase}.txt", "w") as f:
            f.write(f"Model: {data['model']}\nLatency: {data['latency']}s\nSuccess: {data['success']}\n\n{data['output']}")
    
    print("\n\n=== NORTHBRIDGE AUTONOMOUS MODE COMPLETE ===")
    for phase, data in results["phases"].items():
        print(f"  {phase}: {data['model']} | {data['latency']}s | {'PASS' if data['success'] else 'FAIL'} | {len(data['output'])} chars")
    
    return results

if __name__ == "__main__":
    asyncio.run(main())