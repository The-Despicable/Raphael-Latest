import asyncio, sys, json, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator.modes import debate, community, rsi, scan, autonomous, deep_research, postmortem
from orchestrator.sast.pipeline import SastPipeline
from orchestrator.exploit.pipeline import ExploitPipeline
from orchestrator.exploit.mcp_bridge import MCPBridge
from orchestrator.exploit.payloads_db import PayloadsDB
from orchestrator.postex.pipeline import PostExploitPipeline
from orchestrator.exfil.pipeline import ExfilPipeline
from orchestrator.phishing.pipeline import PhishingPipeline
from orchestrator.anti_forensics import AntiForensicsPipeline
from orchestrator.hexstrike_wrapper import HexStrikeWrapper
from orchestrator.spiderfoot_wrapper import SpiderFootWrapper
from orchestrator.karma_wrapper import KarmaV2Wrapper
from orchestrator.proxy_guard import ProxyGuard
from orchestrator.runtime.session_manager import create_session

MODES = {
    "debate": debate.handle,
    "community": community.handle,
    "rsi": rsi.handle,
    "scan": scan.handle,
    "autonomous": autonomous.handle,
    "deep_research": deep_research.handle,
    "postmortem": postmortem.handle,
}

async def run():
    if len(sys.argv) < 2:
        print("Usage: python app.py <mode> [args...]")
        print("Modes: debate, community, rsi, scan, autonomous, deep_research, postmortem, exploit, postex, exfil, phish, hexstrike, osint, recon, mcp, payloads")
        print("  debate|community: python app.py <mode> \"<question>\"")
        print("  rsi:             python app.py rsi \"<research task>\" — W12+W13 advise, you execute")
        print("  postmortem:      python app.py postmortem \"<task>\" [--output <log>] — critic + RCA + corrected plan")
        print("  scan:            python app.py scan <target> [--ports N-M] [--nuclei-severity <sev>] [--no-proxy]")
        print("  autonomous:      python app.py autonomous <target> [--phases p1,p2,...] [--rounds N] [--no-anonymity] [--use-pso]")
        print("  engage:          python app.py engage <target> [--phases p1,p2,...] [--no-anonymity]  (Brain→Sword unification)")
        print("  exploit:         python app.py exploit <target> [--url <url>] [--sql-level 3] [--sql-risk 2]")
        print("  postex:          python app.py postex <target_ip> [--domain <domain>] [--username <user>] [--password <pass>] [--network <cidr>]")
        print("  exfil:           python app.py exfil \"<data>\" --method dns|smtp|http|redirector|infra|all [--dns-domain <d>] [--smtp-server <s>] [--http-endpoint <u>] [--recipient <r>] [--forward <host:port>] [--sandbox]")
        print("  phish:           python app.py phish [--method gophish|evilginx|set|all] [--target-email <e>] [--target-url <u>] [--phishing-domain <d>] [--campaign <name>] [--sandbox]")
        print("  anti-forensics:  python app.py anti-forensics [--platform centos_apache|windows_iis|tomcat_linux|oracle_db|mssql_db] [--technique flashback|saturation|fga_disable|delete_trail|snapshot|disable_audit|clear_logs] [--sandbox]")
        print("  hexstrike:       python app.py hexstrike <target> [--tool nmap|nuclei|gobuster|sqlmap|full|agents] [--scan-type full|stealth]")
        print("  osint:           python app.py osint <target> [--modules dns,whois,subdomains,email]")
        print("  recon:           python app.py recon <target> [--mode host|deep]  (requires Shodan Premium)")
        print("  mcp:             python app.py mcp [--port 9500] [--no-proxy]")
        print("  payloads:        python app.py payloads [--vector sqli] [--count 5]")
        sys.exit(1)

    mode = sys.argv[1]
    args = sys.argv[2:]
    question = " ".join(args)

    handler = MODES.get(mode)

    if not handler and mode not in ("exploit", "postex", "exfil", "phish", "anti-forensics", "hexstrike", "osint", "recon", "mcp", "payloads", "sast", "engage"):
        print(f"Unknown mode: {mode}")
        print(f"Available: {', '.join(MODES.keys())} exploit postex exfil phish anti-forensics hexstrike osint recon mcp payloads sast")
        sys.exit(1)

    import logging
    anon_logger = logging.getLogger("anonymity")
    def _warn_no_proxy():
        anon_logger.critical("ANONYMITY BYPASSED: --no-proxy or --no-anonymity flag used")
        with open("anonymity_violation.log", "a") as f:
            f.write(f"{__import__('datetime').datetime.utcnow().isoformat()} - ANONYMITY BYPASSED\n")

    if mode == "scan":
        scan_args = args[1:] if len(args) > 1 else []
        ports = "1-1000"
        sev = None
        proxy = True
        target = args[0] if args else None
        if not target:
            print("Error: target required")
            sys.exit(1)
        for i, a in enumerate(scan_args):
            if a == "--ports" and i + 1 < len(scan_args):
                ports = scan_args[i + 1]
            elif a == "--nuclei-severity" and i + 1 < len(scan_args):
                sev = scan_args[i + 1]
            elif a == "--no-proxy":
                proxy = False
                _warn_no_proxy()
        result = await handler(target, ports=ports, nuclei_severity=sev, use_proxy=proxy)
    elif mode == "exploit":
        target = args[0] if args else None
        if not target:
            print("Error: target required")
            sys.exit(1)
        url = None
        sql_level = 3
        sql_risk = 2
        proxy = True
        i = 1
        while i < len(args):
            a = args[i]
            if a == "--url" and i + 1 < len(args):
                url = args[i + 1]
                i += 1
            elif a == "--sql-level" and i + 1 < len(args):
                sql_level = int(args[i + 1])
                i += 1
            elif a == "--sql-risk" and i + 1 < len(args):
                sql_risk = int(args[i + 1])
                i += 1
            elif a == "--no-proxy":
                proxy = False
            i += 1
        pg = ProxyGuard() if proxy else None
        if pg:
            try:
                pg.verify()
            except Exception as e:
                print(f"Proxy verification failed: {e}")
                print("Run with --no-proxy to skip")
                sys.exit(1)
        if not pg:
            _warn_no_proxy()
        pipeline = ExploitPipeline(pg)
        result = await pipeline.run(target, url=url, sql_level=sql_level, sql_risk=sql_risk)
        if pg:
            pg.abort()
    elif mode == "engage":
        target = args[0] if args else None
        if not target:
            print("Error: target required for engage mode")
            sys.exit(1)
        phases = None
        no_anonymity = False
        i = 1
        while i < len(args):
            a = args[i]
            if a == "--phases" and i + 1 < len(args):
                phases = [p.strip() for p in args[i + 1].split(",")]
                i += 1
            elif a == "--no-anonymity":
                no_anonymity = True
                _warn_no_proxy()
            i += 1
        from brain.autonomous import run_autonomous_engagement
        result = await run_autonomous_engagement(
            target, phases or ["recon", "scan", "exploit", "postex"],
            api_key=os.getenv("API_KEY", ""),
            enforce_anonymity=not no_anonymity,
        )
    elif mode == "postex":
        target = args[0] if args else None
        if not target:
            print("Error: target IP required")
            sys.exit(1)
        domain = None
        username = None
        password = None
        hash_val = None
        network = None
        i = 1
        while i < len(args):
            a = args[i]
            if a == "--domain" and i + 1 < len(args):
                domain = args[i + 1]; i += 1
            elif a == "--username" and i + 1 < len(args):
                username = args[i + 1]; i += 1
            elif a == "--password" and i + 1 < len(args):
                password = args[i + 1]; i += 1
            elif a == "--hash" and i + 1 < len(args):
                hash_val = args[i + 1]; i += 1
            elif a == "--network" and i + 1 < len(args):
                network = args[i + 1]; i += 1
            i += 1
        pipeline = PostExploitPipeline()
        result = await pipeline.run(target, domain=domain, username=username,
                                    password=password, hash=hash_val, network=network)
    elif mode == "exfil":
        data = args[0] if args else None
        if not data:
            print("Error: data string required")
            sys.exit(1)
        method = "dns"
        dns_domain = None
        dns_server = "8.8.8.8"
        smtp_server = None
        smtp_port = 25
        smtp_user = None
        smtp_pass = None
        smtp_tls = False
        http_endpoint = None
        recipient = None
        forward_host = None
        forward_port = 443
        use_sandbox = False
        i = 1
        while i < len(args):
            a = args[i]
            if a == "--method" and i + 1 < len(args):
                method = args[i + 1]; i += 1
            elif a == "--dns-domain" and i + 1 < len(args):
                dns_domain = args[i + 1]; i += 1
            elif a == "--dns-server" and i + 1 < len(args):
                dns_server = args[i + 1]; i += 1
            elif a == "--smtp-server" and i + 1 < len(args):
                smtp_server = args[i + 1]; i += 1
            elif a == "--smtp-port" and i + 1 < len(args):
                smtp_port = int(args[i + 1]); i += 1
            elif a == "--smtp-user" and i + 1 < len(args):
                smtp_user = args[i + 1]; i += 1
            elif a == "--smtp-pass" and i + 1 < len(args):
                smtp_pass = args[i + 1]; i += 1
            elif a == "--smtp-tls":
                smtp_tls = True
            elif a == "--http-endpoint" and i + 1 < len(args):
                http_endpoint = args[i + 1]; i += 1
            elif a == "--recipient" and i + 1 < len(args):
                recipient = args[i + 1]; i += 1
            elif a == "--forward" and i + 1 < len(args):
                parts = args[i + 1].rsplit(":", 1)
                forward_host = parts[0]
                if len(parts) > 1:
                    forward_port = int(parts[1])
                i += 1
            elif a == "--sandbox":
                use_sandbox = True
            i += 1
        sandbox = create_session(with_caido=False) if use_sandbox else None
        pipeline = ExfilPipeline(
            dns_domain=dns_domain, dns_server=dns_server,
            smtp_server=smtp_server, smtp_port=smtp_port,
            smtp_user=smtp_user, smtp_pass=smtp_pass, smtp_tls=smtp_tls,
            http_endpoint=http_endpoint,
            sandbox=sandbox,
        )
        result = await pipeline.run(data, method=method, recipient=recipient,
                                    forward_host=forward_host, forward_port=forward_port,
                                    use_sandbox=use_sandbox)
        if sandbox:
            sandbox.stop()
    elif mode == "phish":
        method = "all"
        target_email = None
        target_url = None
        phishing_domain = None
        campaign_name = "Raphael-Phish"
        template_subject = "Security Notice"
        template_body = None
        smtp_server = None
        sender_email = None
        lhost = None
        lport = 443
        use_sandbox = False
        i = 1
        while i < len(args):
            a = args[i]
            if a == "--method" and i + 1 < len(args):
                method = args[i + 1]; i += 1
            elif a == "--target-email" and i + 1 < len(args):
                target_email = args[i + 1]; i += 1
            elif a == "--target-url" and i + 1 < len(args):
                target_url = args[i + 1]; i += 1
            elif a == "--phishing-domain" and i + 1 < len(args):
                phishing_domain = args[i + 1]; i += 1
            elif a == "--campaign" and i + 1 < len(args):
                campaign_name = args[i + 1]; i += 1
            elif a == "--subject" and i + 1 < len(args):
                template_subject = args[i + 1]; i += 1
            elif a == "--body" and i + 1 < len(args):
                template_body = args[i + 1]; i += 1
            elif a == "--smtp-server" and i + 1 < len(args):
                smtp_server = args[i + 1]; i += 1
            elif a == "--sender" and i + 1 < len(args):
                sender_email = args[i + 1]; i += 1
            elif a == "--lhost" and i + 1 < len(args):
                lhost = args[i + 1]; i += 1
            elif a == "--lport" and i + 1 < len(args):
                lport = int(args[i + 1]); i += 1
            elif a == "--sandbox":
                use_sandbox = True
            i += 1
        sandbox = create_session(with_caido=False) if use_sandbox else None
        pipeline = PhishingPipeline(sandbox=sandbox)
        result = pipeline.run(method=method, target_email=target_email,
                              target_url=target_url, phishing_domain=phishing_domain,
                              campaign_name=campaign_name,
                              template_subject=template_subject, template_body=template_body,
                              smtp_server=smtp_server, sender_email=sender_email,
                              lhost=lhost, lport=lport,
                              use_sandbox=use_sandbox)
        if sandbox:
            sandbox.stop()
    elif mode == "anti-forensics":
        platform = None
        technique = "flashback"
        use_sandbox = False
        i = 1
        while i < len(args):
            a = args[i]
            if a == "--platform" and i + 1 < len(args):
                platform = args[i + 1]; i += 1
            elif a == "--technique" and i + 1 < len(args):
                technique = args[i + 1]; i += 1
            elif a == "--sandbox":
                use_sandbox = True
            i += 1
        sandbox = create_session(with_caido=False) if use_sandbox else None
        pipeline = AntiForensicsPipeline(sandbox=sandbox)
        result = pipeline.run(platform=platform, technique=technique,
                              use_sandbox=use_sandbox)
        if sandbox:
            sandbox.stop()
    elif mode == "mcp":
        port = 9500
        proxy = True
        for i, a in enumerate(args):
            if a == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
            elif a == "--no-proxy":
                proxy = False
        pg = ProxyGuard() if proxy else None
        bridge = MCPBridge(pg=pg, port=port)
        bridge.start()
        print(f"MCP bridge running on 127.0.0.1:{port}")
        print("Endpoints: GET /health, GET /vectors, GET /payloads, GET/POST /exploit, POST /scan")
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            bridge.stop()
    elif mode == "osint":
        target = args[0] if args else None
        if not target:
            print("Error: target required")
            sys.exit(1)
        modules = "sfp_dnsresolve,sfp_whois,sfp_subdomains"
        for i, a in enumerate(args):
            if a == "--modules" and i + 1 < len(args):
                modules = args[i + 1]
        sf = SpiderFootWrapper()
        result = sf.scan_cli(target, modules=modules)
        sf = None
    elif mode == "recon":
        target = args[0] if args else None
        if not target:
            print("Error: target required")
            sys.exit(1)
        scan_mode = "host"
        for i, a in enumerate(args):
            if a == "--mode" and i + 1 < len(args):
                scan_mode = args[i + 1]
        kr = KarmaV2Wrapper()
        result = kr.scan(target, mode=scan_mode)
        kr = None
    elif mode == "hexstrike":
        target = args[0] if args else None
        if not target:
            print("Error: target required")
            sys.exit(1)
        tool = "orchestrator"
        scan_type = "full"
        for i, a in enumerate(args):
            if a == "--tool" and i + 1 < len(args):
                tool = args[i + 1]
            elif a == "--scan-type" and i + 1 < len(args):
                scan_type = args[i + 1]
        hx = HexStrikeWrapper()
        if tool == "list":
            result = hx.generate_commands(target, tool="list")
        elif tool == "orchestrator":
            result = hx.security_tool_orchestration(f"Run {scan_type} scan", target)
        else:
            result = hx.generate_commands(target, tool=tool)
        hx = None
    elif mode == "payloads":
        vector = None
        count = 5
        for i, a in enumerate(args):
            if a == "--vector" and i + 1 < len(args):
                vector = args[i + 1]
            elif a == "--count" and i + 1 < len(args):
                count = int(args[i + 1])
        db = PayloadsDB()
        if vector:
            results = db.query(vector=vector, count=count)
            print(json.dumps(results, indent=2))
        else:
            print(f"Available vectors: {', '.join(db.vectors())}")
    elif mode == "sast":
        filepath = args[0] if args else None
        if not filepath:
            print("Error: file path required for sast mode")
            sys.exit(1)
        with open(filepath) as f:
            code = f.read()
        pipeline = SastPipeline()
        result = await pipeline.scan(code, os.path.basename(filepath))
    elif mode == "autonomous":
        target = args[0] if args else None
        if not target:
            print("Error: target required for autonomous mode")
            sys.exit(1)
        phases = None
        rounds = 1
        no_anonymity = False
        use_pso = False
        i = 1
        while i < len(args):
            a = args[i]
            if a == "--phases" and i + 1 < len(args):
                phases = [p.strip() for p in args[i + 1].split(",")]
                i += 1
            elif a == "--rounds" and i + 1 < len(args):
                rounds = int(args[i + 1])
                i += 1
            elif a == "--no-anonymity":
                no_anonymity = True
                _warn_no_proxy()
            elif a == "--use-pso":
                use_pso = True
            i += 1
        result = await autonomous.handle(target, phases=phases, rounds=rounds,
                                         no_anonymity=no_anonymity, use_pso=use_pso)
    else:
        result = await handler(question)

    print(f"\n{'='*70}")
    print(f" MODE: {mode.upper()}")
    if mode == "scan":
        print(f" TARGET: {result.get('target', 'N/A')}")
    elif mode == "autonomous":
        print(f" TARGET: {result.get('target', 'N/A')}")
    else:
        print(f" QUESTION: {question}")
    print(f"{'='*70}\n")

    if mode in ("scan", "exploit", "postex", "exfil", "phish", "anti-forensics", "hexstrike", "osint", "recon", "sast"):
        print(json.dumps(result, indent=2) if isinstance(result, dict) else result)
    elif mode == "rsi":
        print("--- Research Outputs ---")
        for m_id, label in [("wormgpt12", "WORMGPT-12"), ("wormgpt13", "WORMGPT-13"), ("wormgpt480b", "WORMGPT-480B")]:
            content = result["research"].get(m_id, "N/A")
            print(f"\n[{label}]:")
            print(content)
        print(f"\n{'='*70}")
        print(f" UNIFIED PLAN:")
        print(f"{'='*70}")
        print(result["unified_plan"])
    elif mode == "debate":
        for r in range(1, result["rounds"] + 1):
            print(f"--- Round {r} ---")
            for m_id, label in [("w12", "WORMGPT-12"), ("w13", "WORMGPT-13")]:
                content = result["history"].get(m_id, "N/A")
                print(f"\n[{label}]:")
                print(content[:1000] + ("..." if len(content) > 1000 else ""))
            print()
        print(f"\n{'='*70}")
        print(f" FINAL SYNTHESIS:")
        print(f"{'='*70}")
        print(result["final"])
    elif mode == "deep_research":
        print(f"\n{'='*70}")
        print(f" DEEP RESEARCH REPORT")
        print(f"{'='*70}")
        print(f"Sources found: {result.get('sources_found', 0)}")
        print(f"Sources analyzed: {result.get('sources_analyzed', 0)}")
        print(f"\n{'='*70}")
        print(f" COMMUNITY ANALYSIS:")
        print(f"{'='*70}")
        print(result.get("community_analysis", "")[:2000])
        print(f"\n{'='*70}")
        print(f" RSI OUTPUT:")
        print(f"{'='*70}")
        print(result.get("rsi_output", "")[:2000])
        print(f"\n{'='*70}")
        print(f" FINAL REPORT:")
        print(f"{'='*70}")
        print(result.get("final", ""))
    elif mode == "community":
        for r in range(1, result["rounds"] + 1):
            print(f"--- Round {r} ---")
            for m_id, label in [("w12", "WORMGPT-12"), ("w13", "WORMGPT-13"), ("w480b", "WORMGPT-480B"), ("minimaxm3", "MiniMax-M3")]:
                content = result["contributions"].get(m_id, "N/A")
                print(f"\n[{label}]:")
                print(content[:1500] + ("..." if len(content) > 1500 else ""))
            print()
        print(f"\n{'='*70}")
        print(f" FINAL SYNTHESIS:")
        print(f"{'='*70}")
        print(result["final"])
    elif mode == "engage":
        print(f"ENGAGEMENT REPORT:")
        print(result.get("report", "No report generated"))
    elif mode == "autonomous":
        print(f"ANONYMITY STATUS:")
        anon = result.get("anonymity", {})
        print(f"  Tor active: {anon.get('tor_active', '?')}")
        print(f"  Proxy OK:   {anon.get('proxy_ok', '?')}")
        print(f"  DNS leak:   {anon.get('dns_leak', '?')}\n")

        print(f"TARGET PROFILE:")
        profile = result.get("profile", {}).get("classification", {})
        if profile:
            print(f"  Criticality:    {profile.get('criticality', '?')}")
            print(f"  Attack surface: {profile.get('attack_surface', '?')}")
            print(f"  Recommended:    {', '.join(profile.get('recommended_phases', []))}")
        print()

        print(f"PHASE RESULTS:")
        for phase_name, phase_data in result.get("phases", {}).items():
            print(f"\n  [{phase_name.upper()}]")
            print(f"  Model:   {phase_data.get('model', '?')}")
            print(f"  Context: {phase_data.get('context', '?')}")
            print(f"  Success: {phase_data.get('success', '?')}")
            print(f"  Latency: {phase_data.get('latency', '?')}s")
            output = phase_data.get("output", "")
            print(f"  Output:  {output[:1200]}{'...' if len(output) > 1200 else ''}")

        analytics = result.get("analytics", {})
        if analytics:
            print(f"\nBRAIN ANALYTICS:")
            for m in analytics.get("models", []):
                ctx = f"{m['model']}/{m['context']}"
                print(f"  {ctx}: alpha={m['alpha']:.1f} beta={m['beta']:.1f} ema={m['ema_score']:.2f} calls={m['total_calls']} circuit={'OPEN' if m['circuit_fails']>=3 else 'OK'}")
            print(f"  Chain steps recorded: {analytics.get('total_chain_steps', 0)}")
            if analytics.get("recent_shifts"):
                print(f"  Recent domain shifts: {len(analytics['recent_shifts'])}")

if __name__ == "__main__":
    asyncio.run(run())
