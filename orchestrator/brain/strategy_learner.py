"""
strategy_learner.py — Reinforcement Learning-based strategy selection engine.

Q-learning variant that learns optimal phase ordering from engagement outcomes.
Seeded with transfer knowledge from existing phase modules (lpd_exploit,
pjl_exploit, craft_exploit, etc.) so Raphael is immediately competent.

State encoding: f{foothold}_s{services}_l{has_lpd}_p{has_pjl}_w{has_web}_ph{phase_bucket}
- foothold: none | web | low_priv | high_priv | root
- services: 0 | 1 | 2 | 3+ (count bucket)
- has_lpd: 0 | 1
- has_pjl: 0 | 1
- has_web: 0 | 1
- phase_bucket: recon | entry | postex | exfil | privesc

Actions: phase names from PHASE_EXECUTORS
Rewards: +10 flag, +5 credential, +3 new access level, +1 new service,
         -1 timeout, -2 failed phase, -5 circuit breaker trip
"""

import json
import logging
import os
import random
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from orchestrator.brain.phases.models import Finding, Severity

logger = logging.getLogger("strategy_learner")

MODEL_PATH = os.getenv(
    "STRATEGY_MODEL_PATH",
    str(Path(__file__).resolve().parent.parent / "data" / "strategy_model.json"),
)

ALPHA = 0.3
GAMMA = 0.9
EPSILON_INIT = 0.4
EPSILON_DECAY = 0.995
EPSILON_MIN = 0.05

REWARD_COMPONENTS = {
    "flag_found": 10.0,
    "credential_obtained": 5.0,
    "new_access_level": 3.0,
    "service_discovered": 1.0,
    "phase_timeout": -1.0,
    "phase_failed": -2.0,
    "circuit_breaker_tripped": -5.0,
    "wasted_effort": -0.5,
}

PHASE_BUCKET_MAP = {
    "recon": "recon",
    "scan": "recon",
    "web_fuzz": "recon",
    "web_scan": "recon",
    "supply_chain_recon": "recon",
    "anonymous_ttp": "entry",
    "port_scan": "recon",
    "exploit": "entry",
    "lpd_exploit": "entry",
    "pjl_exploit": "entry",
    "relay_chain": "entry",
    "craft_exploit": "entry",
    "openstamanager_exploit": "entry",
    "generic_exploit": "entry",
    "direct_exploit": "entry",
    "llm_exploit": "entry",
    "nextjs_exploit": "entry",
    "privesc": "privesc",
    "socket_scm": "privesc",
    "honeypot_analyzer": "privesc",
    "postex": "postex",
    "credential": "postex",
    "persistence": "postex",
    "pivot": "postex",
    "lateral": "postex",
    "exploit_chain": "postex",
    "exfil": "exfil",
    "phish": "exfil",
    "reporting": "exfil",
    "flag_capture": "exfil",
}

INITIAL_Q = {
    ("froot_s3+_l1_p1_w1_phprivesc", "flag_capture"): 5.0,
    ("froot_s3+_l1_p1_w1_phprivesc", "reporting"): 3.0,
    ("froot_s3+_l1_p1_w1_phprivesc", "exfil"): 4.0,
    ("froot_s3+_l1_p1_w1_phprivesc", "persistence"): 4.0,
    ("fhigh_priv_s3+_l1_p1_w1_phpostex", "exfil"): 4.0,
    ("fhigh_priv_s3+_l1_p1_w1_phpostex", "flag_capture"): 5.0,
    ("fhigh_priv_s3+_l1_p1_w1_phpostex", "privesc"): 5.0,
    ("fhigh_priv_s3+_l1_p1_w1_phpostex", "persistence"): 4.0,
    ("fhigh_priv_s3+_l1_p1_w1_phpostex", "reporting"): 3.0,
    ("flow_priv_s3+_l1_p1_w1_phprivesc", "privesc"): 5.0,
    ("flow_priv_s3+_l1_p1_w1_phprivesc", "relay_chain"): 5.0,
    ("flow_priv_s3+_l1_p1_w1_phprivesc", "pjl_exploit"): 4.0,
    ("flow_priv_s3+_l1_p1_w1_phprivesc", "socket_scm"): 3.0,
    ("flow_priv_s3+_l1_p1_w1_phprivesc", "honeypot_analyzer"): 3.0,
    ("flow_priv_s3+_l1_p1_w1_phprivesc", "credential"): 4.0,
    ("flow_priv_s3+_l1_p1_w1_phprivesc", "postex"): 3.0,
    ("flow_priv_s3+_l1_p1_w1_phprivesc", "persistence"): 2.0,
    ("flow_priv_s2_l1_p1_w1_phprivesc", "privesc"): 5.0,
    ("flow_priv_s2_l1_p1_w1_phprivesc", "relay_chain"): 5.0,
    ("flow_priv_s2_l1_p1_w1_phprivesc", "pjl_exploit"): 4.0,
    ("flow_priv_s2_l1_p1_w1_phprivesc", "socket_scm"): 3.0,
    ("flow_priv_s2_l1_p1_w1_phprivesc", "credential"): 4.0,
    ("flow_priv_s2_l1_p1_w1_phprivesc", "postex"): 3.0,
    ("fweb_s3+_l1_p1_w1_phentry", "pjl_exploit"): 5.0,
    ("fweb_s3+_l1_p1_w1_phentry", "relay_chain"): 4.0,
    ("fweb_s3+_l1_p1_w1_phentry", "socket_scm"): 4.0,
    ("fweb_s3+_l1_p1_w1_phentry", "honeypot_analyzer"): 3.0,
    ("fweb_s3+_l1_p1_w1_phentry", "privesc"): 3.0,
    ("fweb_s3+_l1_p1_w1_phentry", "exploit_chain"): 4.0,
    ("fweb_s2_l1_p1_w1_phentry", "pjl_exploit"): 5.0,
    ("fweb_s2_l1_p1_w1_phentry", "relay_chain"): 4.0,
    ("fweb_s2_l1_p1_w1_phentry", "socket_scm"): 4.0,
    ("fweb_s2_l1_p1_w1_phentry", "honeypot_analyzer"): 3.0,
    ("fweb_s2_l1_p1_w1_phentry", "exploit_chain"): 4.0,
    ("fweb_s2_l1_p1_w1_phentry", "lpd_exploit"): 4.0,
    ("fweb_s2_l1_p1_w1_phentry", "privesc"): 3.0,
    ("fweb_s1_l1_p1_w1_phentry", "relay_chain"): 5.0,
    ("fweb_s1_l1_p1_w1_phentry", "pjl_exploit"): 4.0,
    ("fweb_s1_l1_p1_w1_phentry", "lpd_exploit"): 5.0,
    ("fweb_s1_l1_p1_w1_phentry", "socket_scm"): 3.0,
    ("fweb_s1_l1_p1_w1_phentry", "exploit_chain"): 3.0,
    ("fweb_s1_l1_p1_w1_phentry", "privesc"): 2.0,
    ("fweb_s1_l0_p0_w1_phentry", "craft_exploit"): 5.0,
    ("fweb_s1_l0_p0_w1_phentry", "web_fuzz"): 4.0,
    ("fweb_s1_l0_p0_w1_phentry", "web_scan"): 4.0,
    ("fweb_s1_l0_p0_w1_phentry", "generic_exploit"): 3.0,
    ("fweb_s1_l0_p0_w1_phentry", "direct_exploit"): 3.0,
    ("fweb_s1_l0_p0_w1_phentry", "openstamanager_exploit"): 4.0,
    ("fweb_s2_l0_p0_w1_phentry", "craft_exploit"): 5.0,
    ("fweb_s2_l0_p0_w1_phentry", "web_fuzz"): 4.0,
    ("fweb_s2_l0_p0_w1_phentry", "generic_exploit"): 4.0,
    ("fweb_s2_l0_p0_w1_phentry", "direct_exploit"): 3.0,
    ("fweb_s2_l0_p0_w1_phentry", "openstamanager_exploit"): 4.0,
    ("fweb_s2_l0_p0_w1_phentry", "web_scan"): 4.0,
    ("fnone_s0_l0_p0_w0_phrecon", "recon"): 5.0,
    ("fnone_s0_l0_p0_w0_phrecon", "scan"): 4.0,
    ("fnone_s0_l0_p0_w0_phrecon", "stealth"): 2.0,
    ("fnone_s1_l0_p0_w0_phrecon", "recon"): 5.0,
    ("fnone_s1_l0_p0_w0_phrecon", "scan"): 4.0,
    ("fnone_s2_l0_p0_w1_phrecon", "recon"): 4.0,
    ("fnone_s2_l0_p0_w1_phrecon", "scan"): 4.0,
    ("fnone_s2_l0_p0_w1_phrecon", "web_fuzz"): 3.0,
    ("fnone_s2_l0_p0_w1_phrecon", "web_scan"): 3.0,
    ("fnone_s2_l0_p1_w1_phrecon", "recon"): 4.0,
    ("fnone_s2_l0_p1_w1_phrecon", "scan"): 4.0,
    ("fnone_s2_l0_p1_w1_phrecon", "web_fuzz"): 3.0,
    ("fnone_s2_l0_p1_w1_phrecon", "pjl_exploit"): 3.0,
    ("fnone_s2_l1_p0_w1_phrecon", "recon"): 4.0,
    ("fnone_s2_l1_p0_w1_phrecon", "scan"): 4.0,
    ("fnone_s2_l1_p0_w1_phrecon", "lpd_exploit"): 5.0,
    ("fnone_s2_l1_p0_w1_phrecon", "web_fuzz"): 2.0,
    ("fnone_s2_l1_p0_w1_phrecon", "exploit_chain"): 3.0,
    ("fnone_s3+_l1_p0_w1_phrecon", "recon"): 4.0,
    ("fnone_s3+_l1_p0_w1_phrecon", "scan"): 3.0,
    ("fnone_s3+_l1_p0_w1_phrecon", "lpd_exploit"): 5.0,
    ("fnone_s3+_l1_p0_w1_phrecon", "exploit_chain"): 4.0,
    ("fnone_s3+_l1_p0_w1_phrecon", "craft_exploit"): 3.0,
    ("fnone_s3+_l1_p0_w1_phrecon", "generic_exploit"): 2.0,
    ("fnone_s3+_l1_p0_w1_phrecon", "web_fuzz"): 2.0,
    ("fnone_s3+_l0_p0_w1_phrecon", "recon"): 5.0,
    ("fnone_s3+_l0_p0_w1_phrecon", "scan"): 4.0,
    ("fnone_s3+_l0_p0_w1_phrecon", "craft_exploit"): 4.0,
    ("fnone_s3+_l0_p0_w1_phrecon", "generic_exploit"): 3.0,
    ("fnone_s3+_l0_p0_w1_phrecon", "web_fuzz"): 3.0,
    ("fnone_s3+_l0_p0_w1_phrecon", "web_scan"): 3.0,
    ("fnone_s3+_l0_p0_w1_phrecon", "openstamanager_exploit"): 3.0,
    ("fnone_s3+_l0_p0_w1_phrecon", "direct_exploit"): 2.0,
    ("fnone_s3+_l0_p0_w1_phrecon", "llm_exploit"): 2.0,
    ("none_to_web", "craft_exploit"): 5.0,
    ("none_to_web", "lpd_exploit"): 5.0,
    ("none_to_web", "pjl_exploit"): 4.0,
    ("none_to_web", "web_fuzz"): 3.0,
    ("none_to_web", "generic_exploit"): 3.0,
    ("none_to_web", "exploit_chain"): 4.0,
    ("web_to_low_priv", "relay_chain"): 5.0,
    ("web_to_low_priv", "privesc"): 4.0,
    ("web_to_low_priv", "socket_scm"): 4.0,
    ("web_to_low_priv", "honeypot_analyzer"): 3.0,
    ("web_to_low_priv", "pjl_exploit"): 4.0,
    ("web_to_low_priv", "credential"): 3.0,
    ("web_to_low_priv", "persistence"): 2.0,
    ("low_priv_to_root", "privesc"): 5.0,
    ("low_priv_to_root", "relay_chain"): 5.0,
    ("low_priv_to_root", "socket_scm"): 4.0,
    ("low_priv_to_root", "credential"): 3.0,
    ("low_priv_to_root", "postex"): 2.0,
    ("low_priv_to_root", "exploit_chain"): 3.0,
    # Anonymous TTP seeds
    ("fnone_s2_l0_p0_w1_phrecon", "anonymous_ttp"): 4.0,
    ("fnone_s3+_l0_p0_w1_phrecon", "anonymous_ttp"): 4.0,
    ("fnone_s3+_l1_p0_w1_phrecon", "anonymous_ttp"): 3.0,
    ("fweb_s1_l0_p0_w1_phentry", "anonymous_ttp"): 5.0,
    ("fweb_s2_l0_p0_w1_phentry", "anonymous_ttp"): 5.0,
    ("fweb_s2_l1_p1_w1_phentry", "anonymous_ttp"): 4.0,
    ("fweb_s3+_l0_p0_w1_phentry", "anonymous_ttp"): 5.0,
    ("fweb_s3+_l1_p1_w1_phentry", "anonymous_ttp"): 4.0,
    ("flow_priv_s2_l1_p1_w1_phprivesc", "anonymous_ttp"): 3.0,
    ("flow_priv_s3+_l1_p1_w1_phprivesc", "anonymous_ttp"): 3.0,
    ("none_to_web", "anonymous_ttp"): 5.0,
    ("web_to_low_priv", "anonymous_ttp"): 3.0,
}

# Default phase priority ordering when Q-table has no data for a state
DEFAULT_PRIORITY = [
    "recon", "scan", "stealth", "web_scan", "web_fuzz",
    "anonymous_ttp",
    "lpd_exploit", "pjl_exploit", "relay_chain", "craft_exploit",
    "openstamanager_exploit", "nextjs_exploit",
    "exploit", "exploit_chain", "generic_exploit", "direct_exploit", "llm_exploit",
    "socket_scm", "honeypot_analyzer",
    "privesc", "credential", "postex", "persistence", "pivot", "lateral",
    "exfil", "flag_capture", "reporting", "phish", "multitarget",
    "reversing", "binary_analysis", "generate_report", "exploit_chaining",
]

FOOTHOLD_PRIORITY = {
    "none": [
        "recon", "scan", "stealth", "web_scan", "web_fuzz",
        "anonymous_ttp",
        "lpd_exploit", "pjl_exploit", "craft_exploit",
        "openstamanager_exploit", "nextjs_exploit",
        "exploit", "generic_exploit", "direct_exploit", "llm_exploit",
        "exploit_chain",
    ],
    "web": [
        "anonymous_ttp",
        "lpd_exploit", "pjl_exploit", "relay_chain",
        "craft_exploit", "generic_exploit", "exploit",
        "socket_scm", "honeypot_analyzer",
        "privesc", "credential", "postex", "persistence",
        "exploit_chain",
    ],
    "low_priv": [
        "relay_chain", "privesc", "pjl_exploit", "socket_scm", "honeypot_analyzer",
        "lpd_exploit", "credential", "postex", "persistence",
        "exploit_chain", "exploit",
    ],
    "high_priv": [
        "privesc", "credential", "exfil", "flag_capture",
        "persistence", "postex", "reporting", "pivot", "lateral",
    ],
    "root": [
        "flag_capture", "exfil", "reporting", "persistence",
        "postex", "pivot", "lateral", "credential",
    ],
}


def encode_state(foothold: str, services_count: int, has_lpd: bool,
                 has_pjl: bool, has_web: bool, phase_bucket: str) -> str:
    if services_count > 3:
        s_bucket = "3+"
    elif services_count == 0:
        s_bucket = "0"
    else:
        s_bucket = str(services_count)
    return (f"f{foothold}_s{s_bucket}_l{int(has_lpd)}_p{int(has_pjl)}"
            f"_w{int(has_web)}_ph{phase_bucket}")


def compute_reward(phase_success: bool, findings: list, phase_name: str,
                   latency: float, timeout_hit: bool = False,
                   breaker_tripped: bool = False) -> float:
    reward = 0.0

    if timeout_hit:
        reward += REWARD_COMPONENTS["phase_timeout"]
        return reward

    if breaker_tripped:
        reward += REWARD_COMPONENTS["circuit_breaker_tripped"]
        return reward

    if not phase_success:
        reward += REWARD_COMPONENTS["phase_failed"]
        return reward

    for f in findings:
        if f.type in ("user_flag", "root_flag", "flag"):
            reward += REWARD_COMPONENTS["flag_found"]
        if f.type == "credential":
            reward += REWARD_COMPONENTS["credential_obtained"]
        if f.type in ("shell", "user_shell", "root_shell",
                      "ssh_access", "ssh_session"):
            reward += REWARD_COMPONENTS["new_access_level"]
        if f.type in ("open_port", "service_discovery", "service_discovered"):
            reward += REWARD_COMPONENTS["service_discovered"]
        if f.type in ("privesc_success", "privesc_telnetd",
                      "pjl_path_traversal", "relay_service_hijack"):
            reward += REWARD_COMPONENTS["new_access_level"]

    latency_penalty = min(0.5, latency / 600.0 * 0.5)
    reward -= latency_penalty

    return reward


class StrategyLearner:
    """
    Q-learning strategy selection engine for autonomous phase ordering.

    Usage:
        sl = StrategyLearner()
        state = sl.encode_state("none", 2, True, False, True, "recon")
        action = sl.select_action(state, available_phases)
        # ... execute phase ...
        reward = compute_reward(phase_result.success, phase_result.findings, ...)
        next_state = sl.encode_state(...)
        sl.update(state, action, reward, next_state)
        sl.save()
    """

    def __init__(self, alpha: float = ALPHA, gamma: float = GAMMA,
                 epsilon: float = EPSILON_INIT):
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = EPSILON_DECAY
        self.epsilon_min = EPSILON_MIN
        self.episode_count = 0
        self.total_reward = 0.0
        self.q_table: dict[str, dict[str, float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self._state_action_counts: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._last_state: Optional[str] = None
        self._last_action: Optional[str] = None
        self._engagement_start: float = 0.0
        self._step = 0
        self._seeded = False
        self.load()

    def seed_from_patterns(self):
        """Initialize Q-table with domain knowledge from existing phase modules."""
        if self._seeded:
            return
        count = 0
        for (state, action), q in INITIAL_Q.items():
            self.q_table[state][action] = q
            count += 1
        self._seeded = True
        logger.info(f"[StrategyLearner] Seeded Q-table with {count} entries from phase patterns")

    def get_state(self, foothold: str = "none", findings: Optional[list] = None,
                  phase_bucket: str = "recon") -> str:
        if findings is None:
            findings = []
        svc_count = len(set(
            f.service or str(f.port) for f in findings
            if f.service or f.port
        ))
        has_lpd = any(
            f.port == 1515 or (f.service and f.service.lower() == "lpd")
            for f in findings
        )
        has_pjl = any(
            f.port == 9100 or (f.service and "pjl" in f.service.lower()) or
            f.type == "service_discovery" and "9100" in f.evidence
            for f in findings
        )
        has_web = any(
            f.port in (80, 443, 8080, 8443) or
            (f.service and f.service.lower() in ("http", "https"))
            for f in findings
        )
        return encode_state(foothold, svc_count, has_lpd, has_pjl, has_web, phase_bucket)

    def get_available_actions(self, foothold: str, findings: Optional[list] = None) -> list[str]:
        from orchestrator.brain.phases import PHASE_EXECUTORS
        all_phases = list(PHASE_EXECUTORS.keys())
        excluded = set()

        if findings is None:
            findings = []

        has_web = any(f.port in (80, 443, 8080, 8443) for f in findings)
        has_lpd = any(f.port == 1515 for f in findings)
        has_pjl = any(f.port == 9100 for f in findings)
        has_flags = any(f.type in ("user_flag", "root_flag") for f in findings)

        if foothold == "root" and has_flags:
            excluded.update({"recon", "scan", "exploit", "pjl_exploit",
                             "lpd_exploit", "socket_scm", "relay_chain",
                             "craft_exploit", "honeypot_analyzer"})
        elif foothold in ("none",):
            excluded.update({"privesc", "exfil", "flag_capture", "postex",
                             "persistence", "reporting", "phish", "pivot",
                             "lateral", "exploit_chaining", "multitarget"})
        elif foothold in ("web", "low_priv"):
            excluded.update({"phish", "multitarget"})

        if not has_web:
            excluded.update({"craft_exploit", "openstamanager_exploit",
                             "nextjs_exploit", "web_fuzz", "web_scan"})
        if not has_lpd:
            excluded.update({"lpd_exploit", "relay_chain"})
        if not has_pjl:
            excluded.update({"pjl_exploit"})

        if foothold != "low_priv" and foothold != "root":
            excluded.discard("socket_scm")
            excluded.discard("honeypot_analyzer")

        available = [p for p in all_phases if p not in excluded]
        if not available:
            return ["recon"]
        return available

    def select_action(self, state: str, available_actions: list[str]) -> str:
        if not available_actions:
            return "recon"

        if random.random() < self.epsilon:
            action = random.choice(available_actions)
            logger.debug(f"[RL] EXPLORE: {action} (eps={self.epsilon:.3f})")
            return action

        q_values = {
            a: self.q_table[state].get(a, 0.0) for a in available_actions
        }
        max_q = max(q_values.values()) if q_values else 0.0
        best_actions = [a for a, q in q_values.items() if q == max_q]
        action = random.choice(best_actions) if best_actions else available_actions[0]
        logger.debug(f"[RL] EXPLOIT: {action} (Q={q_values[action]:.2f}, eps={self.epsilon:.3f})")
        return action

    def update(self, state: str, action: str, reward: float, next_state: str):
        self._state_action_counts[state][action] += 1

        current_q = self.q_table[state].get(action, 0.0)
        next_max = max(self.q_table[next_state].values()) if self.q_table[next_state] else 0.0

        new_q = current_q + self.alpha * (reward + self.gamma * next_max - current_q)
        self.q_table[state][action] = new_q

        self.total_reward += reward
        self._step += 1

        if self._step % 5 == 0:
            self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

        logger.debug(f"[RL] Update: ({state}, {action}) Q={current_q:.2f}→{new_q:.2f} "
                     f"R={reward:.1f} next={next_state[:20]}")

    def select_and_execute(self, context: dict) -> str:
        state = self.get_state(
            context.get("foothold", "none"),
            context.get("findings"),
            context.get("phase_bucket", "recon"),
        )
        available = self.get_available_actions(
            context.get("foothold", "none"),
            context.get("findings"),
        )
        action = self.select_action(state, available)
        self._last_state = state
        self._last_action = action
        return action

    def record_outcome(self, success: bool, findings: list, phase_name: str,
                       latency: float, timeout: bool = False,
                       breaker: bool = False):
        if self._last_state is None or self._last_action is None:
            return

        reward = compute_reward(success, findings, phase_name, latency, timeout, breaker)
        next_state = self.get_state(
            self._infer_foothold(findings),
            findings,
            PHASE_BUCKET_MAP.get(phase_name, "postex"),
        )
        self.update(self._last_state, self._last_action, reward, next_state)
        self._last_state = None
        self._last_action = None

    def _infer_foothold(self, findings: list) -> str:
        for f in findings:
            if f.type == "root_flag":
                return "root"
            if f.type in ("root_shell", "system_shell"):
                return "root"
            if f.type == "user_flag":
                return "low_priv"
            if f.type in ("user_shell", "ssh_session", "shell"):
                return "low_priv"
            if f.type in ("credential", "ssh_key", "password"):
                return "web"
            if f.type in ("pjl_path_traversal", "exploit_success",
                          "service_hijack"):
                return "low_priv"
        return "none"

    def get_best_strategy(self, foothold: str = "none",
                          findings: Optional[list] = None) -> list[str]:
        """Generate ordered list of phases to run, based on learned Q-values.

        Uses RL Q-table when data exists; falls back to FOOTHOLD_PRIORITY
        for unseen states. Transitions simulate foothold progression.
        """
        strategy = []
        simulated_findings = list(findings or [])
        simulated_foothold = foothold
        current_bucket = "recon" if foothold in ("none",) else "entry"
        fallback_priority = FOOTHOLD_PRIORITY.get(foothold, DEFAULT_PRIORITY)

        for step in range(15):
            state = self.get_state(simulated_foothold, simulated_findings, current_bucket)
            available = self.get_available_actions(simulated_foothold, simulated_findings)
            done = {s for s in strategy}

            # Score available actions: Q-value when available, else priority index
            scored = []
            all_zero = True
            for a in available:
                if a in done:
                    continue
                q = self.q_table[state].get(a, 0.0)
                if q != 0.0:
                    all_zero = False
                scored.append((q, a))

            if not scored:
                break

            scored.sort(key=lambda x: (-x[0], x[1]))

            if all_zero:
                prior = [p for p in fallback_priority if p in available and p not in done]
                if prior:
                    best = prior[0]
                else:
                    best = scored[0][1] if scored else available[0]
            else:
                best = scored[0][1]

            if best in done:
                for q, alt in scored[:5]:
                    if alt not in done:
                        best = alt
                        break
                else:
                    break

            strategy.append(best)
            current_bucket = PHASE_BUCKET_MAP.get(best, current_bucket)

            if best in ("lpd_exploit", "pjl_exploit", "relay_chain",
                        "craft_exploit", "generic_exploit", "exploit_chain",
                        "anonymous_ttp"):
                if simulated_foothold in ("none", "web"):
                    simulated_foothold = "low_priv"
                    simulated_findings.append(
                        Finding("strategy", "access_gained", "sim",
                                severity=Severity.INFO,
                                description="Simulated access from strategy planner")
                    )
                    fallback_priority = FOOTHOLD_PRIORITY.get("low_priv", DEFAULT_PRIORITY)
            elif best in ("privesc", "socket_scm", "honeypot_analyzer"):
                if simulated_foothold in ("low_priv", "web"):
                    simulated_foothold = "high_priv"
                    fallback_priority = FOOTHOLD_PRIORITY.get("high_priv", DEFAULT_PRIORITY)
            elif best == "flag_capture":
                simulated_foothold = "root"
                fallback_priority = FOOTHOLD_PRIORITY.get("root", DEFAULT_PRIORITY)

        return strategy[:12]

    def save(self):
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        data = {
            "q_table": {k: dict(v) for k, v in self.q_table.items()},
            "alpha": self.alpha,
            "gamma": self.gamma,
            "epsilon": self.epsilon,
            "episode_count": self.episode_count,
            "total_reward": self.total_reward,
            "step": self._step,
        }
        with open(MODEL_PATH, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"[StrategyLearner] Model saved ({len(self.q_table)} states, "
                    f"{self.episode_count} episodes, total_reward={self.total_reward:.1f})")

    def load(self):
        try:
            with open(MODEL_PATH) as f:
                data = json.load(f)
            self.q_table.clear()
            for state, actions in data.get("q_table", {}).items():
                for action, q in actions.items():
                    self.q_table[state][action] = q
            self.alpha = data.get("alpha", ALPHA)
            self.gamma = data.get("gamma", GAMMA)
            self.epsilon = data.get("epsilon", EPSILON_INIT)
            self.episode_count = data.get("episode_count", 0)
            self.total_reward = data.get("total_reward", 0.0)
            self._step = data.get("step", 0)
            logger.info(f"[StrategyLearner] Model loaded ({len(self.q_table)} states, "
                        f"{self.episode_count} episodes)")
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            logger.info("[StrategyLearner] No saved model — seeding from phase patterns")
            self.seed_from_patterns()

    def get_stats(self) -> dict:
        return {
            "q_table_size": len(self.q_table),
            "episode_count": self.episode_count,
            "total_reward": round(self.total_reward, 1),
            "epsilon": round(self.epsilon, 3),
            "step": self._step,
            "seeded": self._seeded,
            "model_path": MODEL_PATH,
        }

    def reset(self, reseed: bool = True):
        self.q_table.clear()
        self._state_action_counts.clear()
        self._seeded = False
        self.episode_count = 0
        self.total_reward = 0.0
        self._step = 0
        self.epsilon = EPSILON_INIT
        if reseed:
            self.seed_from_patterns()
        logger.info("[StrategyLearner] Reset complete")


_strategy_learner: StrategyLearner = None


def get_strategy_learner() -> StrategyLearner:
    global _strategy_learner
    if _strategy_learner is None:
        _strategy_learner = StrategyLearner()
    return _strategy_learner


# ═══════════════════════════════════════════════════════════════════════════════
# EXPLOIT REGISTRY — Maps target profiles to exploit modules
# ═══════════════════════════════════════════════════════════════════════════════

EXPLOIT_REGISTRY = {
    # ── Active Directory Domain Controller ───────────────────────────────────
    "windows_dc": {
        "cve_2021_42278_nopac_shadow": {
            "versions": ["10.0.17763", "10.0.19041", "10.0.19042", "10.0.19043", "10.0.19044", "10.0.19045", "10.0.20348"],
            "patches": {"not": ["KB5004230", "KB5008602"]},
            "module": "exploits.ad.nopac_shadow_creds",
            "class": "NTPACExploit",
            "severity": "critical",
            "reliability": 0.85,
            "platform": "windows",
            "arch": "any",
            "requires": ["impacket", "ldap3"],
            "description": "NoPAC (CVE-2021-42278) + Shadow Credentials → DCSync",
        },
    },

    # ── Linux Kernel (5.11–6.5) ──────────────────────────────────────────────
    "linux_kernel": {
        "cve_2023_0386_overlayfs_io_uring": {
            "versions": ["5.11", "5.12", "5.13", "5.14", "5.15", "6.0", "6.1", "6.2", "6.3", "6.4", "6.5"],
            "mitigations": {"not": ["kaslr_disabled"]},
            "module": "exploits.linux.cve_2023_0386_overlayfs_io_uring",
            "class": "binary",
            "severity": "high",
            "reliability": 0.75,
            "platform": "linux",
            "arch": "x64",
            "compile": "gcc",
            "description": "OverlayFS io_uring UAF → modprobe_path overwrite → root",
        },
    },

    # ── Chrome/Chromium Renderer ─────────────────────────────────────────────
    "chrome_renderer": {
        "cve_2024_2887_v8_webgpu": {
            "versions": ["120", "121", "122", "123", "124", "125", "126"],
            "patches": {"not": ["127.0.6533.88"]},
            "mitigations": {"not": ["no_webgpu"]},
            "module": "exploits.browser.chrome_v8_webgpu_escape",
            "class": "ChromeExploitBuilder",
            "severity": "critical",
            "reliability": 0.55,
            "platform": "any",
            "arch": "any",
            "description": "V8 Turbofan type confusion + WebGPU sandbox escape",
        },
    },

    # ── Kubernetes Cluster ───────────────────────────────────────────────────
    "kubernetes": {
        "metadata_service": {
            "conditions": {"cloud": ["aws", "gcp", "azure"]},
            "module": "exploits.cloud.k8s_cluster_escalation",
            "class": "K8sClusterExploit",
            "severity": "critical",
            "reliability": 0.90,
            "platform": "linux",
            "description": "Instance metadata service + SA token → node escape → cluster-admin",
        },
        "privileged_pod": {
            "conditions": {"can_create_pods": True},
            "module": "exploits.cloud.k8s_cluster_escalation",
            "class": "K8sPrivilegedPodExploit",
            "severity": "high",
            "reliability": 0.80,
            "platform": "linux",
            "description": "SA token → privileged pod → node escape → etcd access",
        },
    },

    # ── Windows Kernel (10/11 22H2/23H2) ─────────────────────────────────────
    "windows": {
        "cve_2024_26234_dxgkrnl_acg": {
            "versions": ["10.0.19041", "10.0.19042", "10.0.19043", "10.0.19044", "10.0.19045", "10.0.22621", "10.0.22631"],
            "patches": {"not": ["KB5036892"]},
            "mitigations": {"not": ["no_gpu"]},
            "module": "exploits.windows.cve_2024_26234_dxgkrnl_acg_bypass",
            "class": "binary",
            "severity": "critical",
            "reliability": 0.70,
            "platform": "windows",
            "arch": "x64",
            "compile": "msvc",
            "description": "dxgkrnl.sys UAF → IoMmu page table corruption → ACG/CIG bypass → SYSTEM",
        },
    },

    # ── VMware ESXi Hypervisor ───────────────────────────────────────────────
    "vmware": {
        "cve_2025_22224_vmci": {
            "versions": ["8.0", "8.0.1", "8.0.2"],
            "patches": {"not": ["ESXi80U2b-23305545"]},
            "mitigations": {"not": ["no_vmci"]},
            "module": "exploits.vmware.esxi_vmci_escape",
            "class": "binary",
            "severity": "critical",
            "reliability": 0.60,
            "platform": "linux",
            "arch": "x64",
            "compile": "gcc",
            "description": "VMCI heap overflow → hypervisor RCE → VM escape",
        },
    },

    # ── MSSQL Server (2016–2022) ─────────────────────────────────────────────
    "mssql": {
        "xp_cmdshell_clr_chain": {
            "versions": ["2016", "2017", "2019", "2022"],
            "patches": {},
            "mitigations": {"not": ["no_sql_port"]},
            "module": "exploits.mssql.mssql_rce_xp_cmdshell_clr",
            "class": "MssqlExploit",
            "severity": "critical",
            "reliability": 0.85,
            "platform": "windows",
            "arch": "any",
            "description": "xp_cmdshell enable → CLR assembly → persistent OS shell",
        },
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER: Exploit Selector
# ═══════════════════════════════════════════════════════════════════════════════

def select_exploit(target_profile: dict) -> Optional[dict]:
    """
    Given a target profile from the profiler, select the best exploit.

    Args:
        target_profile: Dict with keys:
            - os_type: "windows", "linux", "chrome", "kubernetes", "vmware", "mssql"
            - os_version: "10.0.19041", "5.15.0", "120", "8.0", "2019"
            - patches: list of installed KB/article IDs
            - mitigations: list of active mitigations
            - services: list of discovered services
            - cloud: "aws" | "gcp" | "azure" | ""
            - mitigations: list of active mitigations (kaslr, smep, smap, cfg, acg, cig, etc.)

    Returns:
        Dict with exploit config or None if no suitable exploit
    """
    os_type = target_profile.get("os_type", "").lower()
    os_version = target_profile.get("os_version", "")
    patches = set(target_profile.get("patches", []))
    mitigations = set(target_profile.get("mitigations", []))
    services = set(target_profile.get("services", []))
    cloud = target_profile.get("cloud", "").lower()

    registry = EXPLOIT_REGISTRY.get(os_type, {})
    if not registry:
        return None

    best_match = None
    best_score = 0.0

    for exploit_id, config in registry.items():
        score = 0.0

        # Version match
        for ver_range in config.get("versions", []):
            if os_version.startswith(ver_range) or ver_range in os_version:
                score += 0.4
                break

        # Patch requirements
        required_absent = config.get("patches", {}).get("not", [])
        missing = [p for p in required_absent if p in patches]
        if missing:
            score -= 0.5

        # Mitigation bypass requirements
        required_mitigations = config.get("mitigations", {}).get("not", [])
        active = [m for m in required_mitigations if m in mitigations]
        if not active:
            score += 0.3

        # Cloud provider match
        if "conditions" in config:
            cond = config["conditions"]
            if "cloud" in cond:
                required_cloud = cond["cloud"]
                if isinstance(required_cloud, list):
                    if cloud in required_cloud:
                        score += 0.2
                elif isinstance(required_cloud, str) and cloud == required_cloud:
                    score += 0.2

            if "can_create_pods" in cond and cond["can_create_pods"]:
                if "create" in services or "pods" in services:
                    score += 0.2
            if "requires_service" in cond:
                required_svc = cond["requires_service"]
                if isinstance(required_svc, list):
                    if any(svc in services for svc in required_svc):
                        score += 0.2
                elif isinstance(required_svc, str) and required_svc in services:
                    score += 0.2

        # Service match (legacy "services" key)
        if "services" in config:
            required_svc = config["services"]
            if isinstance(required_svc, list):
                if any(svc in services for svc in required_svc):
                    score += 0.2
            elif isinstance(required_svc, str) and required_svc in services:
                score += 0.2

        # Reliability factor
        score *= config.get("reliability", 0.5)

        if score > best_score:
            best_score = score
            best_match = {exploit_id: config}

    if best_match and best_score > 0.3:
        return best_match

    return None
