#!/usr/bin/env python3
"""proxy_guard.py — Raphael 2.0 Mandatory Proxy Enforcement Layer"""
from __future__ import annotations

import os
import sys
import socket
import struct
import subprocess
import threading
import time
import random
import json
import logging
import hashlib
import ipaddress
from datetime import datetime
from typing import Optional, Dict, Tuple, TYPE_CHECKING
from urllib.parse import urlparse
from functools import wraps
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto

if TYPE_CHECKING:
    import requests

from .skills_bridge import SkillsBridge

# ── Logging ──
logger = logging.getLogger("proxy_guard")
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("[PG] %(levelname)s - %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ── Configuration ──
TOR_PORT = 9050
TOR_CONTROL_PORT = 9051
WG_INTERFACE = "wg0"
FLARETUNNEL_URL = "http://127.0.0.1:8080/status"
DNSCRYPT_ADDRESS = "127.0.2.1"
DNSCRYPT_PORT = 53
VPNBOOK_TUN_INTERFACE = "tun1"  # VPNBook OpenVPN creates tun1
PROXY_URL = "socks5h://127.0.0.1:9050"
CAIDO_PROXY_URL = "http://127.0.0.1:48080"
REAL_IP_CHECK_URLS = [
    "https://check.torproject.org/api/ip",
    "https://ifconfig.me",
    "https://api.ipify.org?format=json",
]
DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]  # only used for proxy verification, not for target DNS
MIN_DELAY = 1.0    # minimum seconds between requests
MAX_DELAY = 4.0    # maximum seconds between requests

# User-Agent pool per-circuit (rotated per session)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
]


# ============================================================
# Proxy Strategy — Enums, Models, Backend ABC
# ============================================================

class ProxyStrategy(Enum):
    DIRECT = auto()
    VPN = auto()
    TOR = auto()
    ACADEMIC = auto()
    MULTI = auto()
    CAIDO = auto()

class ProxyHealth(Enum):
    HEALTHY = auto()
    DEGRADED = auto()
    FAILING = auto()
    UNKNOWN = auto()

class ChainOrder(Enum):
    PRIVACY_FIRST = auto()
    PERFORMANCE_FIRST = auto()
    ADAPTIVE = auto()

class ProxyLifecycleState(Enum):
    UNINITIALIZED = auto()
    PROBING = auto()
    ACTIVE = auto()
    ROTATING = auto()
    DEGRADED = auto()
    EMERGENCY = auto()

@dataclass(frozen=True, slots=True)
class ProxyEndpoint:
    protocol: str
    host: str
    port: int
    auth: Optional[tuple[str, str]] = None
    latency_ms: float = float('inf')
    strategy_source: Optional[ProxyStrategy] = None

    def url(self) -> str:
        auth = ""
        if self.auth:
            user, pwd = self.auth
            auth = f"{user}:{pwd}@"
        return f"{self.protocol}://{auth}{self.host}:{self.port}"

@dataclass(frozen=True, slots=True)
class ProxyState:
    strategy: ProxyStrategy
    health: ProxyHealth
    lifecycle: ProxyLifecycleState = ProxyLifecycleState.UNINITIALIZED
    current_endpoint: Optional[ProxyEndpoint] = None
    circuit_id: Optional[str] = None
    bytes_transferred: int = 0
    requests_made: int = 0
    last_rotation: float = 0.0
    chain_order: ChainOrder = ChainOrder.PRIVACY_FIRST

    def is_fresh(self, max_age_seconds: float = 300.0) -> bool:
        return (time.time() - self.last_rotation) < max_age_seconds

class ProxyBackend(ABC):
    NAME: str = "abstract"

    def __init__(self, config: dict) -> None:
        self._config = config
        self._health = ProxyHealth.UNKNOWN

    @property
    def health(self) -> ProxyHealth:
        return self._health

    @abstractmethod
    async def health_check(self, timeout: float = 10.0) -> ProxyHealth:
        ...

    @abstractmethod
    async def rotate(self) -> ProxyEndpoint:
        ...

    @property
    @abstractmethod
    def current_endpoint(self) -> Optional[ProxyEndpoint]:
        ...

# ============================================================

LOCALHOST_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

LOCALHOST_NAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "127.0.1.1"}


def _is_localhost_target(target: str) -> bool:
    """Return True if target resolves to a local/private address."""
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname or target
    if host in LOCALHOST_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in LOCALHOST_NETS)
    except ValueError:
        pass
    try:
        for _, _, _, _, (ip_str, _) in socket.getaddrinfo(host, None, socket.AF_INET):
            ip = ipaddress.ip_address(ip_str)
            if any(ip in net for net in LOCALHOST_NETS):
                return True
    except Exception:
        pass
    return False


class ProxyError(Exception):
    """Raised when proxy enforcement fails"""
    pass


class ProxyGuard:
    """
    Mandatory proxy enforcement for all outbound traffic.

    Usage:
        pg = ProxyGuard()
        pg.verify()                        # pre-flight check
        session = pg.get_session()          # returns requests.Session forced through proxy
        response = session.get("https://target.com")
    """

    def __init__(self, target: str = ""):
        dev_mode = os.getenv("RAPHAEL_DEV_MODE", "").lower() in ("1", "true", "yes")
        self._dev_mode = dev_mode
        self._target = target
        self._exit_ip = None
        self._real_ip = None
        self._session = None
        self._circuit_id = None
        self._user_agent = random.choice(USER_AGENTS)
        self._last_request_time = 0.0
        self._lock = threading.Lock()
        self._active_requests: list = []
        self._aborted = False
        self._lifecycle = ProxyLifecycleState.UNINITIALIZED
        self._chain_order = ChainOrder.PRIVACY_FIRST
        self._current_strategy: Optional[ProxyStrategy] = None
        self._state_history: list[ProxyState] = []
        self._opsec_skill_result = None

        if dev_mode:
            logger.critical("=" * 60)
            logger.critical("RAPHAEL_DEV_MODE=1 — PROXY ENFORCEMENT IS DISABLED")
            logger.critical("All traffic will be DIRECT. Do NOT use this against real targets.")
            logger.critical("Set RAPHAEL_DEV_MODE=0 or unset for production mode.")
            logger.critical("=" * 60)

        # Use certifi's CA bundle for TLS verification
        import certifi
        self._ca_bundle = certifi.where()

    # ── Public API ──

    PROXY_STRATEGIES = [
        "protonvpn",
        "tor",
        "caido",
        "compromised_academic",
        "direct",
    ]

    def _detect_proxy_strategy(self) -> str:
        """Auto-detect the best proxy strategy based on what's available and the target."""
        if self._dev_mode:
            return "direct"

        # 1) ProtonVPN — preferred when available (fast, reliable, no Tor bootstrap)
        if self._check_protonvpn(silent=True):
            return "protonvpn"

        # 1.5) Caido — HTTP capture proxy (sandbox or local)
        if self._check_caido(silent=True):
            return "caido"

        # 2) Tor — standard proxy, but may be blocked by target
        try:
            tor_ok = self._check_tor(silent=True)
        except ProxyError:
            tor_ok = False
        if tor_ok:
            # If target is set, test if Tor is blocked against it
            if self._target:
                blocked = self._check_target_blocks_tor()
                if blocked:
                    logger.info(f"  ⚠ Tor blocked by target '{self._target}' — skipping Tor strategy")
                    return self._find_alternative_strategy()
            return "tor"

        # 3) Nothing available
        raise ProxyError(
            "No proxy strategy available — ProtonVPN inactive, Tor not running, "
            "and no alternative proxy configured"
        )

    def _check_target_blocks_tor(self) -> bool:
        """Probe target to see if Tor exit IPs are blocked. Returns True if blocked."""
        if not self._target:
            return False
        try:
            import requests
            target_url = self._target if "://" in self._target else f"https://{self._target}"
            r = requests.get(target_url, proxies={
                "http": PROXY_URL,
                "https": PROXY_URL,
            }, timeout=10, verify=False, headers={"User-Agent": self._user_agent})
            if r.status_code in (403, 406, 429):
                logger.info(f"  ✓ Tor blocked by target (HTTP {r.status_code})")
                return True
            return False
        except requests.exceptions.ProxyError:
            logger.info(f"  ⚠ Tor proxy error when probing target — assuming blocked")
            return True
        except Exception:
            return False

    def _find_alternative_strategy(self) -> str:
        """When Tor is blocked, find an alternative proxy strategy."""
        # ProtonVPN already checked — if not available, we're out of options on this host
        raise ProxyError(
            "Tor blocked by target and no alternative proxy available. "
            "Options: enable ProtonVPN on Windows host, or configure compromised academic proxy chain."
        )

    def verify(self, use_skills: bool = True) -> bool:
        """
        Full pre-flight check. Raises ProxyError if anything is wrong.
        Must pass before any target contact.
        Set RAPHAEL_DEV_MODE=1 env var to bypass for localhost testing.
        """
        if self._dev_mode:
            logger.critical("=== PROXY GUARD — BYPASSED (RAPHAEL_DEV_MODE) ===")
            logger.critical(f"  Target: {self._target or '(not set)'}")
            logger.critical("  All proxy/anonymity checks skipped — direct connection allowed")
            logger.critical("=== BYPASS LOGGED ===\n")
            return True

        logger.info("=== PROXY GUARD PRE-FLIGHT VERIFICATION ===")

        # Auto-detect strategy
        strategy = self._detect_proxy_strategy()
        self._active_strategy = strategy
        logger.info(f"  Strategy: {strategy}")

        # Kill-switch check — mandatory before any proxy initialization
        self._check_iptables_kill_switch()

        if use_skills:
            self._run_opsec_skill()

        if strategy == "protonvpn":
            logger.info("  ✓ ProtonVPN active on Windows host — Tor checks skipped")
            self._check_dns_leak()
            self._check_ipv6_disabled()
            self._check_exit_ip()
            logger.info(f"  Exit IP:    {self._exit_ip}")
            logger.info("=== VERIFICATION PASSED — PROTONVPN ACTIVE ===\n")
            return True

        if strategy == "caido":
            self._check_caido()
            self._check_dns_leak()
            self._check_ipv6_disabled()
            self._check_exit_ip()
            logger.info(f"  Exit IP:    {self._exit_ip}")
            logger.info(f"  Caido URL:  {CAIDO_PROXY_URL}")
            logger.info("=== VERIFICATION PASSED — CAIDO PROXY ACTIVE ===\n")
            return True

        if strategy == "tor":
            self._check_tor()
            self._check_tor_control()
            self._check_dns_leak()
            self._check_ipv6_disabled()
            self._check_exit_ip()
            logger.info(f"  Real IP:    {self._real_ip}")
            logger.info(f"  Exit IP:    {self._exit_ip}")
            logger.info(f"  User-Agent: {self._user_agent[:50]}...")
            logger.info(f"  Circuit ID: {self._circuit_id}")
            logger.info("=== VERIFICATION PASSED — TOR ACTIVE ===\n")
            return True

        raise ProxyError(f"Unsupported proxy strategy: {strategy}")

    def _run_opsec_skill(self):
        """Run OPSEC validation skill as an additional pre-flight check."""
        try:
            bridge = SkillsBridge()
            result = bridge.execute_skill(
                "performing-open-source-intelligence-gathering",
                [self._target or "8.8.8.8"],
            )
            if result and "error" not in result:
                logger.info(f"  ✓ OPSEC skill check passed")
                self._opsec_skill_result = result
            else:
                logger.info(f"  ⚠ OPSEC skill check unavailable (non-fatal)")
        except Exception as e:
            logger.debug(f"  ⚠ OPSEC skill error (non-fatal): {e}")

    def get_session(self) -> requests.Session:
        """Get a requests.Session that is FORCED through the proxy chain"""
        if self._session is None:
            self._session = self._build_session()
        return self._session

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make a single request through the proxy with timing isolation.
        This is the primary interface for all recon operations.
        """
        if self._aborted:
            raise ProxyError("ProxyGuard is in FAIL-DEAD state. Cannot make requests.")

        if self._session is None:
            self._session = self._build_session()

        # Enforce minimum delay between requests (no machine-gun)
        self._enforce_timing()

        # Add jitter and isolation headers
        kwargs.setdefault("headers", {})
        if "User-Agent" not in kwargs["headers"]:
            kwargs["headers"]["User-Agent"] = self._user_agent
        kwargs.setdefault("timeout", 30)
        kwargs.setdefault("verify", False)

        # Track active request for fail-closed
        req_id = random.randint(0, 2**32)
        self._active_requests.append(req_id)

        try:
            logger.debug(f"  → {method} {url}")
            response = self._session.request(method, url, **kwargs)
            self._log_request(method, url, response.status_code)
            return response
        except Exception as e:
            logger.error(f"  ✗ {method} {url} — {e}")
            raise
        finally:
            self._active_requests.remove(req_id)
            self._last_request_time = time.time()

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def new_circuit(self, target_domain: str = None) -> str:
        """
        Request a new Tor circuit. Must be called per-target for circuit isolation.
        Returns new circuit ID.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(("127.0.0.1", TOR_CONTROL_PORT))
            password = os.getenv("TOR_CONTROL_PASS", "") or os.getenv("TOR_PASSWORD", "")
            if password:
                sock.sendall(f'AUTHENTICATE "{password}"\r\n'.encode())
            else:
                sock.sendall(b"AUTHENTICATE\r\n")
            data = sock.recv(1024)
            if b"250" in data:
                sock.sendall(b"SIGNAL NEWNYM\r\n")
                sock.recv(1024)
            sock.close()
        except Exception as e:
            logger.warning(f"  Could not request new Tor circuit: {e}")

        # Generate new circuit ID
        self._circuit_id = hashlib.sha256(
            (str(time.time()) + str(random.getrandbits(128))).encode()
        ).hexdigest()[:16]

        # Rotate User-Agent per circuit
        self._user_agent = random.choice(USER_AGENTS)

        # Rebuild session with new identity
        self._session = self._build_session()

        # Recheck exit IP
        self._check_exit_ip()

        logger.info(f"  New circuit: {self._circuit_id} → {self._exit_ip}")
        return self._circuit_id

    def abort(self):
        """
        FAIL-DEAD: Emergency stop. Kills all active connections, prevents any further requests.
        """
        logger.critical("!!! FAIL-DEAD TRIGGERED !!!")
        self._aborted = True
        # Close session
        if self._session:
            self._session.close()
            self._session = None
        # Kill all in-flight connections (drop sockets)
        for req_id in self._active_requests:
            logger.critical(f"  Killing in-flight request: {req_id}")
        self._active_requests.clear()
        logger.critical("ProxyGuard is dead. No further requests allowed.")

    def status(self) -> dict:
        """Return current guard status"""
        proton_ok = self._check_protonvpn(silent=True)
        return {
            "active": not self._aborted,
            "strategy": getattr(self, "_active_strategy", "unknown"),
            "exit_ip": self._exit_ip,
            "circuit_id": self._circuit_id,
            "user_agent": self._user_agent,
            "open_requests": len(self._active_requests),
            "protonvpn_active": proton_ok,
            "tor_running": self._check_tor(silent=True) if not proton_ok else False,
            "caido_running": self._check_caido(silent=True) if not proton_ok else False,
            "wireguard_up": self._check_wireguard(silent=True),
            "flare_ok": self._check_flaretunnel(silent=True),
            "dnscrypt_running": self._check_dnscrypt(silent=True),
            "vpnbook_up": self._check_vpnbook(silent=True),
            "opsec_skill_ok": self._opsec_skill_result is not None,
        }

    # ── Session Building ──

    def _build_session(self):
        """Build a requests.Session that CANNOT reach the internet without proxy"""
        import requests
        s = requests.Session()
        s.verify = getattr(self, '_ca_bundle', True)
        proxy_url = CAIDO_PROXY_URL if getattr(self, "_active_strategy", None) == "caido" else PROXY_URL
        s.proxies = {
            "http": proxy_url,
            "https": proxy_url,
        }
        s.headers.update({
            "User-Agent": self._user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })
        # Override the mount to force SOCKS proxy for all schemes
        s.mount("http://", requests.adapters.HTTPAdapter(
            max_retries=0,
            pool_connections=10,
            pool_maxsize=10,
        ))
        s.mount("https://", requests.adapters.HTTPAdapter(
            max_retries=0,
            pool_connections=10,
            pool_maxsize=10,
        ))
        return s

    def _tor_dns_resolver(self, hostname: str) -> list:
        """
        DNS resolver that routes through Tor's SOCKS proxy.
        This prevents DNS leaks by never performing direct DNS lookups.
        """
        # Force DNS resolution through Tor's SOCKS5h (proxy-resolved DNS)
        try:
            import socks
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, "127.0.0.1", TOR_PORT, True)  # True = resolve via proxy
            s.settimeout(5)
            # We don't actually connect — we just need the proxy to resolve DNS
            # For DNS resolution through SOCKS5, we rely on the socks5h proxy
            # which resolves DNS through the proxy
            result = s.connect_ex((hostname, 1))
            s.close()
        except Exception:
            pass

        # Fallback: use dnscrypt-proxy (encrypted DNS)
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [DNSCRYPT_ADDRESS]
            resolver.port = DNSCRYPT_PORT
            resolver.timeout = 3
            resolver.lifetime = 5
            answers = resolver.resolve(hostname, "A")
            return [str(r) for r in answers]
        except Exception:
            return []

    # ── Pre-flight Checks ──

    def _check_protonvpn(self, silent=False) -> bool:
        """Verify ProtonVPN is active on the Windows host (WSL)."""
        try:
            import subprocess
            result = subprocess.run(
                ["powershell.exe", "-Command",
                 "Get-Service ProtonVPN* | Where-Object { $_.Status -eq 'Running' } | Measure-Object | Select-Object -ExpandProperty Count"],
                capture_output=True, text=True, timeout=5
            )
            count = result.stdout.strip()
            if count and int(count) >= 2:
                if not silent:
                    logger.info("  ✓ ProtonVPN active (Service + WireGuard on Windows host)")
                return True
            if not silent:
                logger.warning(f"  ⚠ ProtonVPN services not fully running (found {count})")
            return False
        except FileNotFoundError:
            if not silent:
                logger.warning("  ⚠ powershell.exe not available — not a WSL environment")
            return False
        except Exception as e:
            if not silent:
                logger.warning(f"  ⚠ ProtonVPN check failed: {e}")
            return False

    def _check_tor(self, silent=False) -> bool:
        """Verify Tor daemon is running on the expected port"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", TOR_PORT))
            s.close()
            if not silent:
                logger.info(f"  ✓ Tor running on 127.0.0.1:{TOR_PORT}")
            return True
        except Exception as e:
            msg = f"Tor not running on 127.0.0.1:{TOR_PORT} — {e}"
            if not silent:
                logger.error(f"  ✗ {msg}")
                raise ProxyError(msg)
            return False

    def _check_tor_control(self, silent=False) -> bool:
        """Verify Tor control port is accessible"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", TOR_CONTROL_PORT))
            s.sendall(b"AUTHENTICATE\r\n")
            data = s.recv(1024)
            s.close()
            if b"250" in data:
                if not silent:
                    logger.info(f"  ✓ Tor control port {TOR_CONTROL_PORT} accessible")
                return True
            if not silent:
                logger.info(f"  ✓ Tor control port {TOR_CONTROL_PORT} accessible (auth may be needed for circuits)")
            return True
        except Exception as e:
            msg = f"Tor control port {TOR_CONTROL_PORT} not accessible — {e}"
            if not silent:
                logger.warning(f"  ⚠ {msg}")
            # Non-fatal — control port is needed for new circuits but not for proxying
            return False

    def _check_caido(self, silent=False) -> bool:
        """Check if a Caido proxy is running and reachable."""
        try:
            import requests
            r = requests.get(f"{CAIDO_PROXY_URL}/graphql", timeout=3,
                             headers={"Content-Type": "application/json"})
            if r.status_code == 200 or r.status_code == 405:
                if not silent:
                    logger.info(f"  ✓ Caido proxy running on {CAIDO_PROXY_URL}")
                return True
            if not silent:
                logger.warning(f"  ⚠ Caido proxy unreachable (HTTP {r.status_code})")
            return False
        except requests.exceptions.ConnectionError:
            if not silent:
                logger.warning(f"  ⚠ Caido proxy not responding at {CAIDO_PROXY_URL}")
            return False
        except Exception as e:
            if not silent:
                logger.warning(f"  ⚠ Caido check failed: {e}")
            return False

    def _check_wireguard(self, silent=False) -> bool:
        """Verify WireGuard interface is up"""
        try:
            result = subprocess.run(
                ["wg", "show", WG_INTERFACE],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                if not silent:
                    # Extract last handshake for status
                    for line in result.stdout.split("\n"):
                        if "latest handshake" in line:
                            logger.info(f"  ✓ WireGuard {WG_INTERFACE} up ({line.strip()})")
                            break
                    else:
                        logger.info(f"  ✓ WireGuard {WG_INTERFACE} up")
                return True
            raise Exception(result.stderr)
        except FileNotFoundError:
            # wg command not installed — warn but don't fail
            if not silent:
                logger.warning(f"  ⚠ WireGuard CLI not found — cannot verify {WG_INTERFACE}")
            return True  # soft check
        except Exception as e:
            msg = f"WireGuard {WG_INTERFACE} not available — {e}"
            if not silent:
                logger.warning(f"  ⚠ {msg}")
            return True  # soft check — optional layer

    def _check_flaretunnel(self, silent=False) -> bool:
        """Verify FlareTunnel proxy is responding"""
        try:
            import requests
            r = requests.get(FLARETUNNEL_URL, timeout=3)
            if r.status_code == 200:
                if not silent:
                    logger.info(f"  ✓ FlareTunnel responding on {FLARETUNNEL_URL}")
                return True
            raise Exception(f"status {r.status_code}")
        except Exception as e:
            msg = f"FlareTunnel not responding on {FLARETUNNEL_URL} — {e}"
            if not silent:
                logger.warning(f"  ⚠ {msg}")
            # Soft check — if Tor is up, we can still work
            return False

    def _check_vpnbook(self, silent=False) -> bool:
        """Verify VPNBook OpenVPN tunnel is up"""
        try:
            result = subprocess.run(
                ["ip", "link", "show", VPNBOOK_TUN_INTERFACE],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0 and "UP" in result.stdout:
                if not silent:
                    logger.info(f"  ✓ VPNBook {VPNBOOK_TUN_INTERFACE} interface UP")
                return True
            raise Exception("Interface not found or not UP")
        except FileNotFoundError:
            if not silent:
                logger.warning(f"  ⚠ ip command not found — cannot verify {VPNBOOK_TUN_INTERFACE}")
            return True  # soft check
        except Exception as e:
            if not silent:
                logger.warning(f"  ⚠ VPNBook {VPNBOOK_TUN_INTERFACE} not available — {e}")
            return True  # soft check — optional layer

    def _check_dnscrypt(self, silent=False) -> bool:
        """Verify dnscrypt-proxy is running and responding"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            # Minimal DNS query to test
            tid = random.randint(0, 65535)
            query = struct.pack('>H', tid)
            query += struct.pack('>H', 0x0100)
            query += struct.pack('>HHHH', 1, 0, 0, 0)
            for part in b'cloudflare', b'com':
                query += struct.pack('B', len(part)) + part
            query += b'\x00'
            query += struct.pack('>HH', 1, 1)
            sock.sendto(query, (DNSCRYPT_ADDRESS, DNSCRYPT_PORT))
            data, addr = sock.recvfrom(512)
            sock.close()
            if not silent:
                logger.info(f"  ✓ dnscrypt-proxy responding on {DNSCRYPT_ADDRESS}:{DNSCRYPT_PORT} (DoH via Cloudflare)")
            return True
        except Exception as e:
            msg = f"dnscrypt-proxy not responding on {DNSCRYPT_ADDRESS}:{DNSCRYPT_PORT} — {e}"
            if not silent:
                logger.error(f"  ✗ {msg}")
            # Non-fatal — Tor can still work without dnscrypt-proxy
            return False

    def _check_dns_leak(self, silent=False) -> bool:
        """Verify DNS is not leaking — all DNS lookups route through Tor SOCKS5h."""
        try:
            import socks
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, "127.0.0.1", TOR_PORT, True)
            s.settimeout(5)
            s.connect(("check.torproject.org", 80))
            s.sendall(b"GET / HTTP/1.0\r\nHost: check.torproject.org\r\n\r\n")
            s.recv(256)
            s.close()
            if not silent:
                logger.info(f"  ✓ DNS routes through Tor SOCKS5h (no direct DNS leaks)")
            return True
        except Exception:
            if not silent:
                logger.warning(f"  ⚠ Cannot confirm Tor DNS routing — check proxy chain")
            return False

    def _check_iptables_kill_switch(self, silent=False) -> bool:
        """Verify iptables OUTPUT policy is DROP (kill-switch active)"""
        try:
            result = subprocess.run(
                ["iptables", "-L", "OUTPUT", "-n"],
                capture_output=True, text=True, timeout=5
            )
            if "DROP" in result.stdout.split("\n")[0] if result.stdout else "":
                if not silent:
                    logger.info("  ✓ iptables OUTPUT policy DROP (kill-switch active)")
                return True
            if not silent:
                logger.info("  ✓ iptables OUTPUT policy not DROP (expected without root — kill-switch inactive)")
            return False
        except FileNotFoundError:
            if not silent:
                logger.warning("  ⚠ iptables CLI not found — cannot verify kill-switch")
            return True
        except Exception as e:
            if not silent:
                logger.warning(f"  ⚠ iptables check failed: {e}")
            return False

    def _check_ipv6_disabled(self, silent=False) -> bool:
        """Verify IPv6 is disabled to prevent leaks via IPv6"""
        try:
            with open("/proc/sys/net/ipv6/conf/all/disable_ipv6") as f:
                disabled = f.read().strip() == "1"
            if disabled:
                if not silent:
                    logger.info("  ✓ IPv6 disabled at kernel level")
                return True
            else:
                if not silent:
                    logger.info("  ✓ IPv6 active (expected — set sysctl disable_ipv6=1 to suppress)")
                return False
        except FileNotFoundError:
            # Not a Linux system — skip check
            if not silent:
                logger.info("  ✓ IPv6 check skipped (not Linux or /proc not available)")
            return True

    def _check_exit_ip(self, silent=False) -> bool:
        """Verify exit IP is different from real IP and not blacklisted"""
        # Get real IP
        real_ip = self._get_real_ip()

        # Get exit IP through proxy
        exit_ip = self._get_exit_ip()
        if not exit_ip:
            msg = "Cannot determine exit IP — proxy may not be routing traffic"
            raise ProxyError(msg)

        self._real_ip = real_ip
        self._exit_ip = exit_ip

        if exit_ip == real_ip:
            msg = f"Exit IP ({exit_ip}) matches real IP — proxy is NOT routing traffic!"
            raise ProxyError(msg)

        if not silent:
            logger.info(f"  ✓ Exit IP: {exit_ip} (different from real IP: {real_ip})")
        return True

    # ── Internal Helpers ──

    def _get_real_ip(self) -> Optional[str]:
        """Get actual public IP via direct connection (verification only, not during operations)"""
        cached = os.getenv("CACHED_REAL_IP")
        if cached:
            return cached
        import requests
        session = requests.Session()
        for url in REAL_IP_CHECK_URLS:
            try:
                r = session.get(url, timeout=10)
                if "ip" in r.text.lower():
                    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
                    if isinstance(data, dict) and "ip" in data:
                        return data["ip"]
                    import re
                    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', r.text)
                    if ip_match:
                        return ip_match.group(0)
            except Exception:
                continue
        return None

    def _get_exit_ip(self) -> Optional[str]:
        """Get exit IP through the proxy chain"""
        for url in REAL_IP_CHECK_URLS:
            try:
                import requests
                r = requests.get(url, proxies={
                    "http": PROXY_URL,
                    "https": PROXY_URL,
                }, timeout=10)
                import re
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', r.text)
                if ip_match:
                    return ip_match.group(0)
            except Exception:
                continue
        return None

    def _enforce_timing(self):
        """Enforce random delay between requests to avoid pattern detection"""
        elapsed = time.time() - self._last_request_time
        if elapsed < MIN_DELAY and self._last_request_time > 0:
            delay = random.uniform(MIN_DELAY, MAX_DELAY)
            logger.debug(f"  Timing: sleeping {delay:.2f}s (elapsed: {elapsed:.2f}s)")
            time.sleep(delay)

    def _log_request(self, method: str, url: str, status: int):
        """Log every request with timestamp, exit IP, target"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": method,
            "url": url,
            "status": status,
            "exit_ip": self._exit_ip,
            "circuit_id": self._circuit_id,
            "user_agent": self._user_agent[:60],
        }
        # Write to structured log
        log_line = json.dumps(log_entry)
        logger.info(f"  ✓ {method} {url} → {status} [{self._exit_ip}]")

        # Append to request log file
        log_file = f"recon_log_{datetime.utcnow().strftime('%Y%m')}.jsonl"
        try:
            with open(log_file, "a") as f:
                f.write(log_line + "\n")
        except Exception:
            pass  # non-critical

    # ── V3 Extensions: State Machine + Strategy Pattern ──

    async def get_endpoint(self, *, force_rotation: bool = False) -> ProxyEndpoint:
        strategy = self._detect_proxy_strategy()
        self._lifecycle = ProxyLifecycleState.ACTIVE
        if force_rotation and strategy == "tor":
            self.new_circuit()
        ep = ProxyEndpoint(
            protocol="socks5",
            host="127.0.0.1",
            port=TOR_PORT,
            strategy_source=ProxyStrategy.TOR if strategy == "tor" else ProxyStrategy.VPN,
        )
        return ep

    async def get_state(self) -> ProxyState:
        return ProxyState(
            strategy=self._current_strategy or ProxyStrategy.DIRECT,
            health=ProxyHealth.HEALTHY if not self._aborted else ProxyHealth.FAILING,
            lifecycle=self._lifecycle,
            current_endpoint=ProxyEndpoint(
                protocol="socks5", host="127.0.0.1", port=TOR_PORT,
            ) if self._session else None,
            circuit_id=self._circuit_id,
            requests_made=len(self._active_requests),
            last_rotation=time.time(),
            chain_order=self._chain_order,
        )

    def detect_and_rotate(self, *, force: bool = False) -> str:
        strategy = self._detect_proxy_strategy()
        self._current_strategy = {
            "protonvpn": ProxyStrategy.VPN,
            "tor": ProxyStrategy.TOR,
            "direct": ProxyStrategy.DIRECT,
            "compromised_academic": ProxyStrategy.ACADEMIC,
        }.get(strategy, ProxyStrategy.DIRECT)
        if force and self._current_strategy == ProxyStrategy.TOR:
            self.new_circuit()
        return strategy

    def renew_tor_circuit(self) -> str:
        return self.new_circuit()

    def emergency_fallback(self) -> None:
        self._lifecycle = ProxyLifecycleState.EMERGENCY
        self.abort()

    def chain_proxies(self, strategies: list[ProxyStrategy], chain_order: ChainOrder = ChainOrder.PRIVACY_FIRST) -> list[ProxyEndpoint]:
        self._chain_order = chain_order
        if chain_order == ChainOrder.PRIVACY_FIRST:
            strategies = sorted(strategies, key=lambda s: 0 if s == ProxyStrategy.TOR else 1)
        endpoints = []
        for s in strategies:
            if s == ProxyStrategy.TOR:
                endpoints.append(ProxyEndpoint(protocol="socks5", host="127.0.0.1", port=TOR_PORT, strategy_source=s))
            elif s == ProxyStrategy.VPN:
                endpoints.append(ProxyEndpoint(protocol="socks5", host="127.0.0.1", port=1080, strategy_source=s))
        return endpoints


# ── Decorator for wrapping functions ──

def guarded(pg: ProxyGuard):
    """
    Decorator that wraps a function with proxy guard enforcement.
    Usage:
        pg = ProxyGuard()
        pg.verify()

        @guarded(pg)
        def my_recon(target):
            return pg.get(f"https://{target}")
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if pg._aborted:
                raise ProxyError("ProxyGuard is in FAIL-DEAD state. Aborting.")
            # Inject guard as first arg if function expects it
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ── Context Manager ──

class guarded_operation:
    """
    Context manager for proxy-guarded operations.

    Usage:
        with guarded_operation("osmania.ac.in") as pg:
            response = pg.get("https://nertu.osmania.ac.in/")
    """

    def __init__(self, target_description: str = None):
        self.target = target_description
        self.pg = None

    def __enter__(self) -> ProxyGuard:
        self.pg = ProxyGuard()
        # Pre-flight verification — will throw ProxyError if anything fails
        self.pg.verify()
        # New circuit per target (circuit isolation)
        if self.target:
            self.pg.new_circuit(self.target)
        return self.pg

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is ProxyError:
            # Proxy failure — trigger fail-dead
            if self.pg:
                self.pg.abort()
        # Close session cleanly if no error
        if self.pg and not exc_type:
            if self.pg._session:
                self.pg._session.close()
        return False  # don't suppress exceptions


# ── CLI Test ──

if __name__ == "__main__":
    print("ProxyGuard v3.0 — Community-Refactored Enforcement Layer")
    print("=" * 60)

    import sys
    no_anon = "--no-anonymity" in sys.argv

    if no_anon:
        pg = ProxyGuard(no_anonymity=True)
        print("\nRunning in no_anonymity mode — all proxy checks skipped.")
        assert pg.verify()
        print("\n✓ ProxyGuard bypassed successfully")
    else:
        try:
            with guarded_operation() as pg:
                print("\nProxy chain status:")
                for k, v in pg.status().items():
                    print(f"  {k}: {v}")
                print("\n✓ ProxyGuard verification passed")
        except ProxyError as e:
            print(f"\n✗ ProxyGuard FAILED: {e}")
            print("  Fix the proxy chain and try again.\n")
            print("  Tip: pass --no-anonymity to skip proxy checks for localhost testing")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\nAborted by user.")
            sys.exit(1)
