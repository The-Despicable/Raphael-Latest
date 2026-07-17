#!/usr/bin/env python3
"""proxy_guard.py — Raphael 2.0 Mandatory Proxy Enforcement Layer"""
from __future__ import annotations

import os, sys, socket, subprocess, threading, time, random, json, logging, hashlib, ipaddress
from urllib.parse import urlparse
from datetime import datetime
from typing import Optional
from functools import wraps

logger = logging.getLogger("proxy_guard")
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("[PG] %(levelname)s - %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

TOR_PORT = 9050
TOR_CONTROL_PORT = 9051
PROXY_URL = "socks5://127.0.0.1:9050"
REAL_IP_CHECK_URLS = [
    "https://check.torproject.org/api/ip",
    "https://ifconfig.me",
    "https://api.ipify.org?format=json",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
]
MIN_DELAY = 1.0
MAX_DELAY = 4.0

LOCALHOST_NETS = [
    ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
LOCALHOST_NAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "127.0.1.1"}

try:
    from orchestrator.egress.router import EgressRouter
    _egress_router = EgressRouter(strategy=os.getenv("EGRESS_STRATEGY", "auto"))
except ImportError:
    _egress_router = None

LOCALHOST_NETS = [
    ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
LOCALHOST_NAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "127.0.1.1"}

def _is_localhost_target(target: str) -> bool:
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
            if any(ipaddress.ip_address(ip_str) in net for net in LOCALHOST_NETS):
                return True
    except Exception:
        logger.debug("Non-critical error", exc_info=True)
    return False

class ProxyError(Exception):
    pass

class ProxyGuard:
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
        self._aborted = False

        if dev_mode:
            logger.critical("=" * 60)
            logger.critical("RAPHAEL_DEV_MODE=1 — PROXY ENFORCEMENT IS DISABLED")
            logger.critical("All traffic will be DIRECT. Do NOT use this against real targets.")
            logger.critical("=" * 60)

        import certifi
        self._ca_bundle = certifi.where()

    def _detect_proxy_strategy(self) -> str:
        if self._dev_mode:
            return "direct"
        if self._check_tor(silent=True):
            return "tor"
        if self._check_wireguard(silent=True):
            return "wireguard"
        if self._check_protonvpn(silent=True):
            return "protonvpn"
        if self._check_openvpn(silent=True):
            return "openvpn"
        if self._check_vpn_passive(silent=True):
            return "vpn"
        raise ProxyError("No proxy found (checked: Tor:9050, WireGuard, ProtonVPN, OpenVPN, system VPN)")

    def verify(self) -> bool:
        if self._dev_mode:
            logger.critical("=== PROXY GUARD — BYPASSED (RAPHAEL_DEV_MODE) ===")
            return True

        logger.info("=== PROXY GUARD PRE-FLIGHT VERIFICATION ===")
        strategy = self._detect_proxy_strategy()
        logger.info(f"  Strategy: {strategy}")

        if strategy == "tor":
            self._check_tor()
            self._check_tor_control()
            self._check_dns_leak()
            self._check_ipv6_disabled()
            self._check_exit_ip()
            logger.info(f"  Exit IP:    {self._exit_ip}")
            logger.info(f"  User-Agent: {self._user_agent[:50]}...")
            logger.info("=== VERIFICATION PASSED — TOR ACTIVE ===\n")
            return True

        if strategy in ("wireguard", "protonvpn", "openvpn", "vpn"):
            ext_ip = self._get_exit_ip()
            self._exit_ip = ext_ip
            logger.info(f"  ✓ External IP: {ext_ip or 'unknown'}")
            logger.info(f"  ✓ Strategy: {strategy}")
            logger.info(f"=== VERIFICATION PASSED — {strategy.upper()} ACTIVE ===\n")
            return True

        raise ProxyError(f"Unsupported proxy strategy: {strategy}")

    def get_session(self) -> "requests.Session":
        if self._session is None:
            self._session = self._build_session()
        return self._session

    def _delegate_to_router(self, method, url, **kwargs):
        if not _egress_router:
            return None
        target = urlparse(url).hostname
        kw = _egress_router.build_requests_kwargs(target)
        kw.update(kwargs)
        kw.setdefault("timeout", 30)
        import requests
        logger.debug(f"  → [{_egress_router.status()['strategy']}] {method} {url}")
        return requests.request(method, url, **kw)

    def set_egress_strategy(self, strategy_name: str):
        global _egress_router
        if _egress_router:
            _egress_router = EgressRouter(strategy=strategy_name)
            logger.info(f"  Egress strategy set to: {strategy_name}")

    def rotate_egress(self):
        if _egress_router:
            return _egress_router.rotate_strategy()
        return None

    def request(self, method: str, url: str, **kwargs) -> "requests.Response":
        if self._aborted:
            raise ProxyError("ProxyGuard is in FAIL-DEAD state. Cannot make requests.")
        if self._session is None:
            self._session = self._build_session()
        self._enforce_timing()
        kwargs.setdefault("headers", {})
        if "User-Agent" not in kwargs["headers"]:
            kwargs["headers"]["User-Agent"] = self._user_agent
        kwargs.setdefault("timeout", 30)
        kwargs.setdefault("verify", False)
        try:
            logger.debug(f"  → {method} {url}")
            return self._session.request(method, url, **kwargs)
        finally:
            self._last_request_time = time.time()

    def get(self, url: str, **kwargs) -> "requests.Response":
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> "requests.Response":
        return self.request("POST", url, **kwargs)

    def new_circuit(self, target_domain: str = None) -> str:
        tor_pass = os.getenv("TOR_CONTROL_PASS", "") or os.getenv("TOR_PASSWORD", "")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(("127.0.0.1", TOR_CONTROL_PORT))
            if tor_pass:
                sock.sendall(f'AUTHENTICATE "{tor_pass}"\r\n'.encode())
            else:
                sock.sendall(b"AUTHENTICATE\r\n")
            data = sock.recv(1024)
            if b"250" in data:
                sock.sendall(b"SIGNAL NEWNYM\r\n")
                sock.recv(1024)
            sock.close()
        except Exception as e:
            logger.warning(f"  Could not request new Tor circuit: {e}")

        self._circuit_id = hashlib.sha256(
            (str(time.time()) + str(random.getrandbits(128))).encode()
        ).hexdigest()[:16]
        self._user_agent = random.choice(USER_AGENTS)
        self._session = self._build_session()
        self._check_exit_ip()
        logger.info(f"  New circuit: {self._circuit_id} → {self._exit_ip}")
        return self._circuit_id

    def abort(self):
        logger.critical("!!! FAIL-DEAD TRIGGERED !!!")
        self._aborted = True
        if self._session:
            self._session.close()
            self._session = None
        logger.critical("ProxyGuard is dead. No further requests allowed.")

    def status(self) -> dict:
        if self._check_tor(silent=True):
            strategy = "tor"
        elif self._check_wireguard(silent=True):
            strategy = "wireguard"
        elif self._check_protonvpn(silent=True):
            strategy = "protonvpn"
        elif self._check_openvpn(silent=True):
            strategy = "openvpn"
        elif self._check_vpn_passive(silent=True):
            strategy = "vpn"
        else:
            strategy = "none"
        return {
            "active": not self._aborted,
            "strategy": strategy,
            "exit_ip": self._exit_ip,
            "circuit_id": self._circuit_id,
            "user_agent": self._user_agent,
            "tor_running": self._check_tor(silent=True),
        }

    def _build_session(self):
        import requests
        s = requests.Session()
        s.verify = self._ca_bundle
        s.proxies = {"http": PROXY_URL, "https": PROXY_URL}
        s.headers.update({
            "User-Agent": self._user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "DNT": "1", "Connection": "keep-alive",
        })
        return s

    def _check_wireguard(self, silent=False) -> bool:
        try:
            r = subprocess.run(["wg", "show", "interfaces"], capture_output=True, text=True, timeout=3)
            ifaces = r.stdout.strip().split()
            if ifaces:
                if not silent:
                    logger.info(f"  ✓ WireGuard interfaces: {', '.join(ifaces)}")
                return True
            return False
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def _check_vpn_passive(self, silent=False) -> bool:
        """Detect Windows host VPN from WSL by checking PowerShell."""
        try:
            r = subprocess.run(
                ["powershell.exe", "-Command",
                 "Get-VpnConnection | Where-Object {$_.ConnectionStatus -eq 'Connected'} | Select-Object -ExpandProperty Name"],
                capture_output=True, text=True, timeout=5,
            )
            vpn_name = r.stdout.strip()
            if vpn_name:
                if not silent:
                    logger.info(f"  ✓ Windows VPN detected: {vpn_name}")
                return True
            return False
        except FileNotFoundError:
            pass
        except Exception:
            logger.debug("Non-critical error", exc_info=True)
        return False

    def _check_protonvpn(self, silent=False) -> bool:
        try:
            r = subprocess.run(["protonvpn-cli", "status"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and "Connected" in r.stdout:
                if not silent:
                    for line in r.stdout.split("\n"):
                        if "IP" in line or "Server" in line or "Country" in line:
                            logger.info(f"  {line.strip()}")
                return True
            return False
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def _check_openvpn(self, silent=False) -> bool:
        """Detect active OpenVPN connection via tun interface or process."""
        try:
            # Check for tun interfaces (common OpenVPN device name)
            r = subprocess.run(["ip", "link", "show", "type", "tun"], capture_output=True, text=True, timeout=3)
            if "tun" in r.stdout and "UP" in r.stdout:
                if not silent:
                    logger.info("  ✓ OpenVPN tun interface detected")
                return True
        except FileNotFoundError:
            pass
        except Exception:
            pass
        try:
            # Check for openvpn process
            r = subprocess.run(["pgrep", "-a", "openvpn"], capture_output=True, text=True, timeout=3)
            if r.stdout.strip():
                if not silent:
                    for line in r.stdout.strip().split("\n"):
                        logger.info(f"  ✓ OpenVPN: {line.strip()[:80]}")
                return True
        except FileNotFoundError:
            pass
        except Exception:
            pass
        # Check for /proc/net/tun (Linux tun device)
        try:
            if os.path.exists("/proc/net/tun"):
                with open("/proc/net/tun") as f:
                    data = f.read().strip()
                if data:
                    if not silent:
                        logger.info("  ✓ OpenVPN tun device present")
                    return True
        except Exception:
            pass
        return False

    def openvpn_connect(self, config_path: str, auth_user_pass: str = None, log_path: str = None) -> bool:
        """Start OpenVPN connection. Returns True if started successfully."""
        if not os.path.exists(config_path):
            logger.error(f"  ✗ OpenVPN config not found: {config_path}")
            return False
        log_path = log_path or f"/tmp/openvpn_{int(time.time())}.log"
        cmd = ["sudo", "openvpn", "--config", config_path, "--daemon", "--log", log_path, "--verb", "3"]
        if auth_user_pass and os.path.exists(auth_user_pass):
            cmd.extend(["--auth-user-pass", auth_user_pass])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                logger.info(f"  ✓ OpenVPN started: {config_path}")
                logger.info(f"  ✓ Log: {log_path}")
                return True
            else:
                logger.error(f"  ✗ OpenVPN failed: {r.stderr.strip()}")
                return False
        except subprocess.TimeoutExpired:
            logger.warning("  ⚠ OpenVPN start timed out (may still connect)")
            return True
        except Exception as e:
            logger.error(f"  ✗ OpenVPN error: {e}")
            return False

    def openvpn_disconnect(self) -> bool:
        """Kill all OpenVPN processes."""
        try:
            r = subprocess.run(["sudo", "pkill", "openvpn"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                logger.info("  ✓ OpenVPN stopped")
                return True
            logger.warning("  ⚠ No OpenVPN processes found")
            return False
        except Exception as e:
            logger.error(f"  ✗ OpenVPN kill error: {e}")
            return False

    def openvpn_status(self) -> dict:
        """Get OpenVPN connection details."""
        result = {"connected": False, "interface": None, "ip": None, "config": None, "uptime": None}
        try:
            r = subprocess.run(["pgrep", "-a", "openvpn"], capture_output=True, text=True, timeout=3)
            if r.stdout.strip():
                result["connected"] = True
                # Extract config path from process args
                for line in r.stdout.strip().split("\n"):
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "--config" and i + 1 < len(parts):
                            result["config"] = parts[i + 1]
        except Exception:
            pass
        try:
            # Get tun interface IP
            r = subprocess.run(["ip", "-4", "addr", "show", "type", "tun"], capture_output=True, text=True, timeout=3)
            import re
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout)
            if m:
                result["ip"] = m.group(1)
            # Get interface name
            m2 = re.search(r"\d+: (\w+):", r.stdout)
            if m2:
                result["interface"] = m2.group(1)
        except Exception:
            pass
        return result

    def _check_tor(self, silent=False) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", TOR_PORT))
            s.close()
            if not silent:
                logger.info(f"  ✓ Tor running on 127.0.0.1:{TOR_PORT}")
            return True
        except Exception as e:
            if not silent:
                logger.error(f"  ✗ Tor not running on 127.0.0.1:{TOR_PORT} — {e}")
                raise ProxyError(f"Tor not running on 127.0.0.1:{TOR_PORT} — {e}")
            return False

    def _check_tor_control(self, silent=False) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", TOR_CONTROL_PORT))
            s.sendall(b"AUTHENTICATE\r\n")
            data = s.recv(1024)
            s.close()
            ok = b"250" in data
            if not silent:
                logger.info(f"  ✓ Tor control port {TOR_CONTROL_PORT} accessible")
            return True
        except Exception as e:
            if not silent:
                logger.warning(f"  ⚠ Tor control port {TOR_CONTROL_PORT} not accessible — {e}")
            return False

    def _check_dns_leak(self, silent=False) -> bool:
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
                logger.info("  ✓ DNS routes through Tor SOCKS5h (no direct DNS leaks)")
            return True
        except Exception:
            if not silent:
                logger.warning("  ⚠ Cannot confirm Tor DNS routing — check proxy chain")
            return False

    def _check_ipv6_disabled(self, silent=False) -> bool:
        try:
            with open("/proc/sys/net/ipv6/conf/all/disable_ipv6") as f:
                disabled = f.read().strip() == "1"
            if not silent:
                logger.info(f"  {'✓ IPv6 disabled' if disabled else '⚠ IPv6 enabled'}")
            return disabled
        except FileNotFoundError:
            if not silent:
                logger.info("  ✓ IPv6 check skipped (not Linux)")
            return True

    def _get_real_ip(self) -> Optional[str]:
        cached = os.getenv("CACHED_REAL_IP")
        if cached:
            return cached
        import requests
        s = requests.Session()
        for url in REAL_IP_CHECK_URLS:
            try:
                r = s.get(url, timeout=5)
                if "ip" in r.text.lower():
                    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
                    if isinstance(data, dict) and "ip" in data:
                        return data["ip"]
                    import re
                    m = re.search(r'\d+\.\d+\.\d+\.\d+', r.text)
                    if m:
                        return m.group(0)
            except Exception:
                continue
        return None

    def _get_exit_ip(self) -> Optional[str]:
        # Try via configured proxy first (Tor)
        for url in REAL_IP_CHECK_URLS:
            try:
                import requests
                r = requests.get(url, proxies={"http": PROXY_URL, "https": PROXY_URL}, timeout=5)
                import re
                m = re.search(r'\d+\.\d+\.\d+\.\d+', r.text)
                if m:
                    return m.group(0)
            except Exception:
                continue
        # Fallback: direct connection (e.g. through Windows host VPN)
        for url in REAL_IP_CHECK_URLS:
            try:
                import requests
                r = requests.get(url, timeout=5)
                import re
                m = re.search(r'\d+\.\d+\.\d+\.\d+', r.text)
                if m:
                    return m.group(0)
            except Exception:
                continue
        return None

    def _check_exit_ip(self, silent=False) -> bool:
        try:
            real_ip = self._get_real_ip()
            exit_ip = self._get_exit_ip()
            if not exit_ip:
                if not silent:
                    logger.warning("  ⚠ Cannot determine exit IP — proxy may not be routing traffic")
                return False
            self._real_ip = real_ip
            self._exit_ip = exit_ip
            if exit_ip == real_ip:
                if not silent:
                    logger.warning(f"  ⚠ Exit IP ({exit_ip}) matches real IP — proxy may not be routing traffic")
                return False
            if not silent:
                logger.info(f"  ✓ Exit IP: {exit_ip} (different from real IP: {real_ip})")
            return True
        except Exception as e:
            if not silent:
                logger.warning(f"  ⚠ Exit IP check failed: {e}")
            return False

    def _enforce_timing(self):
        elapsed = time.time() - self._last_request_time
        if elapsed < MIN_DELAY and self._last_request_time > 0:
            delay = random.uniform(MIN_DELAY, MAX_DELAY)
            time.sleep(delay)


class guarded_operation:
    def __init__(self, target_description: str = None):
        self.target = target_description
        self.pg = None

    def __enter__(self) -> ProxyGuard:
        self.pg = ProxyGuard()
        self.pg.verify()
        if self.target:
            self.pg.new_circuit(self.target)
        return self.pg

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is ProxyError and self.pg:
            self.pg.abort()
        if self.pg and not exc_type and self.pg._session:
            self.pg._session.close()
        return False


if __name__ == "__main__":
    print("ProxyGuard — Mandatory Proxy Enforcement")
    print("=" * 60)
    try:
        with guarded_operation() as pg:
            print("\nProxy chain status:")
            for k, v in pg.status().items():
                print(f"  {k}: {v}")
            print("\n✓ ProxyGuard verification passed")
    except ProxyError as e:
        print(f"\n✗ ProxyGuard FAILED: {e}")
        print("  Fix the proxy chain and try again.\n")
        print("  Tip: set RAPHAEL_DEV_MODE=1 to skip proxy checks for localhost testing")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(1)
