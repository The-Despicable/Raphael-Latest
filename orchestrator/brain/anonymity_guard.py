import socket, time, os, json


def verify_anonymity(target: str = "") -> dict:
    result = {
        "tor_active": False, "proxy_ok": False,
        "identity_fresh": True, "strategy": "unknown",
    }

    dev_mode = os.getenv("RAPHAEL_DEV_MODE", "").lower() in ("1", "true", "yes")

    try:
        from orchestrator.proxy_guard import ProxyGuard
        pg = ProxyGuard(target=target)

        try:
            strategy = pg._detect_proxy_strategy()
        except Exception:
            strategy = "tor"

        result["strategy"] = strategy
        pg.verify()
        result["proxy_ok"] = True

        if strategy == "protonvpn":
            result["tor_active"] = False
            result["dns_leak"] = False
        elif strategy == "tor":
            result["tor_active"] = True
            result["dns_leak"] = False
        else:
            result["dns_leak"] = False
    except ImportError:
        result["proxy_guard_available"] = False
    except Exception as e:
        if dev_mode:
            result["proxy_error"] = str(e)
            result["proxy_ok"] = False
        else:
            raise RuntimeError(f"Anonymity check failed: {e}")

    return result


def rotate_tor_identity() -> bool:
    TOR_CONTROL = os.getenv("TOR_CONTROL", "127.0.0.1:9051")
    tor_pass = os.getenv("TOR_CONTROL_PASS", "") or os.getenv("TOR_PASSWORD", "")
    ctrl_host, ctrl_port = TOR_CONTROL.split(":") if ":" in TOR_CONTROL else ("127.0.0.1", "9051")
    try:
        s = socket.create_connection((ctrl_host, int(ctrl_port)), timeout=5)
        if tor_pass:
            s.sendall(f'AUTHENTICATE "{tor_pass}"\r\n'.encode())
            resp = s.recv(1024)
            if b"250" not in resp:
                return False
        s.sendall(b"SIGNAL NEWNYM\r\n")
        resp = s.recv(1024)
        s.close()
        return b"250" in resp
    except Exception:
        return False


def check_ip_leak(tor_check_url: str = "https://check.torproject.org/api/ip") -> dict:
    import requests
    try:
        from orchestrator.proxy_guard import ProxyGuard
        pg = ProxyGuard()
        pg.verify()
        session = pg.get_session()
        resp = session.get(tor_check_url, timeout=15)
        data = resp.json()
        return {"ip": data.get("IP", "unknown"), "is_tor": data.get("IsTor", False)}
    except Exception as e:
        return {"error": str(e), "is_tor": False}


class AnonymityGuard:
    def __init__(self, strategy: str = "auto", rotation_interval: int = 300):
        self._strategy = strategy
        self.rotation_interval = rotation_interval
        self._last_rotation = 0
        self._identity_count = 0
        self._detected_strategy = None

    def enforce(self, target: str = "") -> dict:
        from orchestrator.proxy_guard import ProxyGuard
        pg = ProxyGuard(target=target)

        if self._strategy == "auto":
            try:
                self._detected_strategy = pg._detect_proxy_strategy()
            except Exception:
                self._detected_strategy = "tor"
        else:
            self._detected_strategy = self._strategy

        status = verify_anonymity(target=target)
        self._maybe_rotate()
        return status

    def _maybe_rotate(self):
        if self._detected_strategy != "tor":
            return
        if time.time() - self._last_rotation > self.rotation_interval:
            if rotate_tor_identity():
                self._identity_count += 1
                self._last_rotation = time.time()

    def get_status(self) -> dict:
        status = verify_anonymity()
        return {
            "strategy": self._detected_strategy or status.get("strategy", "unknown"),
            "proxy_ok": status.get("proxy_ok", False),
            "identity_rotations": self._identity_count,
            "last_rotation": self._last_rotation,
        }
