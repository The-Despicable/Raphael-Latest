import os
import sys
import random
import logging
import time
import threading
from typing import Optional, Union

from orchestrator.egress.strategies import (
    EgressStrategy, DirectStrategy, TorStrategy, ProxyChainStrategy,
    CDNFrontingStrategy, TLSWrapperStrategy, get_strategy, STRATEGY_MAP,
)

logger = logging.getLogger("egress.router")

AUTO_STRATEGY_ORDER = ["tor", "cdn_fronting", "proxy_chain", "tls_wrapper", "direct"]


class EgressRouter:
    def __init__(self, strategy: str = "auto", **strategy_kwargs):
        self._strategy_name = strategy
        self._strategy_kwargs = strategy_kwargs
        self._strategy: Optional[EgressStrategy] = None
        self._lock = threading.Lock()
        self._last_rotation = 0.0
        self._rotation_cooldown = 30.0
        self._failed_strategies = set()
        self._resolve()

    def _resolve(self):
        if self._strategy_name == "auto":
            dev_mode = os.getenv("RAPHAEL_DEV_MODE", "").lower() in ("1", "true", "yes")
            if dev_mode:
                self._strategy = DirectStrategy()
                logger.info("  Egress: auto → direct (RAPHAEL_DEV_MODE)")
                return
            for name in AUTO_STRATEGY_ORDER:
                if name in self._failed_strategies:
                    continue
                try:
                    self._strategy = self._try_strategy(name)
                    if self._strategy:
                        logger.info(f"  Egress: auto → {name}")
                        return
                except Exception as e:
                    logger.debug(f"  Egress: {name} unavailable ({e})")
                    self._failed_strategies.add(name)
            logger.warning("  Egress: no strategy available, falling back to direct")
            self._strategy = DirectStrategy()
        else:
            self._strategy = get_strategy(self._strategy_name, **self._strategy_kwargs)

    def _try_strategy(self, name: str, **kwargs) -> Optional[EgressStrategy]:
        merged = {**self._strategy_kwargs, **kwargs}
        strat = get_strategy(name, **merged)
        if name == "tor":
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                s.connect((merged.get("tor_host", "127.0.0.1"), merged.get("tor_port", 9050)))
                s.close()
                return strat
            except Exception:
                return None
        return strat

    @property
    def strategy(self) -> EgressStrategy:
        return self._strategy or DirectStrategy()

    def build_client_config(self, target_host: str = None) -> dict:
        with self._lock:
            return self.strategy.build_client(target_host)

    def build_httpx_kwargs(self, target_host: str = None) -> dict:
        config = self.build_client_config(target_host)
        kwargs = {
            "proxies": config.get("proxies"),
            "verify": config.get("verify", True),
            "headers": config.get("headers", {}),
        }
        sni = config.get("sni_hostname")
        if sni:
            kwargs["headers"].setdefault("Host", target_host or sni)
        front = config.get("front_domain")
        if front:
            kwargs["headers"].setdefault("Host", target_host or front)
        return kwargs

    def build_requests_kwargs(self, target_host: str = None) -> dict:
        config = self.build_client_config(target_host)
        kwargs = {
            "proxies": config.get("proxies"),
            "verify": config.get("verify", True),
            "headers": config.get("headers", {}),
            "timeout": 30,
        }
        sni = config.get("sni_hostname")
        if sni:
            kwargs["headers"].setdefault("Host", target_host or sni)
        front = config.get("front_domain")
        if front:
            kwargs["headers"].setdefault("Host", target_host or front)
        return kwargs

    def rotate_strategy(self, target_host: str = None) -> str:
        now = time.time()
        if now - self._last_rotation < self._rotation_cooldown:
            remaining = self._rotation_cooldown - (now - self._last_rotation)
            logger.debug(f"  Rotation cooldown: {remaining:.0f}s remaining")
            return self._strategy_name
        available = [n for n in AUTO_STRATEGY_ORDER if n not in self._failed_strategies and n != self._strategy_name]
        if not available:
            available = [n for n in AUTO_STRATEGY_ORDER if n != self._strategy_name]
        if not available:
            return self._strategy_name
        next_strategy = random.choice(available)
        self._strategy_name = next_strategy
        self._last_rotation = now
        self._resolve()
        logger.info(f"  Rotated to strategy: {next_strategy}")
        return next_strategy

    def mark_failed(self, strategy_name: str = None):
        name = strategy_name or self._strategy_name
        self._failed_strategies.add(name)
        logger.warning(f"  Strategy failed and blacklisted: {name}")
        self.rotate_strategy()

    def get_client(self, target_host: str = None):
        from httpx import AsyncClient
        kwargs = self.build_httpx_kwargs(target_host)
        return AsyncClient(**kwargs)

    def get_session(self, target_host: str = None):
        import requests
        kwargs = self.build_requests_kwargs(target_host)
        s = requests.Session()
        if kwargs.get("proxies"):
            s.proxies.update(kwargs["proxies"])
        s.verify = kwargs.get("verify", True)
        if kwargs.get("headers"):
            s.headers.update(kwargs["headers"])
        return s

    def status(self) -> dict:
        return {
            "strategy": self._strategy_name,
            "active": self._strategy.__class__.__name__ if self._strategy else "none",
            "failed_strategies": list(self._failed_strategies),
        }


def create_router(strategy: str = "auto", **kwargs) -> EgressRouter:
    return EgressRouter(strategy=strategy, **kwargs)
