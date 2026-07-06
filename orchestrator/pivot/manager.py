import os
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("pivot_manager")


@dataclass
class PivotHop:
    session_id: str
    hostname: str
    address: str
    proxy_url: str
    reachable_nets: list[str] = field(default_factory=list)


class PivotManager:
    def __init__(self):
        self._hops: list[PivotHop] = []

    @property
    def chain_length(self) -> int:
        return len(self._hops)

    @property
    def deepest_proxy(self) -> Optional[str]:
        if not self._hops:
            return None
        return self._hops[-1].proxy_url

    def add_hop(self, hop: PivotHop):
        self._hops.append(hop)
        logger.info(f"Pivot: added hop {hop.hostname} ({hop.address}) → {hop.proxy_url}")

    def remove_hop(self, session_id: str):
        self._hops = [h for h in self._hops if h.session_id != session_id]

    def proxies_for_target(self, target: str) -> list[str]:
        urls = []
        for hop in self._hops:
            for net in hop.reachable_nets:
                if self._ip_in_net(target, net):
                    urls.append(hop.proxy_url)
        return urls

    def env_for_target(self, target: str) -> dict:
        proxy = self.deepest_proxy
        if proxy:
            return {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "ALL_PROXY": proxy}
        return {}

    def _ip_in_net(self, ip: str, net: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
        except ValueError:
            return False


_pivot: Optional[PivotManager] = None


def get_pivot() -> PivotManager:
    global _pivot
    if _pivot is None:
        _pivot = PivotManager()
    return _pivot
