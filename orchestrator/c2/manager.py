import os
import time
import logging
from typing import Optional

from .models import C2Session, ImplantConfig, TaskResult
from .noop_backend import NoopBackend

logger = logging.getLogger("c2_manager")


class C2Manager:
    def __init__(self):
        self._backend = NoopBackend()
        self._sessions: dict[str, C2Session] = {}
        self._proxy_map: dict[str, str] = {}  # session_id -> socks5h:// url
        self._initialized = False

    @property
    def backend_available(self) -> bool:
        return self._backend.available

    @property
    def active_sessions(self) -> list[C2Session]:
        return list(self._sessions.values())

    async def init(self, backend: str = "auto"):
        if self._initialized:
            return
        self._initialized = True

        if backend == "sliver" or (backend == "auto" and os.getenv("SLIVER_OPERATOR_CONFIG")):
            try:
                from .sliver_backend import SliverBackend
                sb = SliverBackend()
                await sb._ensure_client()
                if sb.available:
                    self._backend = sb
                    logger.info("C2: using Sliver backend")
                    return
            except Exception:
                pass

        if backend == "noop":
            self._backend = NoopBackend()
            logger.info("C2: using Noop backend (no agent capability)")

    async def refresh_sessions(self) -> list[C2Session]:
        sessions = await self._backend.list_sessions()
        self._sessions = {s.id: s for s in sessions}
        return self.active_sessions

    async def generate_implant(self, config: ImplantConfig) -> bytes:
        return await self._backend.generate_implant(config)

    async def execute(self, session_id: str, command: str) -> TaskResult:
        return await self._backend.send_task(session_id, command)

    async def socks_enable(self, session_id: str, port: int = 0) -> Optional[str]:
        if session_id in self._proxy_map:
            return self._proxy_map[session_id]
        port = port or (1080 + len(self._proxy_map) + 1)
        proxy_url = await self._backend.socks_start(session_id, port)
        if proxy_url:
            self._proxy_map[session_id] = proxy_url
            if session_id in self._sessions:
                self._sessions[session_id].socks_port = port
                self._sessions[session_id].proxy_url = proxy_url
        return proxy_url

    async def socks_disable(self, session_id: str):
        await self._backend.socks_stop(session_id)
        self._proxy_map.pop(session_id, None)
        if session_id in self._sessions:
            self._sessions[session_id].socks_port = None
            self._sessions[session_id].proxy_url = None

    async def stop(self):
        await self._backend.stop()


_c2: Optional[C2Manager] = None


def get_c2() -> C2Manager:
    global _c2
    if _c2 is None:
        _c2 = C2Manager()
    return _c2
