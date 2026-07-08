from typing import Optional
from orchestrator.kali_tools_client import kali


class NetExecWrapper:
    def __init__(self):
        self._available = True

    @property
    def available(self) -> bool:
        return self._available

    async def smb_pth(self, target: str, username: str, hash: str,
                      module: str = "shares") -> dict:
        args = f"smb {target} -u {username} -H {hash} -M {module}"
        return await self._run(args)

    async def smb_enum(self, target: str, username: str = None,
                       password: str = None, hash: str = None) -> dict:
        args = f"smb {target} -M shares"
        if username:
            args += f" -u {username}"
        if password:
            args += f" -p {password}"
        if hash:
            args += f" -H {hash}"
        return await self._run(args)

    async def ldap_kerberoast(self, target: str, username: str, password: str) -> dict:
        args = f"ldap {target} -u {username} -p {password} -M kerberoast"
        return await self._run(args)

    async def _run(self, args: str) -> dict:
        result = await kali.run("netexec", args, timeout=120)
        return {
            "command": f"netexec {args[:80]}...",
            "output": (result.get("stdout", "") + result.get("stderr", ""))[:2000],
            "success": result.get("returncode") == 0,
            "error": result.get("error"),
        }
