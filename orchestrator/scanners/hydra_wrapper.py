import re

from orchestrator.kali_tools_client import kali


class HydraWrapper:
    async def brute(self, target: str, service: str = "ssh",
                    username: str = "", userlist: str = "",
                    password: str = "", passlist: str = "",
                    port: int = 0, timeout: int = 300) -> dict:
        ip = target.split(":")[0]
        args = f"-q -t 4"
        if userlist:
            args += f" -L {userlist}"
        elif username:
            args += f" -l {username}"
        if passlist:
            args += f" -P {passlist}"
        elif password:
            args += f" -p {password}"
        port_arg = f" -s {port}" if port else ""
        args += f" {ip} {port_arg} {service}"
        result = await kali.run("hydra", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        creds = re.findall(r'login:\s*(\S+)\s+password:\s*(\S+)', stdout, re.IGNORECASE)
        return {
            "success": len(creds) > 0,
            "credentials": [{"user": u, "password": p} for u, p in creds],
            "count": len(creds),
            "raw": stdout[:3000],
        }

    async def brute_form(self, url: str, form_data: str,
                         failure_str: str = "incorrect",
                         userlist: str = "", passlist: str = "",
                         timeout: int = 300) -> dict:
        args = f"-q -t 4"
        if userlist:
            args += f" -L {userlist}"
        if passlist:
            args += f" -P {passlist}"
        args += f" {url} http-post-form \"{form_data}:{failure_str}\""
        result = await kali.run("hydra", args, timeout=timeout)
        stdout = (result.get("stdout") or "") + (result.get("stderr") or "")
        creds = re.findall(r'login:\s*(\S+)\s+password:\s*(\S+)', stdout, re.IGNORECASE)
        return {
            "success": len(creds) > 0,
            "credentials": [{"user": u, "password": p} for u, p in creds],
            "count": len(creds),
            "raw": stdout[:3000],
        }
