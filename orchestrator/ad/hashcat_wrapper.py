import asyncio
import json
import os
import re
import tempfile
from typing import Optional

HASHCAT_BIN = os.getenv("HASHCAT_BIN", "hashcat")
WORDLIST_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/wordlists/rockyou.txt.bz2",
]
HASHCAT_MODES = {
    "ntlm": 1000,
    "krb5tgs": 13100,
    "krb5asrep": 18200,
    "sha512crypt": 1800,
    "bcrypt": 3200,
    "sha1": 100,
}


class HashcatWrapper:
    def __init__(self, wordlist: str = ""):
        self._wordlist = wordlist or self._find_wordlist()
        self._available = bool(self._wordlist)

    @property
    def available(self) -> bool:
        return self._available

    def _find_wordlist(self) -> str:
        for p in WORDLIST_PATHS:
            if os.path.exists(p):
                return p
        return ""

    def detect_hash_mode(self, hash_str: str) -> Optional[int]:
        for name, mode in HASHCAT_MODES.items():
            if name == "ntlm" and re.match(r"^[a-fA-F0-9]{32}(:.+)?$", hash_str.strip()):
                return mode
            if name == "krb5tgs" and ("$krb5tgs$" in hash_str or hash_str.startswith("$")):
                return mode
            if name == "krb5asrep" and "$krb5asrep$" in hash_str:
                return mode
        return None

    async def crack_hash(self, hash_str: str, mode: Optional[int] = None, timeout: int = 300) -> dict:
        if not self._available:
            return {"success": False, "error": "No wordlist found"}

        mode = mode or self.detect_hash_mode(hash_str)
        if not mode:
            return {"success": False, "error": "Could not detect hash mode"}

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".hash") as f:
            f.write(hash_str.strip() + "\n")
            hash_path = f.name

        try:
            cmd = [HASHCAT_BIN, "-m", str(mode), hash_path, self._wordlist, "--show"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.PIPE, stderr=asyncio.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                return {"success": False, "error": "Hashcat timed out"}

            output = stdout.decode("utf-8", errors="replace").strip()
            if ":" in output:
                parts = output.split(":")
                return {"success": True, "hash": hash_str, "plaintext": parts[-1], "mode": mode}

            if proc.returncode != 0:
                cmd_actual = [HASHCAT_BIN, "-m", str(mode), hash_path, self._wordlist, "-O", "--force", "--potfile-disable"]
                proc2 = await asyncio.create_subprocess_exec(
                    *cmd_actual, stdout=asyncio.PIPE, stderr=asyncio.PIPE
                )
                try:
                    stdout2, stderr2 = await asyncio.wait_for(proc2.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    proc2.kill()
                    return {"success": False, "error": "Hashcat timed out on retry"}

                output2 = stdout2.decode("utf-8", errors="replace").strip()
                if ":" in output2:
                    parts = output2.split(":")
                    return {"success": True, "hash": hash_str, "plaintext": parts[-1], "mode": mode}

            return {"success": False, "hash": hash_str, "error": "Not cracked"}
        finally:
            os.unlink(hash_path)

    async def crack_hashes(self, hashes: list[str], mode: Optional[int] = None) -> list[dict]:
        results = []
        for h in hashes:
            result = await self.crack_hash(h, mode=mode)
            results.append(result)
        return results

    async def crack_from_file(self, hash_file: str, mode: int) -> dict:
        if not os.path.exists(hash_file):
            return {"success": False, "error": f"Hash file not found: {hash_file}"}
        cmd = [HASHCAT_BIN, "-m", str(mode), hash_file, self._wordlist, "-O", "--force", "--potfile-disable", "--outfile", hash_file + ".cracked"]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.PIPE, stderr=asyncio.PIPE)
        stdout, stderr = await proc.communicate()
        cracked = []
        if os.path.exists(hash_file + ".cracked"):
            with open(hash_file + ".cracked") as f:
                for line in f:
                    if ":" in line:
                        parts = line.strip().split(":")
                        cracked.append({"hash": parts[0], "plaintext": parts[-1]})
            os.unlink(hash_file + ".cracked")
        return {"success": len(cracked) > 0, "cracked": cracked, "total": len(cracked)}
