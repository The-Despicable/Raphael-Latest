"""
Sandbox for safe execution of LLM-generated code.
Runs untrusted code in isolated Docker containers with resource limits.
"""
import asyncio
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("sandbox")

SANDBOX_IMAGE = os.getenv("RAPHAEL_SANDBOX_IMAGE", "python:3.11-slim")
SANDBOX_MEMORY = os.getenv("RAPHAEL_SANDBOX_MEMORY", "256m")
SANDBOX_CPUS = os.getenv("RAPHAEL_SANDBOX_CPUS", "0.5")
SANDBOX_TIMEOUT = int(os.getenv("RAPHAEL_SANDBOX_TIMEOUT", "30"))


@dataclass
class SandboxResult:
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False
    duration_ms: float = 0.0


class SandboxError(Exception):
    pass


class PatchSandbox:
    """Runs untrusted code in isolated Docker container with resource limits.

    Uses `docker run --rm` with:
    - No network access (--network=none)
    - Read-only root filesystem (--read-only)
    - Memory limit (default 256m)
    - CPU limit (default 0.5 cores)
    - Timeout (default 30s)
    - No privileges
    """

    def __init__(
        self,
        image: str = SANDBOX_IMAGE,
        memory: str = SANDBOX_MEMORY,
        cpus: str = SANDBOX_CPUS,
        timeout: int = SANDBOX_TIMEOUT,
    ):
        self.image = image
        self.memory = memory
        self.cpus = cpus
        self.timeout = timeout
        self._check_docker()

    def _check_docker(self):
        """Verify docker is available."""
        import subprocess
        try:
            subprocess.run(
                ["docker", "info"],
                capture_output=True, text=True, timeout=5
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"Docker not available for sandbox: {e}")

    async def run_code(
        self,
        code: str,
        args: Optional[list[str]] = None,
        env: Optional[dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> SandboxResult:
        """Run Python code string in sandboxed container."""
        timeout = timeout or self.timeout
        t0 = time.monotonic()

        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "script.py"
            script_path.write_text(code)

            cmd = [
                "docker", "run", "--rm",
                "--network", "none",
                "--read-only",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                "--security-opt", "no-new-privileges:true",
                "--cap-drop", "ALL",
                "--memory", self.memory,
                "--cpus", self.cpus,
                "-v", f"{tmp}:/workspace:ro",
            ]

            for k, v in (env or {}).items():
                cmd.extend(["-e", f"{k}={v}"])

            cmd.extend([self.image, "python", "/workspace/script.py"])
            if args:
                cmd.extend(args)

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.PIPE,
                    stderr=asyncio.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=timeout
                    )
                    elapsed = (time.monotonic() - t0) * 1000
                    return SandboxResult(
                        stdout=stdout.decode("utf-8", errors="replace"),
                        stderr=stderr.decode("utf-8", errors="replace"),
                        returncode=proc.returncode or 0,
                        duration_ms=elapsed,
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    elapsed = (time.monotonic() - t0) * 1000
                    return SandboxResult(
                        stdout="",
                        stderr="[TIMEOUT]",
                        returncode=-1,
                        timed_out=True,
                        duration_ms=elapsed,
                    )
            except FileNotFoundError:
                raise SandboxError("Docker not found. Install docker to use the sandbox.")

    async def run_command(
        self,
        cmd_args: list[str],
        timeout: Optional[int] = None,
    ) -> SandboxResult:
        """Run arbitrary command in sandboxed container."""
        timeout = timeout or self.timeout
        t0 = time.monotonic()

        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--security-opt", "no-new-privileges:true",
            "--cap-drop", "ALL",
            "--memory", self.memory,
            "--cpus", self.cpus,
            self.image,
        ] + cmd_args

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.PIPE,
                stderr=asyncio.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                elapsed = (time.monotonic() - t0) * 1000
                return SandboxResult(
                    stdout=stdout.decode("utf-8", errors="replace"),
                    stderr=stderr.decode("utf-8", errors="replace"),
                    returncode=proc.returncode or 0,
                    duration_ms=elapsed,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                elapsed = (time.monotonic() - t0) * 1000
                return SandboxResult(
                    stdout="",
                    stderr="[TIMEOUT]",
                    returncode=-1,
                    timed_out=True,
                    duration_ms=elapsed,
                )
        except FileNotFoundError:
            raise SandboxError("Docker not found.")

    def validate_syntax(self, code: str) -> tuple[bool, str]:
        """Check Python syntax without executing."""
        try:
            compile(code, "<sandbox>", "exec")
            return True, ""
        except SyntaxError as e:
            return False, str(e)


sandbox = PatchSandbox()
