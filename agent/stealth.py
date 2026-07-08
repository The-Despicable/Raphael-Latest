import random, time, os, sys

class Stealth:
    @staticmethod
    def randomize_jitter(base: int = 30) -> int:
        return int(base * (0.7 + random.random() * 0.6))

    @staticmethod
    def strip_metadata() -> None:
        sys.excepthook = lambda t, v, tb: print(f"Error: {v}", file=sys.stderr)

    @staticmethod
    def no_trace() -> None:
        try:
            with open("/proc/self/status", "w") as f:
                f.write("TracerPid: 0\n")
        except:
            pass

    @staticmethod
    def sandbox_detect() -> bool:
        checks = [
            os.path.exists("/.dockerenv"),
            os.path.exists("/proc/vz"),
        ]
        try:
            if os.path.exists("/proc/1/cgroup"):
                cg = open("/proc/1/cgroup").read()
                checks.append("container" in cg)
        except:
            pass
        return sum(checks) >= 2
