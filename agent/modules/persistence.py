import os

class Persistence:
    @staticmethod
    def install_cron(script_path: str, interval: str = "*/30 * * * *") -> bool:
        try:
            line = f"{interval} python3 {script_path}\n"
            with open("/etc/cron.d/raphael-agent", "w") as f:
                f.write(line)
            os.chmod("/etc/cron.d/raphael-agent", 0o644)
            return True
        except:
            return False

    @staticmethod
    def install_systemd(script_path: str) -> bool:
        unit = f"""[Unit]
Description=Raphael Agent
After=network.target

[Service]
ExecStart=python3 {script_path}
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
"""
        try:
            with open("/etc/systemd/system/raphael-agent.service", "w") as f:
                f.write(unit)
            os.system("systemctl daemon-reload && systemctl enable raphael-agent && systemctl start raphael-agent")
            return True
        except:
            return False

    @staticmethod
    def install_registry(script_path: str) -> bool:
        return False
