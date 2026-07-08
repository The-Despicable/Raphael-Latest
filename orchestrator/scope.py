"""
Scope enforcement for Raphael.
Defines what targets are authorized for testing.
"""
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AllowedScope:
    """Defines the authorized target scope for an engagement."""

    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=lambda: [1, 65535])
    exclude_domains: list[str] = field(default_factory=list)
    exclude_ips: list[str] = field(default_factory=list)
    persona: Optional[str] = None
    rate_limit: float = 2.0
    business_hours_only: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "AllowedScope":
        return cls(
            domains=d.get("allowed_domains", []),
            ip_ranges=d.get("allowed_ips", []),
            ports=d.get("ports", [1, 65535]),
            exclude_domains=d.get("excluded_domains", d.get("excluded", [])),
            exclude_ips=d.get("excluded_ips", []),
            persona=d.get("persona"),
            rate_limit=d.get("rate_limit", 2.0),
            business_hours_only=d.get("business_hours_only", False),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "AllowedScope":
        """Load scope from a YAML file. Falls back to JSON if yaml not available."""
        path = Path(path)
        if not path.exists():
            return cls()

        try:
            import yaml
            with open(path) as f:
                data = yaml.safe_load(f)
            engagement = data.get("engagement", data)
            return cls.from_dict(engagement)
        except ImportError:
            with open(path) as f:
                data = json.load(f)
            engagement = data.get("engagement", data)
            return cls.from_dict(engagement)

    @classmethod
    def from_env(cls) -> "AllowedScope":
        """Load scope from environment variables."""
        scope_file = os.getenv("RAPHAEL_SCOPE_FILE", "")
        if scope_file:
            return cls.from_yaml(scope_file)

        domains_str = os.getenv("RAPHAEL_SCOPE_DOMAINS", "")
        ips_str = os.getenv("RAPHAEL_SCOPE_IPS", "")
        if domains_str or ips_str:
            return cls(
                domains=[d.strip() for d in domains_str.split(",") if d.strip()],
                ip_ranges=[i.strip() for i in ips_str.split(",") if i.strip()],
            )
        return cls()

    def allows_domain(self, domain: str) -> bool:
        domain = domain.lower().strip()
        if self.exclude_domains:
            for ex in self.exclude_domains:
                ex = ex.lower().strip()
                if domain == ex or domain.endswith(f".{ex}"):
                    return False
        if not self.domains:
            return True
        for allowed in self.domains:
            allowed = allowed.lower().strip()
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True
        return False

    def allows_ip(self, ip: str) -> bool:
        ip = ip.strip()
        if self.exclude_ips:
            for ex in self.exclude_ips:
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(ex):
                        return False
                except ValueError:
                    if ip == ex:
                        return False
        if not self.ip_ranges:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            for r in self.ip_ranges:
                if addr in ipaddress.ip_network(r):
                    return True
        except ValueError:
            pass
        return False

    def allows_port(self, port: int) -> bool:
        if len(self.ports) == 2 and self.ports == [1, 65535]:
            return True
        for p in self.ports:
            if isinstance(p, int) and p == port:
                return True
        return False

    def check(self, target: str) -> bool:
        """Check if target is authorized. Accepts IP or domain."""
        target = target.strip()
        try:
            ipaddress.ip_address(target)
            return self.allows_ip(target)
        except ValueError:
            return self.allows_domain(target)

    def check_strict(self, target: str, port: Optional[int] = None) -> tuple[bool, str]:
        """Strict check with error message. Returns (allowed, reason)."""
        target = target.strip()
        try:
            ipaddress.ip_address(target)
            if not self.allows_ip(target):
                return False, f"IP {target} not in allowed ranges"
        except ValueError:
            if not self.allows_domain(target):
                return False, f"Domain {target} not in allowed domains"

        if port is not None and not self.allows_port(port):
            return False, f"Port {port} not in allowed ports"

        if self.business_hours_only:
            import datetime
            hour = datetime.datetime.now().hour
            if hour < 9 or hour > 17:
                return False, "Outside business hours (9-17)"

        return True, "OK"


default_scope = AllowedScope.from_env()
