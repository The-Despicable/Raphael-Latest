import hashlib
import hmac
import os
import secrets
import time
from fastapi import Header, HTTPException
from typing import Optional

API_KEYS: dict[str, dict] = {}

SCOPES = {
    "admin":     ["engagements:rw", "agents:rw", "findings:rw", "config:rw", "logs:rw"],
    "operator":  ["engagements:rw", "agents:r",  "findings:rw", "config:r"],
    "viewer":    ["engagements:r",  "findings:r"],
    "agent":     ["agents:rw", "findings:w"],
}


def load_keys():
    for var, val in os.environ.items():
        if var.startswith("RAPHAEL_KEY_"):
            try:
                parts = val.split("|", 1)
                if len(parts) != 2:
                    continue
                scopes_str, key = parts
                kh = hashlib.sha256(key.encode()).hexdigest()
                scope_list = scopes_str.split(",")
                role = scope_list[0] if scope_list[0] in SCOPES else "viewer"
                resolved_scopes = SCOPES.get(role, [])
                for s in scope_list[1:]:
                    if s in ["engagements:rw", "agents:r", "agents:rw", "findings:rw", "findings:r", "config:rw", "config:r", "logs:rw"]:
                        resolved_scopes.append(s)
                API_KEYS[kh] = {
                    "name": var,
                    "scopes": list(set(resolved_scopes)),
                    "created": time.time(),
                }
            except Exception:
                continue

    legacy_key = os.getenv("API_KEY", "")
    if legacy_key:
        kh = hashlib.sha256(legacy_key.encode()).hexdigest()
        if kh not in API_KEYS:
            API_KEYS[kh] = {
                "name": "API_KEY_legacy",
                "scopes": ["admin"],
                "created": time.time(),
            }


def require_scope(*scopes: str):
    async def dependency(authorization: Optional[str] = Header(None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
        key = authorization[7:]
        kh = hashlib.sha256(key.encode()).hexdigest()
        if kh not in API_KEYS:
            raise HTTPException(status_code=401, detail="Unknown API key")
        entry = API_KEYS[kh]
        for needed in scopes:
            if needed not in entry["scopes"]:
                raise HTTPException(status_code=403, detail=f"Scope '{needed}' required")
        return entry
    return dependency


def generate_key(role: str = "operator") -> tuple[str, str]:
    key = secrets.token_hex(32)
    kh = hashlib.sha256(key.encode()).hexdigest()
    scopes = ",".join(SCOPES.get(role, SCOPES["viewer"]))
    API_KEYS[kh] = {
        "name": f"key_{role}_{int(time.time())}",
        "scopes": SCOPES.get(role, SCOPES["viewer"]),
        "created": time.time(),
    }
    return key, f"{role}|{scopes}|{key}"


load_keys()
