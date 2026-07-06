import asyncio, json, logging, time, hashlib
from dataclasses import dataclass, field
from typing import Optional
import httpx

logger = logging.getLogger("schema_registry")

SCHEMA_TIMEOUT = 3.0
CACHE_TTL = 300


@dataclass
class ServiceSchema:
    name: str
    base_url: str
    openapi: Optional[dict] = None
    available: bool = False
    fetched_at: float = 0.0
    _request_schemas: dict = field(default_factory=dict)

    def request_schema_for(self, path: str, method: str = "post") -> Optional[dict]:
        cache_key = f"{method.upper()}:{path}"
        if cache_key in self._request_schemas:
            return self._request_schemas[cache_key]

        if not self.openapi:
            return None

        path_item = self.openapi.get("paths", {}).get(path, {})
        operation = path_item.get(method.lower(), {})
        content = operation.get("requestBody", {}).get("content", {})
        for media_type in ("application/json", "*/*"):
            schema = content.get(media_type, {}).get("schema")
            if schema:
                resolved = self._resolve_refs(schema)
                self._request_schemas[cache_key] = resolved
                return resolved
        return None

    def _resolve_refs(self, schema: dict, refs_seen: Optional[set] = None) -> dict:
        if refs_seen is None:
            refs_seen = set()
        if "$ref" in schema:
            ref = schema["$ref"]
            if ref in refs_seen:
                return {"type": "object", "description": f"circular: {ref}"}
            refs_seen.add(ref)
            resolved = self._resolve_json_pointer(ref)
            if resolved:
                return self._resolve_refs(resolved, refs_seen)
            return schema
        result = {}
        for k, v in schema.items():
            if isinstance(v, dict):
                result[k] = self._resolve_refs(v, refs_seen)
            elif isinstance(v, list):
                result[k] = [
                    self._resolve_refs(i, refs_seen) if isinstance(i, dict) else i
                    for i in v
                ]
            else:
                result[k] = v
        return result

    def _resolve_json_pointer(self, ref: str) -> Optional[dict]:
        if not self.openapi:
            return None
        parts = ref.lstrip("#/").split("/")
        node = self.openapi
        for part in parts:
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return None
        return node if isinstance(node, dict) else None


class SchemaRegistry:
    def __init__(self, pipeline_map: dict, host: str = "127.0.0.1", timeout: float = SCHEMA_TIMEOUT):
        self.services: dict[str, ServiceSchema] = {}
        for phase, (path, svc_name, port) in pipeline_map.items():
            base_url = f"http://{host}:{port}"
            try:
                resp = httpx.get(f"{base_url}/openapi.json", timeout=timeout)
                if resp.status_code == 200:
                    self.services[svc_name] = ServiceSchema(
                        name=svc_name, base_url=base_url,
                        openapi=resp.json(), available=True,
                        fetched_at=time.time(),
                    )
                    logger.info(f"{svc_name} schema loaded ({len(resp.json().get('paths', {}))} paths)")
                else:
                    logger.warning(f"{svc_name} schema returned {resp.status_code} — skipping")
                    self.services[svc_name] = ServiceSchema(
                        name=svc_name, base_url=base_url, available=False,
                    )
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                logger.warning(f"{svc_name} schema fetch failed ({e}) — phase will be skipped")
                self.services[svc_name] = ServiceSchema(
                    name=svc_name, base_url=base_url, available=False,
                )

    def validate_payload(self, service_name: str, path: str,
                         payload: dict, method: str = "post") -> tuple[bool, Optional[str], dict]:
        svc = self.services.get(service_name)
        if not svc or not svc.available or not svc.openapi:
            return True, None, payload

        schema = svc.request_schema_for(path, method)
        if not schema:
            return True, None, payload

        props = schema.get("properties", {})
        required = schema.get("required", [])

        errors = []
        cleaned = {}

        for field_name in props:
            is_required = field_name in required
            if field_name in payload:
                cleaned[field_name] = payload[field_name]
            elif is_required:
                default = props[field_name].get("default")
                example = props[field_name].get("example")
                if default is not None:
                    cleaned[field_name] = default
                elif example is not None:
                    cleaned[field_name] = example
                elif props[field_name].get("type") == "string":
                    cleaned[field_name] = ""
                elif props[field_name].get("type") in ("integer", "number"):
                    cleaned[field_name] = 0
                elif props[field_name].get("type") == "boolean":
                    cleaned[field_name] = False
                elif props[field_name].get("type") == "array":
                    cleaned[field_name] = []
                elif props[field_name].get("type") == "object":
                    cleaned[field_name] = {}
                else:
                    errors.append(f"missing required field '{field_name}' with no default")

        type_map = {"string": str, "integer": int, "number": float, "boolean": bool}
        for field_name, value in cleaned.items():
            expected_type = props.get(field_name, {}).get("type")
            if expected_type in type_map and value is not None:
                if not isinstance(value, type_map[expected_type]):
                    errors.append(
                        f"field '{field_name}' expected {expected_type}, got {type(value).__name__}"
                    )

        if errors:
            return False, "; ".join(errors), cleaned

        return True, None, cleaned

    def build_payload(self, phase: str, path: str, service_name: str,
                      target: str, strategy: dict) -> dict:
        svc = self.services.get(service_name)
        if not svc or not svc.available:
            return {"target": target}

        schema = svc.request_schema_for(path, "post")
        if not schema:
            return {"target": target}

        props = schema.get("properties", {})
        required = schema.get("required", [])
        payload = {}

        for field_name in props:
            field_schema = props[field_name]
            field_type = field_schema.get("type", "string")
            is_required = field_name in required

            val = None

            if field_name == "target":
                val = target
            elif field_name in ("target_ip",):
                val = target.replace("http://", "").replace("https://", "").split(":")[0]
            elif field_name == "url":
                val = target
            elif field_name in strategy:
                val = strategy[field_name]
            elif field_schema.get("default") is not None:
                val = field_schema["default"]
            elif field_schema.get("example") is not None:
                val = field_schema["example"]
            elif is_required:
                if field_type == "string":
                    val = ""
                elif field_type == "boolean":
                    val = False
                elif field_type in ("integer", "number"):
                    val = 0
                elif field_type == "array":
                    val = []
                elif field_type == "object":
                    val = {}
            else:
                val = None

            if val is not None:
                payload[field_name] = val

        return payload

    def schema_hash(self, service_name: str) -> str:
        svc = self.services.get(service_name)
        if svc and svc.openapi:
            return hashlib.sha256(
                json.dumps(svc.openapi, sort_keys=True).encode()
            ).hexdigest()[:12]
        return ""

    def get_status(self) -> dict:
        return {
            name: {
                "available": svc.available,
                "paths": len(svc.openapi.get("paths", {})) if svc.openapi else 0,
                "age_sec": time.time() - svc.fetched_at if svc.fetched_at else -1,
            }
            for name, svc in self.services.items()
        }
