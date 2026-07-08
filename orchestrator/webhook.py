import asyncio, hmac, hashlib, json, logging, os
from typing import Optional

import httpx

logger = logging.getLogger("webhook")

WEBHOOK_SECRET = os.getenv("RAPHAEL_WEBHOOK_SECRET", "")
WEBHOOK_RETRIES = int(os.getenv("RAPHAEL_WEBHOOK_RETRIES", "3"))
WEBHOOK_TIMEOUT = float(os.getenv("RAPHAEL_WEBHOOK_TIMEOUT", "10"))


async def deliver(url: str, payload: dict) -> bool:
    signing = WEBHOOK_SECRET.encode()
    body = json.dumps(payload, default=str).encode()
    signature = hmac.new(signing, body, hashlib.sha256).hexdigest() if signing else ""

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Raphael-CI/v2.0",
    }
    if signature:
        headers["X-Raphael-Signature"] = signature

    async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
        for attempt in range(1, WEBHOOK_RETRIES + 1):
            try:
                resp = await client.post(url, content=body, headers=headers)
                if resp.is_success:
                    logger.info(f"Webhook {url} delivered (attempt {attempt})")
                    return True
                logger.warning(f"Webhook {url} status {resp.status_code} (attempt {attempt})")
            except httpx.RequestError as e:
                logger.warning(f"Webhook {url} error: {e} (attempt {attempt})")
            if attempt < WEBHOOK_RETRIES:
                await asyncio.sleep(2 ** attempt)
    logger.error(f"Webhook {url} failed after {WEBHOOK_RETRIES} attempts")
    return False
