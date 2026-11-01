"""
Apify Actor entrypoint for `technoplusit/ecomm-seo-llms-auditor-mcp` with
graceful fail-closed Worf quarantine, zero-flake `{}` / `{"helloWorld": 123}`
default execution, and Pay-Per-Event (`PAY_PER_EVENT`) charging:
  - `actor-start` ($0.005)
  - `url-audited` ($0.003)
  - `remediation-pack-generated` ($0.010)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from seo_llms_engine import execute_actor_action


async def _try_charge_event(actor_cls: Any, event_name: str, count: int = 1) -> None:
    """Safely trigger Apify PAY_PER_EVENT charge if supported by the runtime."""
    charge_fn = getattr(actor_cls, "charge", None)
    if callable(charge_fn):
        try:
            await charge_fn(event_name=event_name, count=count)
        except Exception as exc:
            log_obj = getattr(actor_cls, "log", None)
            if log_obj and hasattr(log_obj, "warning"):
                log_obj.warning(f"PPE charge warning for {event_name}: {type(exc).__name__}")


async def main() -> None:
    try:
        from apify import Actor

        async with Actor:
            actor_input = await Actor.get_input() or {}
            Actor.log.info(f"Running E-Commerce SEO & llms.txt Auditor MCP with input: {actor_input}")
            await _try_charge_event(Actor, "actor-start", 1)

            items: List[Dict[str, Any]] = execute_actor_action(actor_input)
            for item in items:
                if item.get("status") == "ok":
                    await _try_charge_event(Actor, "url-audited", 1)
                    if item.get("remediation_pack"):
                        await _try_charge_event(Actor, "remediation-pack-generated", 1)
                await Actor.push_data({k: v for k, v in item.items() if v is not None})

            await Actor.set_value("OUTPUT", items[0] if len(items) == 1 else items)
            if items and isinstance(items[0], dict) and (items[0].get("remediation_pack") or {}).get("generated_llms_txt"):
                await Actor.set_value(
                    "llms.txt",
                    items[0]["remediation_pack"]["generated_llms_txt"],
                    content_type="text/plain",
                )
            Actor.log.info(f"Successfully pushed {len(items)} SEO & llms.txt audit report(s).")
    except ImportError:
        raw_input = os.environ.get("ACTOR_INPUT", "{}")
        actor_input = json.loads(raw_input) if raw_input else {}
        items = execute_actor_action(actor_input)
        print(json.dumps(items, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
