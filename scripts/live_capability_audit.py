from __future__ import annotations

import asyncio
import json

from app.server import ha


async def main() -> None:
    await ha.start()
    try:
        integrations = await ha.integrations()
        solaredge = [item for item in integrations if item.get("domain") == "solaredge"]
        registry = await ha.entity_registry()
        solaredge_registry = [
            item
            for item in registry
            if item.get("platform") == "solaredge"
            or "solaredge" in str(item.get("entity_id", "")).lower()
        ]
        statistics = await ha.ws_command({"type": "recorder/list_statistic_ids"})
        solar_statistics = [
            item
            for item in statistics
            if any(
                marker in str(item.get("statistic_id", "")).lower()
                for marker in ("solaredge", "solar", "inverter", "module")
            )
        ]
        services = await ha.services()
        wanted_domains = {
            "backup",
            "cast",
            "dreame_vacuum",
            "media_player",
            "nest",
            "notify",
            "recorder",
            "tts",
            "vacuum",
            "weather",
        }
        service_summary = {}
        for domain in services:
            if domain.get("domain") in wanted_domains:
                service_summary[str(domain.get("domain"))] = sorted(
                    (domain.get("services") or {}).keys()
                )
        result = {
            "solaredge": [
                {
                    "entry_id": item.get("entry_id"),
                    "state": item.get("state"),
                    "source": item.get("source"),
                    "supports_reconfigure": item.get("supports_reconfigure"),
                    "data_keys": sorted((item.get("data") or {}).keys()),
                    "option_keys": sorted((item.get("options") or {}).keys()),
                }
                for item in solaredge
            ],
            "solaredge_registry": [
                {
                    "entity_id": item.get("entity_id"),
                    "disabled_by": item.get("disabled_by"),
                    "original_name": item.get("original_name"),
                    "device_class": item.get("device_class"),
                }
                for item in solaredge_registry
            ],
            "solar_statistics": solar_statistics,
            "service_summary": service_summary,
        }
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    finally:
        await ha.close()


asyncio.run(main())
