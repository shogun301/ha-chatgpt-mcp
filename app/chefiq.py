"""Read-only CHEF iQ tools over Home Assistant's authoritative sensor states."""
from __future__ import annotations

from datetime import datetime, timezone
import math


async def snapshot(ha):
    registry = await ha.entity_registry()
    allowed = {row["entity_id"] for row in registry if row.get("platform") == "chefiq_cloud" and not row.get("disabled_by")}
    states = [s for s in await ha.states() if s.get("entity_id") in allowed]
    connections, probes = [], {}
    for state in states:
        attrs = state.get("attributes", {})
        role = attrs.get("role")
        if role == "connection":
            connections.append({"entity_id": state["entity_id"], "state": state.get("state")})
        elif role in ("internal_temp", "ambient_temp"):
            probe_id = attrs.get("probe_id")
            if not isinstance(probe_id, str) or not probe_id.startswith("probe_"):
                continue
            probe = probes.setdefault(probe_id, {"probe_id": probe_id})
            try:
                stamp = datetime.fromisoformat(attrs["sample_time"])
                age = (datetime.now(timezone.utc) - stamp).total_seconds()
                value = float(state["state"])
                valid = 0 <= age <= 120 and math.isfinite(value)
            except (KeyError, TypeError, ValueError):
                valid, value = False, None
            probe["food" if role == "internal_temp" else "ambient"] = {
                "entity_id": state["entity_id"], "available": valid, "value": value if valid else None,
                "unit": attrs.get("unit_of_measurement"), "sample_time": attrs.get("sample_time"),
            }
    return {"configured": bool(connections), "status": "setup_required" if not connections else "connected" if all(c["state"] == "listening" for c in connections) else "needs_attention",
            "connections": connections, "probes": list(probes.values()), "read_only": True,
            "setup": None if connections else "In Home Assistant, add the CHEF iQ Cloud integration and sign in."}


def register_chef_iq_tools(mcp, ha, annotations, audit):
    @mcp.tool(title="Get CHEF iQ cloud status", annotations=annotations)
    async def get_chef_iq_status() -> dict:
        """Read CHEF iQ connection and setup state; never returns account credentials."""
        result = await snapshot(ha)
        audit("get_chef_iq_status")
        return {key: value for key, value in result.items() if key != "probes"} | {"probe_count": len(result["probes"])}

    @mcp.tool(title="Read CHEF iQ thermometer probes", annotations=annotations)
    async def list_chef_iq_probes() -> dict:
        """Read current food/ambient temperatures, units and freshness. Stale values are null."""
        result = await snapshot(ha)
        audit("list_chef_iq_probes")
        return result
