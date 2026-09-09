"""Regression coverage for the existing live read-only tools retained in this release."""
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock

from app.chefiq import snapshot


def test_only_registered_fresh_probe_values_are_returned():
    now=datetime.now(timezone.utc)
    ha=AsyncMock()
    ha.entity_registry.return_value=[{"entity_id":"sensor.food","platform":"chefiq_cloud"},{"entity_id":"sensor.ambient","platform":"chefiq_cloud"}]
    ha.states.return_value=[
        {"entity_id":"sensor.food","state":"145","attributes":{"role":"internal_temp","probe_id":"probe_test","sample_time":now.isoformat(),"unit_of_measurement":"F","private_field":"omit"}},
        {"entity_id":"sensor.ambient","state":"300","attributes":{"role":"ambient_temp","probe_id":"probe_test","sample_time":(now-timedelta(seconds=121)).isoformat(),"unit_of_measurement":"F"}},
        {"entity_id":"sensor.unrelated","state":"secret","attributes":{"role":"internal_temp","probe_id":"probe_other"}},
    ]
    result=asyncio.run(snapshot(ha))
    assert result["read_only"] is True and len(result["probes"])==1
    assert result["probes"][0]["food"]["value"]==145
    assert result["probes"][0]["ambient"]["value"] is None
    assert "private_field" not in str(result) and "secret" not in str(result)
    ha.call_service.assert_not_called()
