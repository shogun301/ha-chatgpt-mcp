from copy import deepcopy
from datetime import date, datetime, timedelta
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

import pytest
from jinja2 import Environment, StrictUndefined

from app import sprinkler_schedule as w

FIXTURE = json.loads((Path(__file__).parent / "fixtures/watering-legacy.json").read_text())


def daily_patch(**kw):
    return w.ZonePatch(zone_id="zone-1", periods=[w.Period(start_date="2030-09-08", recurrence="daily")], **kw)


def execute(config, day, trigger="watering_050000", high=90, rain=0, probability=0):
    """Independent miniature HA condition interpreter; actual Jinja, no compiler due()."""
    now = datetime.fromisoformat(day+"T05:00:00")
    env = Environment(undefined=StrictUndefined)
    context = {"now": lambda: now, "trigger": SimpleNamespace(id=trigger),
               "as_datetime": lambda x, default=None: datetime.fromisoformat(x) if x else default,
               "as_local": lambda x:x, "today_at": lambda:now.replace(hour=0), "timedelta":timedelta,
               "is_number": lambda x:isinstance(x,(int,float)),
               "states": lambda x: rain if x in {"sensor.test_rain_today","sensor.test_rain_rate"} else "unknown"}
    commands = []
    def condition(c):
        if c["condition"] == "trigger": return c["id"] == trigger
        return env.from_string(c["value_template"]).render(**context).strip().lower() == "true"
    def actions(items):
        for a in items:
            if "condition" in a:
                if not condition(a): return
            elif "choose" in a:
                chosen = next((c["sequence"] for c in a["choose"] if all(condition(cnd) for cnd in c["conditions"])), a.get("default",[]))
                actions(chosen)
            elif a["action"] == "weather.get_forecasts":
                entity = a["target"]["entity_id"]
                context[a["response_variable"]] = {entity:{"forecast":[{"datetime": now.isoformat(),"temperature":high,"precipitation_probability":probability}]}}
            else: commands.append(a)
    actions(config["actions"])
    return commands


def test_legacy_roundtrip_and_partial_edit():
    before = w.read_model(FIXTURE)
    model, candidate = w.propose(FIXTURE,[daily_patch()])
    assert model["zones"][1:] == before["zones"][1:]
    assert model["policy_template"] == w.definition(FIXTURE)
    assert w.read_model(candidate) == model
    assert "{{" not in json.dumps(candidate["variables"][w.KEY])
    assert "{%" not in json.dumps(candidate["variables"][w.KEY])
    assert FIXTURE["triggers"][0]["at"] == "05:00:00"
    for day,zones in [("2030-09-11",[1,2,3]),("2030-09-12",[1]),("2030-09-13",[1,2,3]),("2030-09-14",[1])]:
        calls=execute(candidate,day)
        assert len(calls)==1
        assert calls[0]["data"]["zones"]==[{"zone":z,"duration_seconds":480} for z in zones]
        assert calls[0]["data"]["source"]=="scheduled"


@pytest.mark.parametrize("high,seconds",[(96,528),(95,480),(85,480),(84,432)])
def test_preserved_temperature_policy(high,seconds):
    _,candidate=w.propose(FIXTURE,[daily_patch()])
    calls=execute(candidate,"2030-09-12",high=high)
    assert calls[0]["data"]["zones"]==[{"zone":1,"duration_seconds":seconds}]


@pytest.mark.parametrize("rain,probability,count",[(0,50,1),(0,51,0),(0.1,0,0),(0,None,1)])
def test_rain_skip_thresholds(rain,probability,count):
    _,candidate=w.propose(FIXTURE,[daily_patch()])
    assert len(execute(candidate,"2030-09-12",rain=rain,probability=probability))==count


def test_weekday_time_runtime_and_second_edit():
    _,first=w.propose(FIXTURE,[daily_patch()])
    model,second=w.propose(first,[w.ZonePatch(zone_id="zone-1",start_time="06:00:00",runtime_seconds=600,periods=[w.Period(start_date="2030-09-01",recurrence="weekdays",weekdays=["mon"])])])
    assert execute(second,"2030-09-09",trigger="watering_060000",high=96)[0]["data"]["zones"]==[{"zone":1,"duration_seconds":660}]
    assert execute(second,"2030-09-10",trigger="watering_060000")==[]
    assert w.read_model(second)==model


@pytest.mark.parametrize("value",[
 {"runtime_seconds":True}, {"runtime_seconds":1.2},{"runtime_seconds":0},{"runtime_seconds":None},
 {"start_time":"25:00:00"},{"start_time":"{{now()}}"},{"enabled":False},
 {"periods":[]}, {"periods":[{"start_date":"2030-02-30","recurrence":"daily"}]},
 {"periods":[{"start_date":"2030-09-01","recurrence":"interval","interval_days":True}]},
 {"periods":[{"start_date":"2030-09-01","recurrence":"weekdays","weekdays":["mon","mon"]}]},
])
def test_invalid_schema(value):
    with pytest.raises(ValueError): w.ZonePatch(zone_id="zone-1",**value)


def test_reject_overlap_unknown_duplicate_and_tampered_source():
    for changes in [[w.ZonePatch(zone_id="zone-1",start_time="05:01:00")], [w.ZonePatch(zone_id="zone-8",runtime_seconds=60)], [daily_patch(),daily_patch()]]:
        with pytest.raises(ValueError): w.propose(FIXTURE,changes)
    bad=deepcopy(FIXTURE);bad["actions"][0]["choose"][0]["sequence"].append({"delay":1})
    with pytest.raises(ValueError):w.read_model(bad)
    _,bad=w.propose(FIXTURE,[daily_patch()]);bad["actions"][0]["value_template"]="{{ true }}"
    with pytest.raises(ValueError):w.read_model(bad)


def server():
    # Reuse the existing suite's isolated, fake-secret environment.
    import tests.test_safety
    from app import server as s
    return s


def test_forecast_allowlist():
    s=server()
    with patch.object(s.config,"AUTOMATION_DAILY_FORECAST_ENTITY","weather.test_temperature"),patch.object(s.config,"AUTOMATION_RAIN_FORECAST_ENTITY","weather.test_rain"):
        s._validate_automation_config(w.definition(FIXTURE),sprinkler_device_id="test-controller")
        for entity,kind in [("weather.unapproved","daily"),("weather.test_rain","daily"),("weather.test_temperature","twice_daily")]:
            bad=deepcopy(FIXTURE);a=bad["actions"][0]["choose"][0]["sequence"][0];a["target"]["entity_id"]=entity;a["data"]["type"]=kind
            with pytest.raises(ValueError):s._validate_automation_config(w.definition(bad),sprinkler_device_id="test-controller")
        assert "get_forecasts" not in s.ALLOWED_SERVICES.get("weather",set())


@pytest.mark.parametrize("failure,expected",[(None,"verified"),("post_timeout","rolled_back"),("third_party","recovery_required"),("pre_write","conflict")])
def test_guarded_transaction(failure,expected):
    s=server(); current=deepcopy(FIXTURE);writes=[];reads=0
    async def get_config(_):
        nonlocal reads
        reads+=1
        if failure=="pre_write" and reads==2: return {**current,"alias":"changed elsewhere"}
        return deepcopy(current)
    async def save(_,value):
        nonlocal current
        writes.append(deepcopy(value));current=deepcopy(value)
        if len(writes)==1 and failure=="post_timeout":raise TimeoutError()
        if len(writes)==1 and failure=="third_party":current["alias"]="another writer"
    state={"entity_id":"automation.test_watering","state":"on","attributes":{"current":0}}
    fake=MagicMock();fake.get_automation_config=AsyncMock(side_effect=get_config);fake.save_automation_config=AsyncMock(side_effect=save);fake.state=AsyncMock(return_value=state);fake.request=AsyncMock(return_value={"time_zone":"America/Los_Angeles"});fake.backup_automations.return_value="retained-test-backup"
    with patch.object(s,"ha",fake),patch.object(s.config,"SPRINKLER_SCHEDULE_ENTITY","automation.test_watering"),patch.object(s.config,"AUTOMATION_DAILY_FORECAST_ENTITY","weather.test_temperature"),patch.object(s.config,"AUTOMATION_RAIN_FORECAST_ENTITY","weather.test_rain"),patch.object(s,"_resolve_automation",AsyncMock(return_value=(state["entity_id"],"test_watering"))),patch.object(s,"_sprinkler_device_id",AsyncMock(return_value="test-controller")),patch.object(s,"list_sprinkler_zones",AsyncMock(return_value={"zones":[{"zone_id":f"zone-{i}","enabled":True} for i in range(1,4)]})),patch.object(s,"get_sprinkler_command_status",AsyncMock(return_value={"pending_command":None,"logical_run":{"state":"idle"},"controller_state":{"state":"idle"}})),patch.object(s,"_audit_tool"):
        token=s.claims_context.set({"scope":"mcp:read mcp:write"})
        try:
            async def run():
                digest=w.fingerprint(w.definition(FIXTURE))
                preview=await s.preview_sprinkler_schedule_update([daily_patch()],digest)
                assert preview["status"]=="validated_no_write" and not writes
                nonlocal reads
                reads=0
                if expected=="conflict":
                    with pytest.raises(ValueError):await s.update_sprinkler_schedule([daily_patch()],digest,True)
                    assert not writes
                else:
                    result=await s.update_sprinkler_schedule([daily_patch()],digest,True)
                    assert result["status"]==expected
                    if expected=="rolled_back":assert current==w.definition(FIXTURE)
                    if expected=="recovery_required":assert len(writes)==1
                fake.call_service.assert_not_called()
            asyncio.run(run())
        finally:s.claims_context.reset(token)


def test_confirmation_and_write_scope_before_access():
    s=server()
    with patch.object(s,"_watering_snapshot",AsyncMock()) as read:
        for scope,confirmed in [("mcp:read",True),("mcp:read mcp:write",False)]:
            token=s.claims_context.set({"scope":scope})
            try:
                with pytest.raises((ValueError,PermissionError)):asyncio.run(s.update_sprinkler_schedule([daily_patch()],"0"*64,confirmed))
                read.assert_not_called()
            finally:s.claims_context.reset(token)


def test_calendar_uses_local_dates_across_month_and_dst():
    model,candidate=w.propose(FIXTURE,[daily_patch()])
    for offset in range(70):
        day=date(2030,9,8)+timedelta(days=offset)
        shared=day<=date(2030,9,11) or (day>=date(2030,9,13) and (day-date(2030,9,13)).days%2==0)
        expected=[1,2,3] if shared else [1]
        commands=execute(candidate,day.isoformat())
        assert len(commands)==1
        assert [z["zone"] for z in commands[0]["data"]["zones"]]==expected
        assert [int(z["zone_id"][-1]) for z in model["zones"] if w.due(z,day)]==expected


def test_stale_hash_rejected_before_backup_or_save():
    s=server()
    with patch.object(s,"_watering_snapshot",AsyncMock(return_value=("automation.test_watering","test_watering",{},deepcopy(FIXTURE)))),patch.object(s,"ha",MagicMock()) as fake:
        with pytest.raises(ValueError,match="changed since read"):
            asyncio.run(s.preview_sprinkler_schedule_update([daily_patch()],"0"*64))
        fake.backup_automations.assert_not_called()
        fake.save_automation_config.assert_not_called()
