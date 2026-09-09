"""Fail-closed compiler for HA-owned, forecast-adjusted ordered watering groups.

No provider calls or filesystem writes. The automation is the only schedule store.
The retained policy template is immutable through the partial-edit interface.
"""
from __future__ import annotations

from copy import deepcopy
import base64
from datetime import date, timedelta
from hashlib import sha256
from itertools import combinations
import json
import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

KEY = "mcp_watering_schedule"
DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class Period(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start_date: Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
    end_date: Annotated[str | None, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")] = None
    recurrence: Literal["daily", "interval", "weekdays"]
    interval_days: Annotated[int | None, Field(strict=True, ge=2, le=366)] = None
    weekdays: list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]] = Field(default_factory=list, max_length=7)

    @model_validator(mode="after")
    def valid(self):
        start = date.fromisoformat(self.start_date)
        if self.end_date and date.fromisoformat(self.end_date) < start:
            raise ValueError("end_date precedes start_date")
        if (self.recurrence == "interval") != (self.interval_days is not None):
            raise ValueError("Only interval recurrence requires interval_days")
        if (self.recurrence == "weekdays") != bool(self.weekdays) or len(set(self.weekdays)) != len(self.weekdays):
            raise ValueError("Only weekdays recurrence requires unique weekday names")
        return self


class ZonePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    zone_id: Annotated[str, Field(pattern=r"^zone-[1-8]$")]
    start_time: Annotated[str | None, Field(pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d:00$")] = None
    runtime_seconds: Annotated[int | None, Field(strict=True, ge=1, le=10800)] = None
    periods: Annotated[list[Period] | None, Field(min_length=1, max_length=8)] = None

    @model_validator(mode="after")
    def valid(self):
        if not self.model_fields_set - {"zone_id"}:
            raise ValueError("At least one changed field is required")
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("Omit unchanged fields; explicit null is not an edit")
        return self


def fingerprint(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def definition(value: dict) -> dict:
    return {k: deepcopy(v) for k, v in value.items() if k != "id"}


def legacy_cadence(start: str, end: str, anchor: str, interval: int) -> str:
    return ("{% set ymd = now().strftime('%Y-%m-%d') %}\n"
            "{% set alternate_start = as_datetime('" + anchor + "').date() %}\n"
            "{{ ('" + start + "' <= ymd <= '" + end + "') or (now().date() >= alternate_start and "
            "((now().date() - alternate_start).days % " + str(interval) + " == 0)) }}")


def _policy(source: dict) -> tuple[dict, list[dict]]:
    """Recognize exactly the preserved group structure; never discard extra actions."""
    assert source.get("mode") == "single" and source.get("conditions") == []
    assert len(source["triggers"]) == 1 and len(source["actions"]) == 1
    trigger = source["triggers"][0]
    assert set(trigger) == {"trigger", "at", "id"} and trigger["trigger"] == "time"
    assert re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d:00", trigger["at"])
    outer = source["actions"][0]
    assert set(outer) == {"choose"} and len(outer["choose"]) == 1
    branch = outer["choose"][0]
    assert set(branch) == {"conditions", "sequence"}
    assert len(branch["conditions"]) == 2
    assert branch["conditions"][0] == {"condition": "trigger", "id": trigger["id"]}
    assert set(branch["conditions"][1]) == {"condition", "value_template"}
    assert branch["conditions"][1]["condition"] == "template"
    seq = branch["sequence"]
    assert len(seq) >= 2 and set(seq[-1]) == {"choose", "default"}
    # Prefix is copied verbatim, including forecast reads and rain conditions.
    assert all(x.get("action") == "weather.get_forecasts" or x.get("condition") == "template" for x in seq[:-1])
    chooser = seq[-1]
    assert len(chooser["choose"]) == 2
    runs = []
    for choice in chooser["choose"]:
        assert set(choice) == {"conditions", "sequence"}
        assert len(choice["conditions"]) == 1 and choice["conditions"][0].get("condition") == "template"
        assert len(choice["sequence"]) == 1
        runs.append(choice["sequence"][0])
    assert len(chooser["default"]) == 1
    runs.append(chooser["default"][0])
    for run in runs:
        assert set(run) == {"action", "data", "target"}
        assert run["action"] == "wyzeapi.run_sprinkler_sequence"
        assert set(run["data"]) <= {"zones", "source", "command_id"}
        assert run["data"].get("source") == "scheduled"
        assert set(run["target"]) == {"device_id"} and run["target"] == runs[0]["target"]
        assert all(set(z) == {"zone", "duration_seconds"} for z in run["data"]["zones"])
        assert [z["zone"] for z in run["data"]["zones"]] == [z["zone"] for z in runs[0]["data"]["zones"]]
    return branch, runs


def read_model(config: dict) -> dict:
    try:
        current = definition(config)
        managed = current.get("variables", {}).get(KEY)
        if managed is not None:
            assert set(managed) == {"version", "zones", "policy_template_b64"} and managed["version"] == 1
            managed = deepcopy(managed)
            managed["policy_template"] = json.loads(base64.b64decode(managed.pop("policy_template_b64"), validate=True))
            assert KEY not in managed["policy_template"].get("variables", {})
            validate_model(managed)
            assert compile_model(managed) == current
            return deepcopy(managed)
        branch, runs = _policy(current)
        text = branch["conditions"][1]["value_template"]
        dates = re.findall(r"'([0-9]{4}-[0-9]{2}-[0-9]{2})'", text)
        interval = int(re.search(r"\.days % (\d+) == 0", text)[1])
        assert len(dates) == 3
        anchor, start, end = dates
        assert text == legacy_cadence(start, end, anchor, interval)
        periods = [Period(start_date=start, end_date=end, recurrence="daily").model_dump(),
                   Period(start_date=anchor, recurrence="interval", interval_days=interval).model_dump()]
        zones = [{"zone_id": f"zone-{z['zone']}", "start_time": current["triggers"][0]["at"],
                  "runtime_seconds": z["duration_seconds"], "periods": deepcopy(periods)} for z in runs[-1]["data"]["zones"]]
        model = {"version": 1, "zones": zones, "policy_template": current}
        validate_model(model)
        return model
    except (AssertionError, KeyError, TypeError, IndexError, AttributeError) as exc:
        raise ValueError("Schedule format is not recognized; no changes were made. Inspect get_automation.") from exc


def validate_model(model: dict) -> None:
    _, runs = _policy(model["policy_template"])
    ids = [f"zone-{z['zone']}" for z in runs[-1]["data"]["zones"]]
    assert 1 <= len(ids) <= 8 and len(ids) == len(set(ids))
    assert [z["zone_id"] for z in model["zones"]] == ids
    for zone in model["zones"]:
        ZonePatch.model_validate(zone)
        periods = [Period.model_validate(p) for p in zone["periods"]]
        previous = None
        for period in periods:
            if previous and (previous.end_date is None or period.start_date <= previous.end_date):
                raise ValueError("Period windows must be ordered and non-overlapping")
            previous = period
    # Conservatively reserve every group's maximum adjusted runtime + handoff buffer,
    # regardless of recurrence, including across midnight. Pause may delay a later run.
    slots: dict[str, int] = {}
    for index, zone in enumerate(model["zones"]):
        maximum = max(_duration(model, index, run) for run in runs)
        slots[zone["start_time"]] = slots.get(zone["start_time"], 0) + maximum + 30
    ordered = sorted((int(t[:2])*3600 + int(t[3:5])*60, total) for t, total in slots.items())
    for index, (start, total) in enumerate(ordered):
        if total > 10800:
            raise ValueError("A group including handoff buffers exceeds 10800 seconds")
        following = ordered[(index + 1) % len(ordered)][0] + (86400 if index == len(ordered)-1 else 0)
        if start + total > following:
            raise ValueError("Start times overlap the maximum weather-adjusted group runtime and handoff buffers")


def _duration(model: dict, index: int, run: dict) -> int:
    _, originals = _policy(model["policy_template"])
    base = originals[-1]["data"]["zones"][index]["duration_seconds"]
    original = run["data"]["zones"][index]["duration_seconds"]
    runtime = model["zones"][index]["runtime_seconds"]
    assert all(type(n) is int and 1 <= n <= 10800 for n in (base, original, runtime))
    # Preserve the existing per-zone multiplier; nearest integer, halves rounded up.
    result = (runtime * original * 2 + base) // (2 * base)
    if not 1 <= result <= 10800:
        raise ValueError("Weather-adjusted runtime is outside 1..10800 seconds")
    return result


def due(zone: dict, day: date) -> bool:
    for p in zone["periods"]:
        if day.isoformat() < p["start_date"] or p["end_date"] and day.isoformat() > p["end_date"]:
            continue
        if p["recurrence"] == "daily": return True
        if p["recurrence"] == "interval" and (day-date.fromisoformat(p["start_date"])).days % p["interval_days"] == 0: return True
        if p["recurrence"] == "weekdays" and DAY_NAMES[day.weekday()] in p["weekdays"]: return True
    return False


def _expression(zone: dict) -> str:
    parts = []
    for p in zone["periods"]:
        terms = [f"now().date().isoformat() >= '{p['start_date']}'"]
        if p["end_date"]: terms.append(f"now().date().isoformat() <= '{p['end_date']}'")
        if p["recurrence"] == "interval": terms.append(f"(now().date() - as_datetime('{p['start_date']}').date()).days % {p['interval_days']} == 0")
        if p["recurrence"] == "weekdays": terms.append(f"now().weekday() in {[DAY_NAMES.index(d) for d in p['weekdays']]}")
        parts.append("(" + " and ".join(terms) + ")")
    return "(" + " or ".join(parts) + ")"


def compile_model(model: dict) -> dict:
    validate_model(model)
    result = deepcopy(model["policy_template"])
    branch, runs = _policy(result)
    prefix = branch["sequence"][:-1]
    weather = branch["sequence"][-1]
    zones = model["zones"]
    expressions = [_expression(z) for z in zones]
    # Once per distinct start time. Each matching subset produces one ordered logical
    # group; no templated service targets/durations and no competing native schedules.
    options = []
    for variant, run in enumerate(runs):
        choices = []
        for time in sorted({z["start_time"] for z in zones}):
            indexes = [i for i, z in enumerate(zones) if z["start_time"] == time]
            for size in range(len(indexes), 0, -1):
                for subset in combinations(indexes, size):
                    condition = " and ".join(("" if i in subset else "not ") + expressions[i] for i in indexes)
                    action = deepcopy(run)
                    action["data"]["zones"] = [{"zone": int(zones[i]["zone_id"][-1]), "duration_seconds": _duration(model, i, run)} for i in subset]
                    # IDs label a group; the integration adds a unique logical-run ID.
                    action["data"]["command_id"] = f"schedule_{time.replace(':', '')}_{variant}_{''.join(str(i+1) for i in subset)}"
                    choices.append({"conditions": [{"condition": "trigger", "id": "watering_"+time.replace(":", "")},
                                                   {"condition": "template", "value_template": "{{ " + condition + " }}"}], "sequence": [action]})
        options.append([{"choose": choices}])
    for index, choice in enumerate(weather["choose"]): choice["sequence"] = options[index]
    weather["default"] = options[-1]
    result["triggers"] = [{"trigger": "time", "at": t, "id": "watering_"+t.replace(":", "")} for t in sorted({z["start_time"] for z in zones})]
    result["actions"] = [{"condition": "template", "value_template": "{{ " + " or ".join(f"(trigger.id == 'watering_{z['start_time'].replace(':', '')}' and {expressions[i]})" for i,z in enumerate(zones)) + " }}"}, *prefix, weather]
    # HA renders nested variable templates at startup. Retain policy as inert data
    # so its forecast/rain templates are evaluated only in their real action order.
    metadata = {"version": 1, "zones": deepcopy(zones), "policy_template_b64": base64.b64encode(json.dumps(model["policy_template"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).decode()}
    result["variables"] = {**result.get("variables", {}), KEY: metadata}
    result["description"] = "HA-managed per-zone watering schedule. Read mcp_watering_schedule or get_sprinkler_schedule for current dates, times and runtimes. Weather policy and ordered-group controls preserved."
    if len(json.dumps(result).encode()) > 65536:
        raise ValueError("Compiled schedule exceeds the automation size limit; simplify periods or groups")
    return result


def propose(config: dict, changes: list[ZonePatch]) -> tuple[dict, dict]:
    model = read_model(config)
    if not 1 <= len(changes) <= 8 or len({p.zone_id for p in changes}) != len(changes):
        raise ValueError("Provide 1..8 unique zone patches")
    for patch in changes:
        matches = [z for z in model["zones"] if z["zone_id"] == patch.zone_id]
        if len(matches) != 1: raise ValueError("Zone is not present in this scheduling source")
        matches[0].update(patch.model_dump(exclude_unset=True))
        matches[0]["periods"] = [Period.model_validate(p).model_dump() for p in matches[0]["periods"]]
    candidate = compile_model(model)
    return model, candidate


def public_plan(model: dict, start: date, days: int = 14) -> dict:
    _, runs = _policy(model["policy_template"])
    return {"zones": deepcopy(model["zones"]),
            "weather_adjusted_runtimes": [{"zone_id": z["zone_id"], "variant_seconds": [_duration(model,i,r) for r in runs]} for i,z in enumerate(model["zones"])],
            "weather_policy": deepcopy(model["policy_template"]["actions"][0]["choose"][0]["sequence"][:-1]),
            "temperature_conditions": [deepcopy(c["conditions"]) for c in model["policy_template"]["actions"][0]["choose"][0]["sequence"][-1]["choose"]],
            "calendar": [{"date": (start+timedelta(days=d)).isoformat(), "groups": [{"start_time": t, "zone_ids": [z["zone_id"] for z in model["zones"] if z["start_time"] == t and due(z,start+timedelta(days=d))]} for t in sorted({z["start_time"] for z in model["zones"] if due(z,start+timedelta(days=d))})]} for d in range(days)],
            "note": "Calendar eligibility only; weather is evaluated on the run day. Paused/active groups may prevent a later start. No native Wyze schedule is changed."}
