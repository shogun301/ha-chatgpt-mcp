"""Home Assistant persistence, history, and API adapter for export events."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import partial
from http import HTTPStatus
from typing import Any, Final

import voluptuous as vol
from aiohttp import web
from homeassistant.components import websocket_api
from homeassistant.components.recorder import get_instance as get_recorder_instance
from homeassistant.components.recorder import history
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, State, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.event import async_track_point_in_utc_time
from homeassistant.helpers.http import KEY_HASS, HomeAssistantView
from homeassistant.helpers.storage import Store

from .const import DOMAIN
from .coordinator import SolarEdgeBridgeCoordinator
from .export_events import (
    BATTERY_TO_GRID,
    BATTERY_TO_GRID_DURATION_SECONDS,
    CSV_COLUMNS,
    EVENT_SCHEMA_VERSION,
    EXPORT_WITH_HEADROOM,
    EXPORT_WITH_HEADROOM_DURATION_SECONDS,
    EventTransition,
    ExportEventEngine,
    ExportSample,
    OperatingPlanSnapshot,
    event_csv,
    public_event,
    select_event,
)
from .model import SolarEdgeSnapshot

_LOGGER = logging.getLogger(__name__)

EVENT_QUALIFIED: Final = "solaredge_export_event_qualified"
EVENT_COMPLETED: Final = "solaredge_export_event_completed"
CSV_URL: Final = "/api/solaredge_one_bridge/export_events.csv"
DETAIL_ROUTE: Final = "/power-energy/export-events"
STORE_VERSION: Final = 1
HISTORY_LOOKBACK: Final = timedelta(days=31)
ACTIVE_RECOVERY_MAX_AGE: Final = timedelta(minutes=15)

DATA_MANAGERS: Final = "export_event_managers"
DATA_APIS_REGISTERED: Final = "export_event_apis_registered"

METRIC_TO_SAMPLE_FIELD: Final = {
    "grid_export_power_w": "grid_export_power_w",
    "grid_export_energy_kwh": "grid_export_energy_kwh",
    "battery_state_of_energy_pct": "soc_pct",
    "battery_charge_power_w": "battery_charge_power_w",
    "battery_discharge_power_w": "battery_discharge_power_w",
    "production_power_w": "production_power_w",
    "consumption_power_w": "consumption_power_w",
}


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def _state_number(state: State | None) -> float | None:
    if state is None or state.state in {"unknown", "unavailable", "none", ""}:
        return None
    try:
        return float(state.state)
    except (TypeError, ValueError):
        return None


def _snapshot_sample(
    snapshot: SolarEdgeSnapshot,
    *,
    at: datetime | None = None,
    source: str = "live",
) -> ExportSample:
    observed = _parse_timestamp(snapshot.observed_at) or datetime.now(UTC)
    sample_at = at or observed

    def value(key: str) -> float | None:
        if not snapshot.connected:
            return None
        return snapshot.value(key)

    return ExportSample(
        at=sample_at,
        grid_export_power_w=value("grid_export_power_w"),
        grid_export_energy_kwh=value("grid_export_energy_kwh"),
        soc_pct=value("battery_state_of_energy_pct"),
        battery_charge_power_w=value("battery_charge_power_w"),
        battery_discharge_power_w=value("battery_discharge_power_w"),
        production_power_w=value("production_power_w"),
        consumption_power_w=value("consumption_power_w"),
        operating_plan=OperatingPlanSnapshot(
            state=snapshot.storage_operating_plan if snapshot.connected else None,
            active=snapshot.storage_operating_plan_active
            if snapshot.connected
            else None,
            block_count=snapshot.storage_operating_plan_block_count
            if snapshot.connected
            else None,
            provider=snapshot.provider,
            observed_at=snapshot.observed_at,
            completeness=snapshot.completeness.get("storage_operating_plan"),
        ),
        source="reconstructed" if source == "reconstructed" else "live",
    )


def _entity_ids(hass: HomeAssistant) -> dict[str, str]:
    registry = er.async_get(hass)
    result: dict[str, str] = {}
    for metric in (*METRIC_TO_SAMPLE_FIELD, "storage_operating_plan"):
        entity_id = registry.async_get_entity_id("sensor", DOMAIN, f"{DOMAIN}_{metric}")
        if entity_id is not None:
            result[metric] = entity_id
    return result


def _history_samples(
    raw_history: dict[str, list[State | dict[str, Any]]],
    entity_ids: dict[str, str],
    start: datetime,
    end: datetime,
) -> list[ExportSample]:
    """Align recorder rows by the bridge's shared provider observation time."""
    observations: dict[str, dict[str, State]] = {}
    by_entity_id = {value: key for key, value in entity_ids.items()}
    for entity_id, rows in raw_history.items():
        metric = by_entity_id.get(entity_id)
        if metric is None:
            continue
        for row in rows:
            if not isinstance(row, State):
                continue
            observed_at = row.attributes.get("observed_at")
            observed = _parse_timestamp(observed_at)
            if observed is None or not start <= observed <= end:
                continue
            normalized = observed.isoformat()
            observations.setdefault(normalized, {})[metric] = row

    samples: list[ExportSample] = []
    for observed_at, states in sorted(observations.items()):
        observed = _parse_timestamp(observed_at)
        if observed is None:
            continue
        plan_state = states.get("storage_operating_plan")
        plan_attributes = plan_state.attributes if plan_state is not None else {}
        provider = plan_attributes.get("provider")
        completeness = plan_attributes.get("completeness")
        plan = OperatingPlanSnapshot(
            state=plan_state.state
            if plan_state is not None
            and plan_state.state not in {"unknown", "unavailable"}
            else None,
            active=plan_attributes.get("active")
            if isinstance(plan_attributes.get("active"), bool)
            else None,
            block_count=plan_attributes.get("block_count")
            if isinstance(plan_attributes.get("block_count"), int)
            and not isinstance(plan_attributes.get("block_count"), bool)
            else None,
            provider=provider if isinstance(provider, str) else None,
            observed_at=observed_at,
            completeness=completeness if isinstance(completeness, bool) else None,
        )
        values = {
            target: _state_number(states.get(metric))
            for metric, target in METRIC_TO_SAMPLE_FIELD.items()
        }
        samples.append(
            ExportSample(
                at=observed,
                operating_plan=plan,
                source="reconstructed",
                **values,
            )
        )
    return samples


class ExportEventManager:
    """Own one config entry's durable event model and recovery lifecycle."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        coordinator: SolarEdgeBridgeCoordinator,
    ) -> None:
        self.hass = hass
        self.entry = entry
        self.coordinator = coordinator
        self.store: Store[dict[str, Any]] = Store(
            hass,
            STORE_VERSION,
            f"{DOMAIN}.export_events.{entry.entry_id}",
            private=True,
            atomic_writes=True,
        )
        self.engine = ExportEventEngine(entry.entry_id)
        self.reconstruction_coverage: dict[str, Any] = {
            "start_at": None,
            "end_at": None,
            "quality": "not-yet-imported",
        }
        self._lock = asyncio.Lock()
        self._coordinator_unsub: Callable[[], None] | None = None
        self._deadline_unsubs: list[Callable[[], None]] = []

    async def async_initialize(self) -> None:
        """Load atomic storage, recover/import recorder history, then listen."""
        stored = await self.store.async_load() or {}
        completed = stored.get("completed_events", [])
        open_event = stored.get("open_event")
        self.engine = ExportEventEngine(
            self.entry.entry_id,
            completed_events=completed if isinstance(completed, list) else [],
            open_event=open_event if isinstance(open_event, dict) else None,
            grid_export_since=stored.get("grid_export_since"),
            evaluated_deadlines=stored.get("evaluated_deadlines"),
            last_sample=stored.get("last_sample")
            if isinstance(stored.get("last_sample"), dict)
            else None,
        )
        coverage = stored.get("reconstruction_coverage")
        if isinstance(coverage, dict):
            self.reconstruction_coverage = coverage
        self.engine.mark_recovered_after_restart()
        await self._async_reconstruct_history()
        await self.async_process_snapshot(self.coordinator.data)
        await self._async_recover_overdue_deadlines()
        self._coordinator_unsub = self.coordinator.async_add_listener(
            self._coordinator_updated
        )

    @callback
    def _coordinator_updated(self) -> None:
        self.hass.async_create_background_task(
            self.async_process_snapshot(
                self.coordinator.data if self.coordinator.last_update_success else None
            ),
            f"{DOMAIN} export event sample",
            eager_start=True,
        )

    async def async_shutdown(self) -> None:
        """Stop listeners/timers and synchronously flush the current state."""
        if self._coordinator_unsub is not None:
            self._coordinator_unsub()
            self._coordinator_unsub = None
        self._cancel_deadlines()
        async with self._lock:
            await self._async_save()

    async def async_process_snapshot(self, snapshot: SolarEdgeSnapshot | None) -> None:
        """Persist every synchronized update, including open candidates."""
        sample = (
            _snapshot_sample(snapshot)
            if snapshot is not None
            else ExportSample(at=datetime.now(UTC))
        )
        async with self._lock:
            transitions = self.engine.process(sample)
            await self._async_save()
            self._reschedule_deadlines()
        self._fire_transitions(transitions)

    async def _async_deadline(self, at: datetime) -> None:
        """Evaluate current held values at the original automation's wall clock."""
        sample = self._current_sample(at=at)
        async with self._lock:
            transitions = self.engine.evaluate_deadline(sample, at=at)
            await self._async_save()
            self._reschedule_deadlines()
        self._fire_transitions(transitions)

    async def _async_recover_overdue_deadlines(self) -> None:
        """Evaluate a deadline missed while HA was down using held current values."""
        export_since = _parse_timestamp(self.engine.grid_export_since)
        if export_since is None:
            return
        now = datetime.now(UTC)
        transitions = []
        async with self._lock:
            for rule, seconds in (
                (BATTERY_TO_GRID, BATTERY_TO_GRID_DURATION_SECONDS),
                (EXPORT_WITH_HEADROOM, EXPORT_WITH_HEADROOM_DURATION_SECONDS),
            ):
                deadline = export_since + timedelta(seconds=seconds)
                if rule in self.engine.evaluated_deadlines or deadline > now:
                    continue
                sample = self._current_sample(at=deadline)
                transitions.extend(self.engine.evaluate_deadline(sample, at=deadline))
            await self._async_save()
            self._reschedule_deadlines()
        self._fire_transitions(transitions)

    def _current_sample(self, *, at: datetime) -> ExportSample:
        """Return held current data only after a successful coordinator refresh."""
        if not self.coordinator.last_update_success:
            return ExportSample(at=at)
        return _snapshot_sample(self.coordinator.data, at=at)

    def _cancel_deadlines(self) -> None:
        while self._deadline_unsubs:
            self._deadline_unsubs.pop()()

    def _reschedule_deadlines(self) -> None:
        self._cancel_deadlines()
        export_since = _parse_timestamp(self.engine.grid_export_since)
        if export_since is None:
            return
        now = datetime.now(UTC)
        for rule, seconds in (
            (BATTERY_TO_GRID, BATTERY_TO_GRID_DURATION_SECONDS),
            (EXPORT_WITH_HEADROOM, EXPORT_WITH_HEADROOM_DURATION_SECONDS),
        ):
            if rule in self.engine.evaluated_deadlines:
                continue
            deadline = export_since + timedelta(seconds=seconds)
            if deadline <= now:
                continue
            self._deadline_unsubs.append(
                async_track_point_in_utc_time(
                    self.hass,
                    self._async_deadline,
                    deadline,
                )
            )

    async def _async_save(self) -> None:
        await self.store.async_save(
            {
                "event_schema_version": EVENT_SCHEMA_VERSION,
                "completed_events": self.engine.completed_events,
                "open_event": self.engine.open_event,
                "grid_export_since": self.engine.grid_export_since,
                "evaluated_deadlines": sorted(self.engine.evaluated_deadlines),
                "last_sample": self.engine.last_sample,
                "reconstruction_coverage": self.reconstruction_coverage,
            }
        )

    async def _async_reconstruct_history(self) -> None:
        ids = _entity_ids(self.hass)
        if "grid_export_power_w" not in ids or "battery_state_of_energy_pct" not in ids:
            self.reconstruction_coverage["quality"] = "required-entities-not-registered"
            return
        now = datetime.now(UTC)
        # Replay the full bounded reliable window. Event IDs are derived from the
        # true candidate start, so this remains idempotent even for long events
        # that would cross a short incremental-overlap boundary.
        start = now - HISTORY_LOOKBACK
        try:
            raw = await get_recorder_instance(self.hass).async_add_executor_job(
                partial(
                    history.get_significant_states,
                    self.hass,
                    start,
                    now,
                    entity_ids=list(ids.values()),
                    include_start_time_state=True,
                    significant_changes_only=False,
                    minimal_response=False,
                    no_attributes=False,
                )
            )
        except (KeyError, RuntimeError) as err:
            _LOGGER.warning(
                "SolarEdge export-event history recovery unavailable: %s", err
            )
            self.reconstruction_coverage["quality"] = "recorder-unavailable"
            return
        samples = _history_samples(raw, ids, start, now)
        if not samples:
            self.reconstruction_coverage["quality"] = "no-aligned-history"
            return

        # First replay new rows into a stored open event so an outage cannot lose
        # a qualification or completion that occurred while HA was restarting.
        recovery_transitions = []
        if self.engine.open_event is not None:
            for sample in samples:
                recovery_transitions.extend(self.engine.process(sample))

        reconstructed = ExportEventEngine(self.entry.entry_id)
        for sample in samples:
            reconstructed.process(sample)
        self.engine.import_completed(reconstructed.completed_events)
        if (
            self.engine.open_event is None
            and reconstructed.open_event is not None
            and now - samples[-1].at <= ACTIVE_RECOVERY_MAX_AGE
        ):
            self.engine.open_event = reconstructed.open_event
            self.engine.grid_export_since = reconstructed.grid_export_since
            self.engine.evaluated_deadlines = reconstructed.evaluated_deadlines
            self.engine.last_sample = reconstructed.last_sample
            if reconstructed.open_event.get("qualified_at") is not None:
                recovery_transitions.append(
                    EventTransition(
                        "qualified",
                        public_event(reconstructed.open_event),
                        samples[-1],
                    )
                )

        self.reconstruction_coverage = {
            "start_at": samples[0].at.astimezone(UTC).isoformat(),
            "end_at": samples[-1].at.astimezone(UTC).isoformat(),
            "quality": "aligned-provider-observations",
        }
        await self._async_save()
        self._fire_transitions(recovery_transitions)

    def _fire_transitions(self, transitions: list[Any]) -> None:
        for transition in transitions:
            event = transition.event
            event_id = event["event_id"]
            route = f"{DETAIL_ROUTE}?event_id={event_id}"
            sample = transition.sample
            payload: dict[str, Any] = {
                "schema_version": EVENT_SCHEMA_VERSION,
                "event_id": event_id,
                "status": event["status"],
                "classification": event["classification"],
                "candidate_start": event["candidate_start"],
                "qualified_at": event["qualified_at"],
                "end_at": event["end_at"],
                "grid_export_power_w": sample.grid_export_power_w,
                "soc_pct": sample.soc_pct,
                "battery_charge_power_w": sample.battery_charge_power_w,
                "battery_discharge_power_w": sample.battery_discharge_power_w,
                "storage_operating_plan": sample.operating_plan.as_dict(),
                "route": route,
                "url": route,
                "clickAction": route,
                "notification_tag": f"solaredge-export-{event_id}",
            }
            if transition.kind == "completed":
                payload.update(
                    {
                        "total_duration_seconds": event["total_duration_seconds"],
                        "exported_energy_kwh": event["exported_energy_kwh"],
                        "export_energy_method": event["export_energy_method"],
                        "export_energy_quality": event["export_energy_quality"],
                        "ending_soc_pct": event["statistics"]["soc_pct"]["end"],
                    }
                )
            self.hass.bus.async_fire(
                EVENT_QUALIFIED if transition.kind == "qualified" else EVENT_COMPLETED,
                payload,
            )

    async def async_events(self, *, include_samples: bool) -> list[dict[str, Any]]:
        async with self._lock:
            events = [
                public_event(event, include_samples=include_samples)
                for event in self.engine.completed_events
            ]
            if (
                self.engine.open_event is not None
                and self.engine.open_event.get("qualified_at") is not None
            ):
                events.append(
                    public_event(
                        self.engine.open_event, include_samples=include_samples
                    )
                )
        return events


def _managers(hass: HomeAssistant) -> list[ExportEventManager]:
    return list(hass.data.get(DOMAIN, {}).get(DATA_MANAGERS, {}).values())


async def _all_events(
    hass: HomeAssistant, *, include_samples: bool
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for manager in _managers(hass):
        events.extend(await manager.async_events(include_samples=include_samples))
    return sorted(events, key=lambda event: event.get("candidate_start") or "")


@websocket_api.websocket_command(
    {
        vol.Required("type"): f"{DOMAIN}/export_events/list",
        vol.Optional("status"): vol.In(("active", "completed")),
        vol.Optional("limit", default=100): vol.All(int, vol.Range(min=1, max=500)),
    }
)
@websocket_api.async_response
async def websocket_list_export_events(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Return bounded event summaries to an authenticated WebSocket user."""
    events = await _all_events(hass, include_samples=False)
    if status := msg.get("status"):
        events = [event for event in events if event.get("status") == status]
    events = list(reversed(events))[: msg["limit"]]
    active = next(
        (event["event_id"] for event in events if event.get("status") == "active"),
        None,
    )
    completed = next(
        (event["event_id"] for event in events if event.get("status") == "completed"),
        None,
    )
    managers = _managers(hass)
    connection.send_result(
        msg["id"],
        {
            "schema_version": EVENT_SCHEMA_VERSION,
            "events": events,
            "active_event_id": active,
            "most_recent_completed_event_id": completed,
            "reconstruction_coverage": managers[0].reconstruction_coverage
            if managers
            else None,
        },
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): f"{DOMAIN}/export_events/get",
        vol.Optional("event_id"): str,
    }
)
@websocket_api.async_response
async def websocket_get_export_event(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Return one full event with a nonfatal invalid-ID fallback."""
    events = await _all_events(hass, include_samples=True)
    requested = msg.get("event_id")
    selected, message = select_event(events, requested)
    connection.send_result(
        msg["id"],
        {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event": selected,
            "requested_event_id": requested,
            "resolved_event_id": selected.get("event_id") if selected else None,
            "message": message,
        },
    )


class ExportEventsCsvView(HomeAssistantView):
    """Authenticated CSV download backed by the same WebSocket event values."""

    url = CSV_URL
    name = "api:solaredge_one_bridge:export_events_csv"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app[KEY_HASS]
        events = await _all_events(hass, include_samples=True)
        requested = request.query.get("event_id")
        if requested:
            events = [event for event in events if event.get("event_id") == requested]
            if not events:
                return self.json_message(
                    "Export event not found",
                    status_code=HTTPStatus.NOT_FOUND,
                    message_code="event_not_found",
                )
        csv_text = event_csv(events, hass.config.time_zone)
        filename = (
            f"solaredge-export-event-{requested}.csv"
            if requested
            else "solaredge-export-events.csv"
        )
        return web.Response(
            text=csv_text,
            content_type="text/csv",
            charset="utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


def async_register_export_event_apis(hass: HomeAssistant) -> None:
    """Register global handlers once; handlers resolve the current manager."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get(DATA_APIS_REGISTERED):
        return
    websocket_api.async_register_command(hass, websocket_list_export_events)
    websocket_api.async_register_command(hass, websocket_get_export_event)
    hass.http.register_view(ExportEventsCsvView())
    domain_data[DATA_APIS_REGISTERED] = True


async def async_setup_export_event_manager(
    hass: HomeAssistant,
    entry: ConfigEntry,
    coordinator: SolarEdgeBridgeCoordinator,
) -> ExportEventManager:
    """Create, initialize, and register an entry manager."""
    async_register_export_event_apis(hass)
    manager = ExportEventManager(hass, entry, coordinator)
    hass.data.setdefault(DOMAIN, {}).setdefault(DATA_MANAGERS, {})[entry.entry_id] = (
        manager
    )
    try:
        await manager.async_initialize()
    except Exception:
        hass.data[DOMAIN][DATA_MANAGERS].pop(entry.entry_id, None)
        raise
    return manager


async def async_unload_export_event_manager(hass: HomeAssistant, entry_id: str) -> None:
    """Flush and unregister an entry manager while leaving global APIs valid."""
    manager = hass.data.get(DOMAIN, {}).get(DATA_MANAGERS, {}).pop(entry_id, None)
    if manager is not None:
        await manager.async_shutdown()


__all__ = [
    "CSV_COLUMNS",
    "CSV_URL",
    "EVENT_COMPLETED",
    "EVENT_QUALIFIED",
    "ExportEventManager",
    "async_setup_export_event_manager",
    "async_unload_export_event_manager",
]
