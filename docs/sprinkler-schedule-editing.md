# HA-owned sprinkler schedules

Use `get_sprinkler_schedule` for the authoritative automation definition, local timezone,
version hash, per-zone base runtimes, period windows, and 14-day eligibility calendar.
Controller duration controls and native Wyze schedules are separate sources and are
not modified by these tools. Weather decisions are evaluated on the actual run day.

1. Reread `get_sprinkler_schedule` before every change. Do not infer dates from old chat.
2. Call `preview_sprinkler_schedule_update(changes, expected_sha256)` using the read hash.
   This tool is read-only; it validates the complete result and returns a proposed plan.
3. For an explicitly authorized edit, call `update_sprinkler_schedule` with the same
   changes/hash and `confirmed: true`. An explicit user instruction naming the change
   supplies confirmation; never apply another pending request as a capability test.
4. Require `status: verified`, then reread `get_sprinkler_schedule`. Compare the requested
   zone fields and untouched zones, weather policy and enablement with the prior read.
   Never start watering or trigger an automation merely to verify an edit.

`changes` contains unique `zone_id` entries (`zone-1` etc). Omit unchanged fields and zones:

* `start_time`: local `HH:MM:00`, the group's start. Zones sharing a start run in existing
  zone order; later zones begin after preceding zones, not simultaneously.
* `runtime_seconds`: integer base seconds. The original per-zone weather multipliers
  are preserved and adjusted seconds round to the nearest integer, halves upwards.
* `periods`: replaces only this zone's complete list of non-overlapping ordered windows.
  Each has `start_date`, optional inclusive `end_date`, and `recurrence`: `daily`,
  `interval` (requires `interval_days`, anchored at start_date), or `weekdays`
  (requires unique `mon` through `sun` names). Gaps are non-watering dates.

For example, an authorized weekday-only change can patch one zone's periods while
omitting its runtime and start time. Use real dates from the current request; never
copy example dates into production. Empty, null, unknown or duplicate fields are rejected.

Writes require OAuth write scope, explicit confirmation, an idle controller and no
active/paused logical run. The server backs up automation files before saving, rechecks
the hash and enablement immediately before the write, and verifies the full readback.
A failed/uncertain save is inspected before recovery. An intact candidate may be restored
to the original; a third-party/unknown definition is never overwritten. `rolled_back`,
`original_verified` and `recovery_required` are failures, not successful edits. They include
the retained backup reference. Do not blindly retry or use generic editing to defeat guards.
Direct HA edits do not participate in the server lock, so users should avoid editing the
same automation simultaneously. An external change in the final REST race cannot be
made atomic because HA does not provide conditional automation writes.

The first real edit migrates a recognized legacy definition into a versioned per-zone
representation inside the same automation. Its policy template is encoded as inert data
to prevent premature template evaluation. Literal HA actions are compiled from this
source; later reads verify the complete generated definition. Unrecognized/drifted
definitions fail closed. The Effective Watering Plan can read these same per-zone fields
and policy data from the automation; no secondary scheduler is introduced.

Distinct start times reserve the worst-case adjusted runtimes plus handoff buffers.
A pause that extends into a later group may prevent that later start; the existing
controller overlap protections remain authoritative. No automatic catch-up is introduced.

Deployment settings: `SPRINKLER_SCHEDULE_ENTITY` selects one exact existing automation;
`AUTOMATION_DAILY_FORECAST_ENTITY` permits that exact daily target, while
`AUTOMATION_RAIN_FORECAST_ENTITY` permits only that exact twice-daily target.
Generic weather service calls, unrelated targets, dynamic targets and all other access
restrictions remain unchanged. The deployment script accepts the optional rain and
schedule entities, tests them in the isolated preflight container, and preserves/backs
up the prior runtime environment before applying them with the release.

After deployment refresh the existing ChatGPT connection's action catalog if these
three tools are absent, then use a fresh conversation if the old one retains cached
schemas. Deployment and local fixture success are not end-to-end ChatGPT acceptance.

Syntax references: [HA script syntax](https://www.home-assistant.io/docs/scripts/) and
[HA weather actions](https://www.home-assistant.io/integrations/weather/).
