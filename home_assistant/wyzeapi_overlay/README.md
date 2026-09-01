# Wyze sprinkler Home Assistant overlay

This directory is a deterministic, sprinkler-only overlay for the installed
`custom_components/wyzeapi` integration. It adds normalized read surfaces,
four response-only Home Assistant services, and seven bounded sprinkler command
services.

The two run services accept exactly one of `duration_seconds` or the legacy
`duration_minutes`. Seconds must be an exact integer from 1 through 10800;
legacy decimal minutes are rounded to the nearest second before construction.
Home Assistant owns every logical run timer and ordered queue, commands only the
current zone, and issues stop at the requested duration. Pause captures the
current-zone remainder and queue; resume restarts that remainder before the
queued zones; skip advances only a dashboard-owned multi-zone run; stop
abandons the entire run before touching the provider. The
coordinator requires affirmative idle before starting or advancing: either
controller-reported idle or a controller-reported `past`/finished schedule run.
Truly unknown watering state remains fail-closed and does not send a provider
command.

## Base guard

The overlay was authored against a private captured installation snapshot of
`custom_components/wyzeapi`. No workstation-specific path is part of this
public source artifact.

The base manifest reports version `0.1.39` and SHA-256
`8C1551778463D995413F6A71739ADC53D820DED0CB069EF08E7DBB7A6395F1BC`.
The overlay replaces it with version `0.1.45` so deployed source has a visible,
deterministic integration identity.
Before deployment, require all replacement-file hashes below to match the
destination. A mismatch is a stop-and-reinspect concurrency guard; do not copy
the overlay over a divergent integration.

| Replacement file | Required base SHA-256 |
| --- | --- |
| `manifest.json` | `8C1551778463D995413F6A71739ADC53D820DED0CB069EF08E7DBB7A6395F1BC` |
| `__init__.py` | `52D31F80DF2D79AC76A258624917DB1F06609C32801F9418C7D09063AE4F2815` |
| `const.py` | `651997A054D7DD1CFBAB902917D598D1BD2C31578DDDE529EDFE803DE24B56FC` |
| `irrigation.py` | `C1E0F1AB419B704BEC9566BCD19F4DEB16A18052FDEE23E62336D8A09A239854` |
| `irrigation_data.py` | `9F59596EB839D6C6ACE8D2B04C2B9593064B1B1CD767E4647EF3A4E8950A0591` |
| `sensor.py` | `3AF7296A87C8B0EA0CDE2E98CE6A05BA81846FE8631D8DD09E5B1954E62DAC15` |
| `services.yaml` | `F69AF27ABBF54435C1A978DBF791F8CDA8D8500187FE4067EE90C18D661A2950` |

An upgrade from the immediately preceding overlay 0.1.44 accepts only this
second exact hash set. These are the tracked 0.1.44 blobs from the public source
commit; accepting them does not broaden the destination-file guard.

| Replacement file | Required 0.1.44 predecessor SHA-256 |
| --- | --- |
| `manifest.json` | `AA5EFC126CF1A42AC4157FBF64AB361446A30E4B2ED73FC2EBB4A4D4C9C614F1` |
| `__init__.py` | `0AABDD062C99D056546F4AE1EC779502A679FF863F51F279C5960762F93A0C67` |
| `const.py` | `45011A7119E381FF2E5E4DB2DCECDD6B43CB2B62B97F170A88912B3F590A2CAA` |
| `irrigation.py` | `12E20B7A600416910FD2580FD6F236FD91F2D18FF81153ED203ABBDB1C205313` |
| `irrigation_data.py` | `917FA0D0E90EA5314118F1ACDAAFA96F82E2DF4C5B544D246BFE2C5D62CFC38D` |
| `sensor.py` | `3083870E8EA5D872097C78D31D383410F97C434CECB6021D781AC0DBABE9CB03` |
| `services.yaml` | `DD2DA1FEF54E4690EB5764D00A7F21F781327D5D0B2A08568C83F2EA0F5CE216` |

Only those seven files are replaced. Back up the exact destination files first,
copy the overlay into `custom_components/wyzeapi`, run an explicit Python syntax
check and Home Assistant configuration check, then perform a full Home Assistant
process/container restart. A config-entry reload is not sufficient after Python
modules are copied because imported module objects can remain cached. Read the
registered service descriptions and invoke only the four read services during
acceptance. Never run a zone, sequence, or completed automation as a test.

## Response services

- `wyzeapi.get_sprinkler_snapshot`: exact device target; returns the current
  normalized coordinator snapshot and performs no network request.
- `wyzeapi.get_sprinkler_schedule_runs`: exact device target; accepts `limit`
  from 1 through 100 and fetches the private schedule-runs endpoint.
- `wyzeapi.get_sprinkler_schedules`: exact device target; uses a signed private
  GET of `/plugin/irrigation/schedule` with only `device_id` and `nonce`, then
  returns allowlisted definition fields.
- `wyzeapi.get_sprinkler_capabilities`: exact device target; returns a static
  supported/unsupported contract and performs no network request.

Each service is registered with `SupportsResponse.ONLY`. Timestamps are emitted
as UTC ISO-8601 strings only when Wyze supplies an epoch or explicit UTC offset.
Naive local time strings are omitted and accompanied by an explicit unsupported
timestamp-ambiguity record. Watering, active-zone, and remaining-time values are
labelled as controller-reported, calculated, inferred, or reconstructed. The
local command latch is labelled commanded. Configured `flow_rate` is explicitly
configuration data and never represented as measured flow. No returned state is
described as physical valve feedback.

Pending command status contains a bounded correlation ID, action, issued and
expiry timestamps, normalized zone/duration inputs, and evidence label. Start
commands reconcile only after watering is observed or the latch times out. Stop
remains pending until a controller poll reports idle or the latch times out;
none of these states claims physical valve confirmation.

This overlay is derived from `SecKatie/ha-wyzeapi`, licensed under Apache-2.0.
Retain `UPSTREAM_LICENSE`, `NOTICE`, and the source modification notices when
copying or redistributing the overlay. The two attribution files are source
distribution assets; the seven guarded runtime files are copied into the custom
component directory.

| Attribution asset | Overlay SHA-256 |
| --- | --- |
| `UPSTREAM_LICENSE` | `074E6E32C86A4C0EF8B3ED25B721CA23ACA83DF277CD88106EF7177C354615FF` |
| `NOTICE` | `9BF747BDE395E8090DAE15FAB014D3570578F6F0695A64D15389933ECED4BE8B` |

The existing per-zone metadata entity IDs are retained. Their attributes use an
explicit allowlist covering the normalized native zone ID, wired state,
irrigation-model configuration, configured flow labels, modeled moisture label,
and at most ten normalized recent zone events.

## Deliberate limits

This overlay does not add schedule writes, schedule enable/disable, native
schedule manual-run, weather-data guesses, physical valve feedback, measured
flow, electrical-load feedback, or physical soil-moisture claims. The static
capability service returns explicit unsupported records for these missing
signals and operations.
