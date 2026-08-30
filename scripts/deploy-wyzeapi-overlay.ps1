param(
    [Parameter(Mandatory)][string]$AwsProfile,
    [Parameter(Mandatory)][string]$AwsRegion,
    [Parameter(Mandatory)][string]$InstanceName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ReleaseCommit
)

$ErrorActionPreference = 'Stop'

$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$overlayPath = 'home_assistant/wyzeapi_overlay'
$gitExe = (Get-Command git -ErrorAction Stop).Source
$awsExe = (Get-Command aws -ErrorAction Stop).Source
$sshExe = (Get-Command ssh -ErrorAction Stop).Source
$scpExe = (Get-Command scp -ErrorAction Stop).Source
$status = (& $gitExe -C $sourceRoot status --porcelain=v1 --untracked-files=all) -join "`n"
if ($LASTEXITCODE -ne 0 -or $status) {
    throw 'Wyze overlay deployment requires a clean Git checkout.'
}
$headCommit = ((& $gitExe -C $sourceRoot rev-parse HEAD) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or $headCommit -ne $ReleaseCommit) {
    throw 'Wyze overlay deployment must use the exact checked-out release commit.'
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempDir = Join-Path $tempBase ("ha-wyze-overlay-deploy-" + [guid]::NewGuid().ToString('N'))
$archiveName = "wyzeapi-overlay-$ReleaseCommit.tar.gz"
$scriptName = "deploy-wyzeapi-overlay-$ReleaseCommit.sh"
$archivePath = Join-Path $tempDir $archiveName
$remoteScriptPath = Join-Path $tempDir $scriptName
$keyPath = Join-Path $tempDir 'lightsail'
$certPath = "$keyPath-cert.pub"
$knownHostsPath = Join-Path $tempDir 'known_hosts'
$failsafePath = Join-Path $tempDir 'close-temporary-ssh.ps1'
$firewallOpened = $false
$temporarySshCidr = $null
$failsafeProcess = $null

$remoteScript = @'
#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

release_commit='__RELEASE_COMMIT__'
archive_sha256='__ARCHIVE_SHA256__'
archive_path='/tmp/__ARCHIVE_NAME__'
release_stage=$(mktemp -d /tmp/wyzeapi-overlay-release.XXXXXX)
overlay_root="$release_stage/home_assistant/wyzeapi_overlay/custom_components/wyzeapi"
ha_config='/opt/homeassistant/config'
target="$ha_config/custom_components/wyzeapi"
stage_target="$ha_config/.wyzeapi-overlay-candidate-$release_commit"
backup_root='/opt/homeassistant/wyzeapi-overlay-backups'
stamp=$(date -u +%Y%m%dT%H%M%SZ)
requested_backup=${1:-}
backup=${requested_backup:-"$backup_root/wyzeapi-pre-0.1.41-$stamp.tar.gz"}
token_file='/opt/ha-chatgpt-mcp/secrets/ha_token'
mutated=0
overlay_stage='validating_archive'
declare -A prior_hashes=()

declare -A base_hashes=(
  [manifest.json]='8C1551778463D995413F6A71739ADC53D820DED0CB069EF08E7DBB7A6395F1BC'
  [__init__.py]='52D31F80DF2D79AC76A258624917DB1F06609C32801F9418C7D09063AE4F2815'
  [const.py]='651997A054D7DD1CFBAB902917D598D1BD2C31578DDDE529EDFE803DE24B56FC'
  [irrigation.py]='C1E0F1AB419B704BEC9566BCD19F4DEB16A18052FDEE23E62336D8A09A239854'
  [irrigation_data.py]='9F59596EB839D6C6ACE8D2B04C2B9593064B1B1CD767E4647EF3A4E8950A0591'
  [sensor.py]='3AF7296A87C8B0EA0CDE2E98CE6A05BA81846FE8631D8DD09E5B1954E62DAC15'
  [services.yaml]='F69AF27ABBF54435C1A978DBF791F8CDA8D8500187FE4067EE90C18D661A2950'
)
declare -A predecessor_hashes=(
  [manifest.json]='96CE2D9B1969CAC02D4FB3F822AB5E2652CDFD2EB21CEF9FF42FF3980834708C'
  [__init__.py]='5977510F5AD032DEF81DDB67D1A72D11B719E7BA37860F969931F7859492CF94'
  [const.py]='24531253DC5445C3D7F16D91CD6727BA9D2DB457CD81098A0471419AD88E2140'
  [irrigation.py]='4DC968ACFC0C66ED7AF001DC0BADD4764CB1751570DF486802ED787B20730EC2'
  [irrigation_data.py]='D828A3007DD019A914256DA2664F584A2BDF6CA8A8C6B7654F3B4E6B9A83F0D5'
  [sensor.py]='95D9B4FFDDFE3199C6C98B62D30338350DAA8E5F6F29C1E501E2BDB53AF604BA'
  [services.yaml]='03F5A037D81FAA0B8AA915F4106D87195DCEC043999669F7EA159F2233E5459B'
)
files=(manifest.json __init__.py const.py irrigation.py irrigation_data.py sensor.py services.yaml)

wait_for_ha() {
  local token
  token=$(sudo cat "$token_file")
  for attempt in $(seq 1 180); do
    if curl --fail --silent --max-time 5 \
      -H "Authorization: Bearer $token" \
      http://127.0.0.1:8123/api/config >/tmp/wyze-overlay-ha-config.json; then
      return 0
    fi
    sudo docker inspect -f '{{.State.Running}}' homeassistant | grep -Fxq true
    sleep 1
  done
  return 1
}

wait_for_wyze_loaded() {
  for attempt in $(seq 1 180); do
    if sudo docker exec ha-chatgpt-mcp python -c '
import asyncio
from pathlib import Path
import aiohttp
async def check():
    token = Path("/run/secrets/ha_token").read_text(encoding="utf-8").strip()
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect("http://127.0.0.1:8123/api/websocket") as ws:
            assert (await ws.receive_json()).get("type") == "auth_required"
            await ws.send_json({"type": "auth", "access_token": token})
            assert (await ws.receive_json()).get("type") == "auth_ok"
            await ws.send_json({"id": 1, "type": "config_entries/get"})
            reply = await ws.receive_json()
            assert reply.get("success") is True
            matches = [item for item in reply.get("result", []) if item.get("domain") == "wyzeapi"]
            assert matches and all(item.get("state") == "loaded" for item in matches)
asyncio.run(check())
' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

capture_loaded_entries() {
  local output=$1
  sudo docker exec ha-chatgpt-mcp python -c '
import asyncio
import json
from pathlib import Path
import aiohttp
async def capture():
    token = Path("/run/secrets/ha_token").read_text(encoding="utf-8").strip()
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect("http://127.0.0.1:8123/api/websocket") as ws:
            assert (await ws.receive_json()).get("type") == "auth_required"
            await ws.send_json({"type": "auth", "access_token": token})
            assert (await ws.receive_json()).get("type") == "auth_ok"
            await ws.send_json({"id": 1, "type": "config_entries/get"})
            reply = await ws.receive_json()
            assert reply.get("success") is True
            entries = reply.get("result", [])
            print(json.dumps(sorted(item["entry_id"] for item in entries if item.get("state") == "loaded")))
asyncio.run(capture())
' >"$output"
  python3 -c 'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); assert isinstance(value,list) and value' "$output"
}

wait_for_loaded_entries() {
  local expected=$1
  local output=$2
  for attempt in $(seq 1 180); do
    if capture_loaded_entries "$output" && python3 -c '
import json,sys
def load(path):
    with open(path, encoding="utf-8") as handle: return set(json.load(handle))
assert load(sys.argv[1]) <= load(sys.argv[2])
' "$expected" "$output"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

capture_runtime() {
  local output=$1
  curl --fail --silent --max-time 15 \
    -H "Authorization: Bearer $token" \
    http://127.0.0.1:8123/api/services >/tmp/wyze-overlay-services.json
  curl --fail --silent --max-time 15 \
    -H "Authorization: Bearer $token" \
    http://127.0.0.1:8123/api/states >/tmp/wyze-overlay-states.json
  sudo python3 - "$device_id" "$output" <<'PY'
import json
import sys
device_id, output = sys.argv[1:]
with open('/tmp/wyze-overlay-services.json', encoding='utf-8') as handle:
    domains = {item['domain']: sorted(item['services']) for item in json.load(handle)}
with open('/tmp/wyze-overlay-states.json', encoding='utf-8') as handle:
    states = {item['entity_id']: item['state'] for item in json.load(handle)}
with open('/opt/homeassistant/config/.storage/core.entity_registry', encoding='utf-8') as handle:
    registry = json.load(handle)['data']['entities']
entity_ids = sorted(
    item['entity_id'] for item in registry
    if item.get('device_id') == device_id and item.get('entity_id') in states
)
unique_ids = {
    item['unique_id']: {
        'entity_id': item['entity_id'],
        'available': states[item['entity_id']] != 'unavailable',
    }
    for item in registry
    if item.get('device_id') == device_id
    and item.get('unique_id')
    and item.get('entity_id') in states
}
payload = {
    'services': domains.get('wyzeapi', []),
    'entities': {entity_id: states[entity_id] != 'unavailable' for entity_id in entity_ids},
    'unique_ids': unique_ids,
}
with open(output, 'w', encoding='utf-8') as handle:
    json.dump(payload, handle, sort_keys=True)
PY
}

wait_for_controller_entities() {
  local output=$1
  for attempt in $(seq 1 180); do
    capture_runtime "$output"
    if sudo python3 -c '
import json,sys
def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)
before = load(sys.argv[1])
after = load(sys.argv[2])
assert set(before["services"]) <= set(after["services"])
assert set(before["entities"]) <= set(after["entities"])
assert set(before["unique_ids"]) <= set(after["unique_ids"])
' /tmp/wyze-overlay-prior.json "$output"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

assert_prior_runtime_restored() {
  wait_for_controller_entities /tmp/wyze-overlay-restored.json
  sudo python3 - <<'PY'
import json
def load(path):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)
before = load('/tmp/wyze-overlay-prior.json')
after = load('/tmp/wyze-overlay-restored.json')
assert set(before['services']) <= set(after['services'])
assert set(before['entities']) <= set(after['entities'])
assert set(before['unique_ids']) <= set(after['unique_ids'])
PY
}

restore_backup() {
  set +e
  sudo rm -rf -- "$target"
  sudo tar -xzf "$backup" -C "$ha_config/custom_components"
  sudo docker restart homeassistant >/dev/null
  wait_for_ha || return 1
  wait_for_loaded_entries /tmp/wyze-overlay-prior-entries.json /tmp/wyze-overlay-restored-entries.json || return 1
  wait_for_wyze_loaded || return 1
  for name in "${files[@]}"; do
    test "$(sudo sha256sum "$target/$name" | awk '{print toupper($1)}')" = \
      "${prior_hashes[$name]}" || return 1
  done
  assert_prior_runtime_restored || return 1
}

cleanup() {
  local exit_code=$?
  trap - EXIT
  if [ "$exit_code" -ne 0 ] && sudo test -d "$backup_root"; then
    printf 'timestamp=%s\nresult=failed\nstage=%s\nexit_code=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$overlay_stage" "$exit_code" | \
      sudo tee "$backup_root/latest-overlay-status" >/dev/null
    printf 'Wyze overlay failure stage=%s exit_code=%s\n' \
      "$overlay_stage" "$exit_code" >&2
  fi
  if [ "$exit_code" -ne 0 ] && sudo test -f "$backup"; then
    printf 'Overlay deployment failed; backup retained at %s\n' "$backup" >&2
  fi
  if [ "$exit_code" -ne 0 ] && [ "$mutated" -eq 1 ]; then
    restore_backup || exit_code=125
  fi
  sudo rm -rf -- "$release_stage" "$stage_target"
  sudo rm -f -- "$archive_path" /tmp/__SCRIPT_NAME__ \
    /tmp/wyze-overlay-ha-config.json /tmp/wyze-overlay-services.json \
    /tmp/wyze-overlay-response.json /tmp/wyze-overlay-request.json \
    /tmp/wyze-overlay-states.json /tmp/wyze-overlay-prior.json \
    /tmp/wyze-overlay-current.json /tmp/wyze-overlay-restored.json \
    /tmp/wyze-overlay-prior-entries.json /tmp/wyze-overlay-current-entries.json \
    /tmp/wyze-overlay-restored-entries.json
  exit "$exit_code"
}
trap cleanup EXIT

printf '%s  %s\n' "$archive_sha256" "$archive_path" | sha256sum -c -
sudo tar -xzf "$archive_path" -C "$release_stage"
test -d "$overlay_root"
actual_files=$(cd "$overlay_root" && find . -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)
expected_files=$(printf '%s\n' "${files[@]}" | sort)
test "$actual_files" = "$expected_files"
python3 -c 'import json,sys; p=json.load(open(sys.argv[1], encoding="utf-8")); assert p["domain"]=="wyzeapi" and p["version"]=="0.1.41"' \
  "$overlay_root/manifest.json"

sudo test -d "$target"
overlay_stage='validating_installed_base'
for name in "${files[@]}"; do
  sudo test -f "$target/$name"
  current=$(sudo sha256sum "$target/$name" | awk '{print toupper($1)}')
  candidate=$(sha256sum "$overlay_root/$name" | awk '{print toupper($1)}')
  prior_hashes[$name]="$current"
  if [ "$current" != "$candidate" ]; then
    test "$current" = "${base_hashes[$name]}" || \
      test "$current" = "${predecessor_hashes[$name]:-}"
  fi
done

overlay_stage='capturing_pre_deploy_runtime'
wait_for_ha
wait_for_wyze_loaded
capture_loaded_entries /tmp/wyze-overlay-prior-entries.json
token=$(sudo cat "$token_file")
device_id=$(sudo python3 - <<'PY'
import json
path='/opt/homeassistant/config/.storage/core.device_registry'
with open(path, encoding='utf-8') as handle:
    devices=json.load(handle)['data']['devices']
matches=[d['id'] for d in devices if d.get('manufacturer')=='WyzeLabs' and d.get('model')=='BS_WK1']
assert len(matches)==1
print(matches[0])
PY
)
capture_runtime /tmp/wyze-overlay-prior.json

sudo install -d -o root -g root -m 0700 "$backup_root"
case "$backup" in
  "$backup_root"/wyzeapi-pre-0.1.41-*.tar.gz) ;;
  *) echo 'Overlay backup path is outside the guarded backup namespace.' >&2; exit 1 ;;
esac
if [ -n "$requested_backup" ]; then
  sudo test -f "$backup"
else
  sudo tar -czf "$backup" -C "$ha_config/custom_components" wyzeapi
fi
sudo rm -rf -- "$stage_target"
sudo install -d -o root -g root -m 0755 "$stage_target"
for name in "${files[@]}"; do
  sudo install -o root -g root -m 0644 "$overlay_root/$name" "$stage_target/$name"
done
sudo docker exec homeassistant python -m py_compile \
  "/config/$(basename "$stage_target")/__init__.py" \
  "/config/$(basename "$stage_target")/const.py" \
  "/config/$(basename "$stage_target")/irrigation.py" \
  "/config/$(basename "$stage_target")/irrigation_data.py" \
  "/config/$(basename "$stage_target")/sensor.py"
sudo docker exec homeassistant python -c \
  'import pathlib,yaml; p=pathlib.Path("/config")/"__STAGE_BASENAME__"/"services.yaml"; value=yaml.safe_load(p.read_text()); assert isinstance(value,dict) and len(value)==8'

overlay_stage='installing_candidate'
mutated=1
for name in "${files[@]}"; do
  sudo install -o root -g root -m 0644 "$overlay_root/$name" "$target/$name"
done
sudo docker exec homeassistant python -m homeassistant --script check_config --config /config
overlay_stage='restarting_home_assistant'
sudo docker restart homeassistant >/dev/null
wait_for_ha
wait_for_loaded_entries /tmp/wyze-overlay-prior-entries.json /tmp/wyze-overlay-current-entries.json
wait_for_wyze_loaded
wait_for_controller_entities /tmp/wyze-overlay-current.json

overlay_stage='verifying_read_only_services'
curl --fail --silent --max-time 15 \
  -H "Authorization: Bearer $token" \
  http://127.0.0.1:8123/api/services >/tmp/wyze-overlay-services.json
python3 - <<'PY'
import json
with open('/tmp/wyze-overlay-services.json', encoding='utf-8') as handle:
    domains = {item['domain']: set(item['services']) for item in json.load(handle)}
required = {
    'run_sprinkler_zone', 'run_sprinkler_sequence', 'stop_sprinkler',
    'refresh_sprinkler', 'get_sprinkler_snapshot',
    'get_sprinkler_schedule_runs', 'get_sprinkler_schedules',
    'get_sprinkler_capabilities',
}
assert required <= domains.get('wyzeapi', set())
PY

for service in get_sprinkler_snapshot get_sprinkler_schedule_runs get_sprinkler_schedules get_sprinkler_capabilities; do
  data='{}'
  if [ "$service" = get_sprinkler_schedule_runs ]; then data='{"limit":100}'; fi
  python3 -c 'import json,sys; p=json.loads(sys.argv[2]); p["device_id"]=[sys.argv[1]]; print(json.dumps(p))' \
    "$device_id" "$data" >/tmp/wyze-overlay-request.json
  curl --fail --silent --max-time 60 \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    --data-binary @/tmp/wyze-overlay-request.json \
    "http://127.0.0.1:8123/api/services/wyzeapi/$service?return_response" \
    >/tmp/wyze-overlay-response.json
  python3 -c 'import json; p=json.load(open("/tmp/wyze-overlay-response.json", encoding="utf-8")); assert isinstance(p.get("service_response"), dict)'
  if [ "$service" = get_sprinkler_snapshot ]; then
    python3 - <<'PY'
import json
p=json.load(open('/tmp/wyze-overlay-response.json', encoding='utf-8'))
def values(value):
    if isinstance(value, dict):
        yield value
        for child in value.values(): yield from values(child)
    elif isinstance(value, list):
        for child in value: yield from values(child)
snapshot = next(
    item for item in values(p.get('service_response'))
    if isinstance(item.get('zones'), list) and 'watering_state' in item
)
zones = []
for zone in snapshot['zones']:
    number = zone.get('zone_number')
    assert isinstance(number, int) and not isinstance(number, bool) and 1 <= number <= 8
    zones.append({'zone_number': number, 'zone_id': zone.get('zone_id')})
assert zones and len({item['zone_number'] for item in zones}) == len(zones)
json.dump(zones, open('/tmp/wyze-overlay-snapshot-zones.json', 'w', encoding='utf-8'), sort_keys=True)
PY
  fi
  if [ "$service" = get_sprinkler_capabilities ]; then
    python3 -c '
import json
p=json.load(open("/tmp/wyze-overlay-response.json", encoding="utf-8"))
def values(value):
    if isinstance(value, dict):
        yield value
        for child in value.values(): yield from values(child)
    elif isinstance(value, list):
        for child in value: yield from values(child)
assert any(item.get("integration_version") == "0.1.41" for item in values(p.get("service_response")))
'
  fi
done

capture_runtime /tmp/wyze-overlay-current.json
overlay_stage='verifying_controller_contract'
sudo python3 - <<'PY'
import json
def load(path):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)
before = load('/tmp/wyze-overlay-prior.json')
after = load('/tmp/wyze-overlay-current.json')
zones = load('/tmp/wyze-overlay-snapshot-zones.json')
required = {
    'run_sprinkler_zone', 'run_sprinkler_sequence', 'stop_sprinkler',
    'refresh_sprinkler', 'get_sprinkler_snapshot',
    'get_sprinkler_schedule_runs', 'get_sprinkler_schedules',
    'get_sprinkler_capabilities',
}
assert required <= set(after['services'])
assert set(before['services']) <= set(after['services'])
assert all(
    entity_id in after['entities']
    for entity_id in before['entities']
)
required_suffixes = {
    '-watering-status', '-active-zone', '-watering-remaining',
    '-last-watering', '-configuration',
}
required_suffixes.update(
    f"-zone-{zone['zone_number']}-metadata" for zone in zones
)
for suffix in required_suffixes:
    matches = [
        item for unique_id, item in after['unique_ids'].items()
        if unique_id.endswith(suffix)
    ]
    assert len(matches) == 1 and matches[0]['available'] is True
PY

for name in "${files[@]}"; do
  test "$(sudo sha256sum "$target/$name" | awk '{print toupper($1)}')" = \
    "$(sha256sum "$overlay_root/$name" | awk '{print toupper($1)}')"
done
overlay_stage='complete'
mutated=0
trap - EXIT
sudo rm -rf -- "$release_stage" "$stage_target"
sudo rm -f -- "$archive_path" /tmp/__SCRIPT_NAME__ \
  /tmp/wyze-overlay-ha-config.json /tmp/wyze-overlay-services.json \
  /tmp/wyze-overlay-response.json /tmp/wyze-overlay-request.json \
  /tmp/wyze-overlay-states.json /tmp/wyze-overlay-prior.json \
  /tmp/wyze-overlay-current.json /tmp/wyze-overlay-restored.json \
  /tmp/wyze-overlay-snapshot-zones.json \
  /tmp/wyze-overlay-prior-entries.json /tmp/wyze-overlay-current-entries.json \
  /tmp/wyze-overlay-restored-entries.json
printf 'Wyze sprinkler overlay 0.1.41 deployed from commit %s; backup=%s\n' \
  "$release_commit" "$backup"
'@

try {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    & $gitExe -C $sourceRoot archive '--format=tar.gz' "--output=$archivePath" `
        $ReleaseCommit $overlayPath
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the exact overlay archive.' }
    $archiveSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    $stageBasename = ".wyzeapi-overlay-candidate-$ReleaseCommit"
    $rendered = $remoteScript.Replace('__RELEASE_COMMIT__', $ReleaseCommit).Replace(
        '__ARCHIVE_SHA256__', $archiveSha
    ).Replace('__ARCHIVE_NAME__', $archiveName).Replace(
        '__SCRIPT_NAME__', $scriptName
    ).Replace('__STAGE_BASENAME__', $stageBasename)
    [IO.File]::WriteAllText(
        $remoteScriptPath,
        (($rendered -replace "`r`n", "`n") + "`n"),
        [Text.UTF8Encoding]::new($false)
    )

    $access = & $awsExe lightsail get-instance-access-details --profile $AwsProfile `
        --region $AwsRegion --instance-name $InstanceName --protocol ssh --output json |
        ConvertFrom-Json
    if (-not $access.accessDetails.privateKey -or -not $access.accessDetails.certKey) {
        throw 'Could not obtain temporary Lightsail access details.'
    }
    [IO.File]::WriteAllText($keyPath, $access.accessDetails.privateKey, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($certPath, $access.accessDetails.certKey, [Text.UTF8Encoding]::new($false))
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & "$env:SystemRoot\System32\icacls.exe" $keyPath '/inheritance:r' '/grant:r' "*$sid`:(F)" | Out-Null
    & "$env:SystemRoot\System32\icacls.exe" $certPath '/inheritance:r' '/grant:r' "*$sid`:(F)" | Out-Null

    $currentIp = (Invoke-RestMethod -Uri 'https://checkip.amazonaws.com').Trim()
    $parsedIp = $null
    if (-not [Net.IPAddress]::TryParse($currentIp, [ref]$parsedIp)) {
        throw 'Could not determine the current public IP.'
    }
    $temporarySshCidr = "$currentIp/32"
    & $awsExe lightsail open-instance-public-ports --profile $AwsProfile --region $AwsRegion `
        --instance-name $InstanceName `
        --port-info "fromPort=22,toPort=22,protocol=tcp,cidrs=$temporarySshCidr" --output json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not open temporary SSH access.' }
    $firewallOpened = $true

    $failsafeBody = @"
`$ErrorActionPreference = 'SilentlyContinue'
Start-Sleep -Seconds 1200
& '$awsExe' lightsail close-instance-public-ports --profile '$AwsProfile' --region '$AwsRegion' --instance-name '$InstanceName' --port-info 'fromPort=22,toPort=22,protocol=tcp,cidrs=$temporarySshCidr' --output json | Out-Null
"@
    [IO.File]::WriteAllText($failsafePath, $failsafeBody, [Text.UTF8Encoding]::new($false))
    $failsafeProcess = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $failsafePath) `
        -WindowStyle Hidden -PassThru

    $targetHost = "$($access.accessDetails.username)@$($access.accessDetails.ipAddress)"
    $sshOptions = @(
        '-i', $keyPath, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=60',
        '-o', 'StrictHostKeyChecking=accept-new', '-o', "UserKnownHostsFile=$knownHostsPath"
    )
    & $scpExe @sshOptions $archivePath "${targetHost}:/tmp/$archiveName"
    if ($LASTEXITCODE -ne 0) { throw 'Could not upload the overlay archive.' }
    & $scpExe @sshOptions $remoteScriptPath "${targetHost}:/tmp/$scriptName"
    if ($LASTEXITCODE -ne 0) { throw 'Could not upload the overlay deployment script.' }
    & $sshExe @sshOptions $targetHost "bash /tmp/$scriptName"
    if ($LASTEXITCODE -ne 0) { throw 'Wyze overlay deployment failed; rollback was attempted.' }
}
finally {
    $firewallCloseFailed = $false
    if ($firewallOpened -and $temporarySshCidr) {
        & $awsExe lightsail close-instance-public-ports --profile $AwsProfile --region $AwsRegion `
            --instance-name $InstanceName `
            --port-info "fromPort=22,toPort=22,protocol=tcp,cidrs=$temporarySshCidr" --output json | Out-Null
        if ($LASTEXITCODE -ne 0) { $firewallCloseFailed = $true }
    }
    if (-not $firewallCloseFailed -and $failsafeProcess -and -not $failsafeProcess.HasExited) {
        Stop-Process -Id $failsafeProcess.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $failsafeProcess.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $tempDir) {
        $resolved = [IO.Path]::GetFullPath($tempDir)
        if (-not $resolved.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase) -or
            -not ([IO.Path]::GetFileName($resolved)).StartsWith('ha-wyze-overlay-deploy-')) {
            throw "Refusing to remove unexpected temporary path: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    if ($firewallCloseFailed) { throw 'Could not close the temporary SSH firewall rule.' }
}
