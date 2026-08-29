param(
    [string]$SecretStagingPath,
    [Parameter(Mandatory)][string]$AwsProfile,
    [Parameter(Mandatory)][string]$AwsRegion,
    [Parameter(Mandatory)][string]$InstanceName,
    [Parameter(Mandatory)][ValidatePattern('^https://')][string]$PublicFrontendUrl,
    [Parameter(Mandatory)][ValidatePattern('^https://')][string]$PublicMcpUrl,
    [switch]$PreflightOnly,
    [switch]$ReuseVerifiedWyzeOverlay
)

$ErrorActionPreference = 'Stop'

$releaseVersion = '2.7.3'
$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$secretRoot = if ($SecretStagingPath) { [IO.Path]::GetFullPath($SecretStagingPath) } else { $null }
$requiredSecrets = @(
    'solaredge_client_id',
    'solaredge_client_secret',
    'solaredge_token_key',
    'solaredge_bridge_secret'
)
$requiredSourceFiles = @(
    'docker-compose.yml',
    'collector/ha_host_diagnostics.py',
    'collector/ha-host-diagnostics.service',
    'collector/README.md',
    'scripts/deploy-wyzeapi-overlay.ps1',
    'home_assistant/wyzeapi_overlay/README.md'
)
foreach ($relativePath in $requiredSourceFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot $relativePath) -PathType Leaf)) {
        throw "The deployment source is missing $relativePath."
    }
}
if ($secretRoot) {
    foreach ($name in $requiredSecrets) {
        if (-not (Test-Path -LiteralPath (Join-Path $secretRoot $name) -PathType Leaf)) {
            throw "The secure staging directory is missing $name."
        }
    }
}

$awsExe = (Get-Command aws -ErrorAction Stop).Source
$ghExe = (Get-Command gh -ErrorAction Stop).Source
$gitExe = (Get-Command git -ErrorAction Stop).Source
$sshExe = (Get-Command ssh -ErrorAction Stop).Source
$scpExe = (Get-Command scp -ErrorAction Stop).Source
$uvExe = (Get-Command uv -ErrorAction Stop).Source
$sourceStatus = (& $gitExe -C $sourceRoot status --porcelain=v1 --untracked-files=all) -join "`n"
if ($LASTEXITCODE -ne 0 -or $sourceStatus) {
    throw 'Deployment requires a clean Git checkout with no untracked files.'
}
$releaseCommit = ((& $gitExe -C $sourceRoot rev-parse HEAD) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or $releaseCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Could not resolve the immutable release commit.'
}
& $uvExe run '--no-project' '--python' '3.12' 'python' `
    (Join-Path $sourceRoot 'scripts/release_integrity.py')
if ($LASTEXITCODE -ne 0) { throw 'Release-integrity validation failed.' }
& $uvExe run '--no-project' '--python' '3.12' 'python' `
    (Join-Path $sourceRoot 'scripts/public_release_audit.py') '--history'
if ($LASTEXITCODE -ne 0) { throw 'Public-release audit failed.' }
$sourceStatus = (& $gitExe -C $sourceRoot status --porcelain=v1 --untracked-files=all) -join "`n"
if ($LASTEXITCODE -ne 0 -or $sourceStatus) {
    throw 'Release validation modified the clean source checkout.'
}
if (-not $PreflightOnly) {
    $publicRepository = 'shogun301/ha-chatgpt-mcp'
    $remoteMain = ((& $gitExe ls-remote "https://github.com/$publicRepository.git" refs/heads/main) -join '').Trim()
    if ($LASTEXITCODE -ne 0 -or -not $remoteMain.StartsWith("$releaseCommit`t")) {
        throw 'The exact release commit is not the public GitHub main branch tip.'
    }
    $ciRuns = & $ghExe run list --repo $publicRepository --commit $releaseCommit `
        --workflow public-safety.yml --limit 20 `
        --json status,conclusion,headSha,headBranch,event | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not ($ciRuns | Where-Object {
        $_.headSha -eq $releaseCommit -and $_.headBranch -eq 'main' -and $_.event -eq 'push' -and $_.status -eq 'completed' -and $_.conclusion -eq 'success'
    })) {
        throw 'GitHub Public safety CI is not green on the exact release commit.'
    }
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempDir = Join-Path $tempBase ("ha-mcp-deploy-" + [guid]::NewGuid().ToString('N'))
$keyPath = Join-Path $tempDir 'lightsail'
$certPath = "$keyPath-cert.pub"
$knownHostsPath = Join-Path $tempDir 'known_hosts'
$archiveName = "ha-chatgpt-mcp-$releaseVersion.tar.gz"
$remoteScriptName = "ha-chatgpt-mcp-deploy-$releaseVersion.sh"
$archivePath = Join-Path $tempDir $archiveName
$remoteScriptPath = Join-Path $tempDir $remoteScriptName
$overlayArchiveName = "wyzeapi-overlay-$releaseCommit.tar.gz"
$overlayScriptName = "deploy-wyzeapi-overlay-$releaseCommit.sh"
$overlayArchivePath = Join-Path $tempDir $overlayArchiveName
$overlayScriptPath = Join-Path $tempDir $overlayScriptName
$sshFailsafePath = Join-Path $tempDir 'close-temporary-ssh.ps1'
$firewallOpened = $false
$temporarySshCidr = $null
$sshFailsafeProcess = $null

$remoteScript = @'
#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

release_version='2.7.3'
release_commit='__RELEASE_COMMIT__'
preflight_only='__PREFLIGHT_ONLY__'
reuse_verified_overlay='__REUSE_VERIFIED_OVERLAY__'
archive_sha256='__ARCHIVE_SHA256__'
archive_path='/tmp/ha-chatgpt-mcp-2.7.3.tar.gz'
candidate_tag="ha-chatgpt-mcp:candidate-$release_commit"
release_stage=$(mktemp -d /tmp/ha-mcp-release.XXXXXX)
app_root='/opt/ha-chatgpt-mcp'
collector_root='/opt/ha-host-diagnostics'
collector_program="$collector_root/ha_host_diagnostics.py"
collector_unit='/etc/systemd/system/ha-host-diagnostics.service'
collector_state='/var/lib/ha-host-diagnostics'
backup_root='/opt/ha-chatgpt-mcp-deploy-backups'
stamp=$(date -u +%Y%m%dT%H%M%SZ)
app_backup="$backup_root/pre-$release_version-$stamp.tar.gz"
collector_backup="$backup_root/ha-host-diagnostics-$stamp.tar.gz"
unit_backup="$backup_root/ha-host-diagnostics.service-$stamp"
rollback_tag="ha-chatgpt-mcp:rollback-$stamp"
tunnel_rollback_tag="ha-chatgpt-cloudflared:rollback-$stamp"
mutated=0
collector_existed=0
unit_existed=0
collector_changed=0
collector_candidate_hash=''
collector_installed_hash=''
prior_image_id=''
prior_image_ref=''
tested_image_id=''
smoke_container="ha-mcp-release-smoke-$stamp"
preflight_container="ha-mcp-release-preflight-$stamp"
prior_collector_enabled='disabled'
prior_collector_active='inactive'
prior_collector_active_enter=''
tunnel_changed=0
prior_tunnel_image_id=''
prior_tunnel_image_ref=''
prior_tunnel_started=''
desired_tunnel_image_id=''
overlay_mutated=0
overlay_backup="/opt/homeassistant/wyzeapi-overlay-backups/wyzeapi-pre-0.1.40-main-$stamp.tar.gz"
overlay_baseline='/tmp/ha-mcp-overlay-baseline'
overlay_target='/opt/homeassistant/config/custom_components/wyzeapi'
homeassistant_started_before=''
caddy_started_before=''
stage='initializing'
status_file="$backup_root/latest-deploy-status"

record_status() {
  local result=$1
  sudo install -d -o root -g root -m 0700 "$backup_root"
  printf 'timestamp=%s\nresult=%s\nstage=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$result" "$stage" | \
    sudo tee "$status_file" >/dev/null
  sudo chown root:root "$status_file"
  sudo chmod 0600 "$status_file"
}

record_marker() {
  local phase=$1
  local marker_program="$collector_program"
  if [ ! -f "$marker_program" ] && [ -f "$app_root/collector/ha_host_diagnostics.py" ]; then
    marker_program="$app_root/collector/ha_host_diagnostics.py"
  fi
  if [ -f "$marker_program" ]; then
    sudo install -d -o root -g 10001 -m 0750 "$collector_state"
    sudo install -d -o root -g root -m 0700 "$collector_state/state"
    sudo install -d -o root -g 10001 -m 0750 "$collector_state/export"
    sudo /usr/bin/python3 "$marker_program" mark-deployment \
      --phase "$phase" --version "$release_version"
  fi
}

cleanup_staging() {
  sudo docker rm -f "$preflight_container" >/dev/null 2>&1 || true
  sudo docker rm -f "$smoke_container" >/dev/null 2>&1 || true
  sudo docker image rm "$candidate_tag" >/dev/null 2>&1 || true
  sudo rm -rf -- "$release_stage"
  sudo rm -rf -- "$overlay_baseline"
  sudo rm -f -- "$archive_path" "/tmp/ha-chatgpt-mcp-deploy-$release_version.sh" \
    "/tmp/__OVERLAY_ARCHIVE_NAME__" "/tmp/__OVERLAY_SCRIPT_NAME__" \
    /tmp/ha-mcp-rollback-health.json
  for secret_name in solaredge_client_id solaredge_client_secret solaredge_token_key solaredge_bridge_secret; do
    sudo rm -f -- "/tmp/$secret_name"
  done
}

collector_content_hash() {
  local program=$1 readme=$2 unit=$3
  if [ ! -f "$program" ] || [ ! -f "$readme" ] || [ ! -f "$unit" ]; then
    printf 'missing\n'
    return 0
  fi
  sha256sum "$program" "$readme" "$unit" | awk '{print $1}' | sha256sum | awk '{print $1}'
}

tunnel_config_hash() {
  sudo awk '/^  cloudflared:/{found=1} found{print}' "$1" | sha256sum | awk '{print $1}'
}

tunnel_image_ref() {
  sudo awk '/^  cloudflared:/{found=1; next} found && $1 == "image:" {print $2; exit}' "$1"
}

wait_ha_api() {
  local token
  token=$(sudo cat "$app_root/secrets/ha_token")
  for attempt in $(seq 1 180); do
    if curl --fail --silent --max-time 5 -H "Authorization: Bearer $token" \
      http://127.0.0.1:8123/api/config >/tmp/ha-mcp-overlay-ha-config.json; then
      return 0
    fi
    sudo docker inspect -f '{{.State.Running}}' homeassistant | grep -Fxq true
    sleep 1
  done
  return 1
}

capture_loaded_entries_main() {
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
            print(json.dumps(sorted(item["entry_id"] for item in reply.get("result", []) if item.get("state") == "loaded")))
asyncio.run(capture())
' | sudo tee "$output" >/dev/null
}

capture_overlay_runtime_main() {
  local output=$1
  local token device_id
  token=$(sudo cat "$app_root/secrets/ha_token") || return 1
  device_id=$(sudo cat "$overlay_baseline/device_id") || return 1
  curl --fail --silent --max-time 15 -H "Authorization: Bearer $token" \
    http://127.0.0.1:8123/api/services >/tmp/ha-mcp-overlay-services.json || return 1
  curl --fail --silent --max-time 15 -H "Authorization: Bearer $token" \
    http://127.0.0.1:8123/api/states >/tmp/ha-mcp-overlay-states.json || return 1
  sudo python3 - "$device_id" "$output" <<'PY' || return 1
import json
import sys
device_id, output = sys.argv[1:]
with open('/tmp/ha-mcp-overlay-services.json', encoding='utf-8') as handle:
    services = {item['domain']: sorted(item['services']) for item in json.load(handle)}
with open('/tmp/ha-mcp-overlay-states.json', encoding='utf-8') as handle:
    states = {item['entity_id']: item['state'] for item in json.load(handle)}
with open('/opt/homeassistant/config/.storage/core.entity_registry', encoding='utf-8') as handle:
    registry = json.load(handle)['data']['entities']
ids = sorted(item['entity_id'] for item in registry if item.get('device_id') == device_id and item.get('entity_id') in states)
with open(output, 'w', encoding='utf-8') as handle:
    json.dump({'services': services.get('wyzeapi', []), 'entities': {item: states[item] != 'unavailable' for item in ids}}, handle, sort_keys=True)
PY
}

rollback_overlay() {
  local verify_root current_entries
  [ "$overlay_mutated" -eq 1 ] || return 0
  case "${HA_MCP_FAIL_OVERLAY_ROLLBACK_STEP:-}" in
    tar|restart|cmp) return 1 ;;
  esac
  sudo test -f "$overlay_backup" || return 1
  sudo rm -rf -- "$overlay_target" || return 1
  sudo tar -xzf "$overlay_backup" -C /opt/homeassistant/config/custom_components || return 1
  verify_root=$(mktemp -d /tmp/ha-mcp-overlay-verify.XXXXXX) || return 1
  sudo tar -xzf "$overlay_backup" -C "$verify_root" || return 1
  sudo diff -qr --no-dereference "$overlay_target" "$verify_root/wyzeapi" >/dev/null || return 1
  sudo rm -rf -- "$verify_root" || return 1
  sudo docker restart homeassistant >/dev/null || return 1
  wait_ha_api || return 1
  for attempt in $(seq 1 180); do
    current_entries="$overlay_baseline/loaded-current.json"
    if capture_loaded_entries_main "$current_entries" && sudo python3 -c '
import json,sys
def load(path):
    with open(path, encoding="utf-8") as handle: return set(json.load(handle))
assert load(sys.argv[1]) <= load(sys.argv[2])
' "$overlay_baseline/loaded-before.json" "$current_entries"; then
      break
    fi
    sleep 1 || return 1
  done
  sudo python3 -c '
import json,sys
def load(path):
    with open(path, encoding="utf-8") as handle: return set(json.load(handle))
assert load(sys.argv[1]) <= load(sys.argv[2])
' "$overlay_baseline/loaded-before.json" "$current_entries" || return 1
  capture_overlay_runtime_main "$overlay_baseline/runtime-current.json" || return 1
  sudo cmp -s "$overlay_baseline/runtime-before.json" "$overlay_baseline/runtime-current.json" || return 1
  overlay_mutated=0
}

rollback() {
  set +e
  local rollback_failed=0
  local restored_image_id=''
  stage='rolling_back'
  if [ "$collector_changed" -eq 1 ]; then
    sudo systemctl stop ha-host-diagnostics.service >/dev/null 2>&1 || rollback_failed=1
  fi
  rollback_app() {
    sudo test -f "$app_backup" || return 1
    sudo tar -tzf "$app_backup" >/dev/null || return 1
    sudo find "$app_root" -mindepth 1 -maxdepth 1 \
      ! -name secrets ! -name data ! -name logs ! -name backups \
      -exec rm -rf -- {} + || return 1
    sudo tar -xzf "$app_backup" -C "$app_root" || return 1
    sudo test -f "$app_root/docker-compose.yml" || return 1
    [ -n "$prior_image_id" ] || return 1
    [ -n "$prior_image_ref" ] || return 1
    sudo docker image tag "$rollback_tag" "$prior_image_ref" || return 1
    cd "$app_root" || return 1
    sudo docker compose config --quiet || return 1
    sudo docker compose config --images | grep -Fx "$prior_image_ref" >/dev/null || return 1
    sudo docker compose up -d --no-deps --force-recreate ha-chatgpt-mcp >/dev/null 2>&1 || return 1
    restored_image_id=$(sudo docker container inspect -f '{{.Image}}' ha-chatgpt-mcp 2>/dev/null) || return 1
    [ "$restored_image_id" = "$prior_image_id" ] || return 1
    for rollback_attempt in $(seq 1 30); do
      if curl --fail --silent --max-time 5 http://127.0.0.1:8000/healthz >/tmp/ha-mcp-rollback-health.json; then
        break
      fi
      sleep 1
    done
    curl --fail --silent --max-time 5 http://127.0.0.1:8000/healthz >/tmp/ha-mcp-rollback-health.json || return 1
    python3 -c 'import json; p=json.load(open("/tmp/ha-mcp-rollback-health.json", encoding="utf-8")); assert p.get("status") == "ok"' || return 1
  }
  rollback_app || rollback_failed=1
  if [ "$collector_changed" -eq 1 ]; then
    if [ "$collector_existed" -eq 1 ]; then
      if [ -f "$collector_backup" ]; then
        sudo rm -rf -- "$collector_root" || rollback_failed=1
        sudo tar -xzf "$collector_backup" -C / || rollback_failed=1
      else
        rollback_failed=1
      fi
    else
      sudo rm -rf -- "$collector_root" || rollback_failed=1
    fi
    if [ "$unit_existed" -eq 1 ]; then
      if [ -f "$unit_backup" ]; then
        sudo install -o root -g root -m 0644 "$unit_backup" "$collector_unit" || rollback_failed=1
      else
        rollback_failed=1
      fi
    else
      sudo rm -f -- "$collector_unit" || rollback_failed=1
    fi
    sudo systemctl daemon-reload || rollback_failed=1
    if [ "$unit_existed" -eq 1 ]; then
      if [[ "$prior_collector_enabled" == enabled* ]]; then
        sudo systemctl enable ha-host-diagnostics.service >/dev/null 2>&1 || rollback_failed=1
      else
        sudo systemctl disable ha-host-diagnostics.service >/dev/null 2>&1 || rollback_failed=1
      fi
      if [ "$prior_collector_active" = 'active' ]; then
        sudo systemctl restart ha-host-diagnostics.service >/dev/null 2>&1 || rollback_failed=1
      fi
    else
      sudo systemctl disable ha-host-diagnostics.service >/dev/null 2>&1 || rollback_failed=1
    fi
  fi
  if [ "$tunnel_changed" -eq 1 ]; then
    sudo docker image tag "$tunnel_rollback_tag" "$prior_tunnel_image_ref" || rollback_failed=1
    cd "$app_root" || rollback_failed=1
    sudo docker compose up -d --no-deps --force-recreate cloudflared >/dev/null 2>&1 || rollback_failed=1
  fi
  if [ "$tunnel_changed" -eq 1 ]; then
    [ "$(sudo docker container inspect -f '{{.Image}}' ha-chatgpt-cloudflared 2>/dev/null || true)" = "$prior_tunnel_image_id" ] || rollback_failed=1
  else
    [ "$(sudo docker container inspect -f '{{.State.StartedAt}}' ha-chatgpt-cloudflared 2>/dev/null || true)" = "$prior_tunnel_started" ] || rollback_failed=1
  fi
  rollback_overlay || rollback_failed=1
  if [ "$unit_existed" -eq 1 ]; then
    sudo test -f "$collector_unit" || rollback_failed=1
    if [[ "$prior_collector_enabled" == enabled* ]]; then
      sudo systemctl is-enabled --quiet ha-host-diagnostics.service || rollback_failed=1
    else
      ! sudo systemctl is-enabled --quiet ha-host-diagnostics.service || rollback_failed=1
    fi
    if [ "$prior_collector_active" = 'active' ]; then
      sudo systemctl is-active --quiet ha-host-diagnostics.service || rollback_failed=1
      if [ "$collector_changed" -eq 0 ]; then
        [ "$(sudo systemctl show -p ActiveEnterTimestampMonotonic --value ha-host-diagnostics.service)" = "$prior_collector_active_enter" ] || rollback_failed=1
      fi
    else
      ! sudo systemctl is-active --quiet ha-host-diagnostics.service || rollback_failed=1
    fi
  else
    ! sudo test -e "$collector_unit" || rollback_failed=1
    ! sudo systemctl is-active --quiet ha-host-diagnostics.service || rollback_failed=1
  fi
  if [ "$rollback_failed" -ne 0 ]; then
    stage='rollback_failed'
    record_status rollback_failed || true
    set -e
    return 1
  fi
  stage='rolled_back'
  record_marker rolled_back || rollback_failed=1
  record_status rolled_back || rollback_failed=1
  if [ "$rollback_failed" -ne 0 ]; then
    stage='rollback_failed'
    record_status rollback_failed || true
    set -e
    return 1
  fi
  set -e
  return 0
}

on_exit() {
  local exit_code=$?
  local rollback_exit=0
  trap - EXIT
  if [ "$exit_code" -ne 0 ] && [ "$mutated" -eq 1 ]; then
    record_status failed
    rollback || rollback_exit=$?
  fi
  cleanup_staging
  if [ "$rollback_exit" -ne 0 ]; then
    exit 125
  fi
  exit "$exit_code"
}
trap on_exit EXIT

stage='extracting_clean_release'
printf '%s  %s\n' "$archive_sha256" "$archive_path" | sha256sum -c -
sudo tar -xzf "$archive_path" -C "$release_stage"
cd "$release_stage"
stage='auditing_clean_release'
sudo /usr/bin/python3 scripts/public_release_audit.py --archive
sudo chmod -R a+rX "$release_stage"
stage='building_mcp_image'
sudo docker build --build-arg "VCS_REF=$release_commit" \
  -t "$candidate_tag" .
test "$(sudo docker image inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
  "$candidate_tag")" = "$release_commit"
tested_image_id=$(sudo docker image inspect -f '{{.Id}}' "$candidate_tag")
stage='validating_release_integrity'
sudo docker run --rm --network none --env HOME=/tmp \
  --env PYTHONDONTWRITEBYTECODE=1 --read-only --tmpfs /tmp \
  --volume "$release_stage:/release:ro" --workdir /release \
  --entrypoint sh "$candidate_tag" -c '
    set -eu
    /app/.venv/bin/python scripts/release_integrity.py --archive
    /app/.venv/bin/python scripts/public_release_audit.py --archive
    /app/.venv/bin/python -m unittest tests.test_deployment_security -v
  '
stage='running_hermetic_release_tests'
sudo docker run --rm --network none --env HOME=/tmp \
  --env PYTHONDONTWRITEBYTECODE=1 --env RELEASE_ARCHIVE=1 \
  --read-only --tmpfs /tmp --volume "$release_stage:/release:ro" \
  --workdir /release --entrypoint /app/.venv/bin/python \
  "$candidate_tag" \
  -m pytest tests collector/tests home_assistant/tests
stage='smoke_testing_release_image'
sudo docker run -d --name "$smoke_container" --network none --read-only \
  --tmpfs /tmp --tmpfs /data --entrypoint sh "$candidate_tag" -c '
    set -eu
    for name in ha_token oauth_hash jwt_secret origin_secret; do
      printf sanitized-test-value > "/tmp/$name"
    done
    export PUBLIC_BASE_URL=https://example.invalid
    export FRONTEND_PUBLIC_URL=https://frontend.example.invalid
    export HA_BASE_URL=http://127.0.0.1:1
    export HA_TOKEN_FILE=/tmp/ha_token
    export OAUTH_PASSWORD_HASH_FILE=/tmp/oauth_hash
    export JWT_SECRET_FILE=/tmp/jwt_secret
    export ORIGIN_SHARED_SECRET_FILE=/tmp/origin_secret
    export DATABASE_PATH=/data/mcp.sqlite
    export AUDIT_LOG_PATH=/data/audit.jsonl
    export HA_CONFIG_PATH=/data/automations.yaml
    export BACKUP_PATH=/data/backups
    exec uvicorn app.server:app --host 127.0.0.1 --port 8000 --no-proxy-headers
  '
for attempt in $(seq 1 20); do
  if sudo docker exec "$smoke_container" python -c \
    'import socket; socket.create_connection(("127.0.0.1", 8000), 1).close()'; then
    break
  fi
  sleep 1
done
sudo docker exec "$smoke_container" python -c \
  'import socket; socket.create_connection(("127.0.0.1", 8000), 1).close()'
sudo docker rm -f "$smoke_container" >/dev/null

stage='running_live_read_only_preflight'
sudo docker run -d --name "$preflight_container" --network host --read-only \
  --env-file "$app_root/.env" \
  --env PUBLIC_BASE_URL=https://preflight.invalid \
  --env PRODUCTION_VERIFY_BASE_URL=http://127.0.0.1:8001 \
  --env MCP_LOCAL_BASE_URL=http://127.0.0.1:8001 \
  --env MCP_ALLOWED_HOSTS=127.0.0.1,localhost \
  --env HA_BASE_URL=http://127.0.0.1:8123 \
  --env HA_TOKEN_FILE=/run/secrets/ha_token \
  --env OAUTH_PASSWORD_HASH_FILE=/run/secrets/oauth_password_hash \
  --env JWT_SECRET_FILE=/run/secrets/jwt_secret \
  --env ORIGIN_SHARED_SECRET_FILE=/run/secrets/origin_shared_secret \
  --env DATABASE_PATH=/data/oauth.sqlite3 \
  --env AUDIT_LOG_PATH=/logs/audit.jsonl \
  --env HA_CONFIG_PATH=/ha-config \
  --env BACKUP_PATH=/backups \
  --env HOST_DIAGNOSTICS_PATH=/host-diagnostics \
  --volume "$app_root/secrets:/run/secrets:ro" \
  --volume /opt/homeassistant/config:/ha-config:ro \
  --volume /var/lib/ha-host-diagnostics/export:/host-diagnostics:ro \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --tmpfs /data:rw,noexec,nosuid,size=32m \
  --tmpfs /logs:rw,noexec,nosuid,size=32m \
  --tmpfs /backups:rw,noexec,nosuid,size=32m \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --entrypoint /app/.venv/bin/uvicorn "$candidate_tag" \
  app.server:app --host 127.0.0.1 --port 8001 --no-proxy-headers
for attempt in $(seq 1 30); do
  if curl --fail --silent --max-time 5 http://127.0.0.1:8001/healthz \
    >/tmp/ha-mcp-preflight-health.json; then
    break
  fi
  sudo docker inspect -f '{{.State.Running}}' "$preflight_container" | grep -Fxq true
  sleep 1
done
curl --fail --silent --max-time 5 http://127.0.0.1:8001/healthz \
  >/tmp/ha-mcp-preflight-health.json
python3 -c 'import json; p=json.load(open("/tmp/ha-mcp-preflight-health.json", encoding="utf-8")); assert p.get("status") == "ok" and p.get("service_version") == "2.7.3"'
sudo docker exec "$preflight_container" python -m scripts.production_mcp_verify
sudo docker rm -f "$preflight_container" >/dev/null
rm -f /tmp/ha-mcp-preflight-health.json
if [ "$preflight_only" = 1 ]; then
  stage='preflight_complete'
  printf 'Production candidate %s passed live read-only preflight; no service was deployed.\n' \
    "$release_commit"
  exit 0
fi

sudo install -d -o root -g root -m 0700 "$backup_root"
sudo tar -czf "$app_backup" \
  --exclude='./secrets' --exclude='./data' --exclude='./logs' --exclude='./backups' \
  -C "$app_root" .
if [ -f "$collector_unit" ]; then
  unit_existed=1
  prior_collector_enabled=$(sudo systemctl is-enabled ha-host-diagnostics.service 2>/dev/null || true)
  prior_collector_active=$(sudo systemctl is-active ha-host-diagnostics.service 2>/dev/null || true)
  prior_collector_active_enter=$(sudo systemctl show -p ActiveEnterTimestampMonotonic --value ha-host-diagnostics.service 2>/dev/null || true)
fi
collector_candidate_hash=$(collector_content_hash \
  "$release_stage/collector/ha_host_diagnostics.py" \
  "$release_stage/collector/README.md" \
  "$release_stage/collector/ha-host-diagnostics.service")
collector_installed_hash=$(collector_content_hash \
  "$collector_program" "$collector_root/README.md" "$collector_unit")
if [ "$collector_candidate_hash" != "$collector_installed_hash" ]; then
  collector_changed=1
  if [ -d "$collector_root" ]; then
    collector_existed=1
    sudo tar -czf "$collector_backup" -C / "${collector_root#/}"
  fi
  if [ "$unit_existed" -eq 1 ]; then
    sudo cp --preserve=mode,ownership,timestamps "$collector_unit" "$unit_backup"
  fi
fi
if sudo docker container inspect ha-chatgpt-mcp >/dev/null 2>&1; then
  prior_image_id=$(sudo docker container inspect -f '{{.Image}}' ha-chatgpt-mcp)
  prior_image_ref=$(sudo docker container inspect -f '{{.Config.Image}}' ha-chatgpt-mcp)
  sudo docker image tag "$prior_image_id" "$rollback_tag"
fi
homeassistant_started_before=$(sudo docker container inspect -f '{{.State.StartedAt}}' homeassistant)
caddy_started_before=$(sudo docker container inspect -f '{{.State.StartedAt}}' caddy)
prior_tunnel_image_id=$(sudo docker container inspect -f '{{.Image}}' ha-chatgpt-cloudflared)
prior_tunnel_image_ref=$(sudo docker container inspect -f '{{.Config.Image}}' ha-chatgpt-cloudflared)
prior_tunnel_started=$(sudo docker container inspect -f '{{.State.StartedAt}}' ha-chatgpt-cloudflared)
prior_tunnel_config_hash=$(tunnel_config_hash "$app_root/docker-compose.yml")
candidate_tunnel_config_hash=$(tunnel_config_hash "$release_stage/docker-compose.yml")
candidate_tunnel_image_ref=$(tunnel_image_ref "$release_stage/docker-compose.yml")
desired_tunnel_image_id=$(sudo docker image inspect -f '{{.Id}}' "$candidate_tunnel_image_ref")
if [ "$prior_tunnel_config_hash" != "$candidate_tunnel_config_hash" ] || \
   [ "$prior_tunnel_image_id" != "$desired_tunnel_image_id" ]; then
  tunnel_changed=1
  sudo docker image tag "$prior_tunnel_image_id" "$tunnel_rollback_tag"
fi

mutated=1
sudo docker image tag "$candidate_tag" "ha-chatgpt-mcp:$release_version"
stage='installing_release_files'
sudo find "$app_root" -mindepth 1 -maxdepth 1 \
  ! -name .env ! -name secrets ! -name data ! -name logs ! -name backups \
  -exec rm -rf -- {} +
sudo tar -C "$release_stage" -cf - . | sudo tar -C "$app_root" -xf -
if [ -s /tmp/solaredge_client_id ]; then
  for secret_name in solaredge_client_id solaredge_client_secret solaredge_token_key solaredge_bridge_secret; do
    sudo install -o 10001 -g 10001 -m 0400 "/tmp/$secret_name" "$app_root/secrets/$secret_name"
  done
fi

if [ "$collector_changed" -eq 1 ]; then
  sudo install -d -o root -g root -m 0750 "$collector_root"
  sudo install -d -o root -g 10001 -m 0750 "$collector_state"
  sudo install -d -o root -g root -m 0700 "$collector_state/state"
  sudo install -d -o root -g 10001 -m 0750 "$collector_state/export"
  sudo /usr/bin/python3 -m py_compile "$app_root/collector/ha_host_diagnostics.py"
  collector_validation=$(sudo /usr/bin/python3 "$app_root/collector/ha_host_diagnostics.py" validate)
  python3 -c 'import json, sys; assert json.load(sys.stdin).get("ok") is True' <<<"$collector_validation"
  sudo install -o root -g root -m 0750 \
    "$app_root/collector/ha_host_diagnostics.py" "$collector_program"
  sudo install -o root -g root -m 0644 \
    "$app_root/collector/README.md" "$collector_root/README.md"
  sudo install -o root -g root -m 0644 \
    "$app_root/collector/ha-host-diagnostics.service" "$collector_unit"
  sudo /usr/bin/python3 -m py_compile "$collector_program"
  collector_validation=$(sudo /usr/bin/python3 "$collector_program" validate)
  python3 -c 'import json, sys; assert json.load(sys.stdin).get("ok") is True' <<<"$collector_validation"
  sudo systemd-analyze verify "$collector_unit"
  sudo systemctl daemon-reload
  stage='starting_changed_collector'
  collector_started_epoch=$(date -u +%s)
  sudo systemctl enable ha-host-diagnostics.service
  sudo systemctl restart ha-host-diagnostics.service
  stage='awaiting_fresh_collector_snapshot'
  for attempt in $(seq 1 180); do
    if sudo test -s "$collector_state/export/current.json" && \
       [ "$(sudo stat -c %Y "$collector_state/export/current.json")" -ge "$collector_started_epoch" ]; then
      break
    fi
    sudo systemctl is-active --quiet ha-host-diagnostics.service
    sleep 1
  done
  sudo test -s "$collector_state/export/current.json"
  collector_snapshot_epoch=$(sudo stat -c %Y "$collector_state/export/current.json")
  [ "$collector_snapshot_epoch" -ge "$collector_started_epoch" ]
else
  stage='verifying_unchanged_collector'
  [ "$(collector_content_hash "$collector_program" "$collector_root/README.md" "$collector_unit")" = "$collector_candidate_hash" ]
  sudo systemctl is-enabled --quiet ha-host-diagnostics.service
  sudo systemctl is-active --quiet ha-host-diagnostics.service
  [ "$(sudo systemctl show -p ActiveEnterTimestampMonotonic --value ha-host-diagnostics.service)" = "$prior_collector_active_enter" ]
fi
stage='recording_start_marker'
record_marker started

cd "$app_root"
stage='validating_compose'
sudo docker compose config --quiet
stage='running_host_security_tests'
sudo /usr/bin/python3 -m unittest tests.test_deployment_security -v
stage='capturing_pre_overlay_runtime'
sudo install -d -o root -g root -m 0700 "$overlay_baseline"
sudo python3 - <<'PY' | sudo tee "$overlay_baseline/device_id" >/dev/null
import json
with open('/opt/homeassistant/config/.storage/core.device_registry', encoding='utf-8') as handle:
    devices = json.load(handle)['data']['devices']
matches = [item['id'] for item in devices if item.get('manufacturer') == 'WyzeLabs' and item.get('model') == 'BS_WK1']
assert len(matches) == 1
print(matches[0])
PY
capture_loaded_entries_main "$overlay_baseline/loaded-before.json"
capture_overlay_runtime_main "$overlay_baseline/runtime-before.json"
stage='deploying_wyze_overlay'
if [ "$reuse_verified_overlay" = 1 ]; then
  stage='verifying_reused_wyze_overlay'
  candidate_overlay="$release_stage/home_assistant/wyzeapi_overlay/custom_components/wyzeapi"
  for name in manifest.json __init__.py const.py irrigation.py irrigation_data.py sensor.py services.yaml; do
    sudo test -f "$candidate_overlay/$name"
    sudo cmp --silent "$candidate_overlay/$name" "$overlay_target/$name"
  done
  sudo python3 -c 'import json,sys; assert json.load(open(sys.argv[1], encoding="utf-8")).get("version") == "0.1.40"' \
    "$overlay_target/manifest.json"
else
  sudo install -d -o root -g root -m 0700 "$(dirname "$overlay_backup")"
  sudo test ! -e "$overlay_backup"
  sudo tar -czf "$overlay_backup" -C /opt/homeassistant/config/custom_components wyzeapi
  overlay_mutated=1
  bash "/tmp/__OVERLAY_SCRIPT_NAME__" "$overlay_backup"
  sudo test -f "$overlay_backup"
  if [ "${HA_MCP_FAIL_AFTER_OVERLAY_SUCCESS:-0}" = 1 ]; then
    stage='injected_failure_after_overlay_success'
    false
  fi
fi
homeassistant_started_before=$(sudo docker container inspect -f '{{.State.StartedAt}}' homeassistant)
stage='recreating_mcp'
sudo docker compose up -d --no-deps --force-recreate ha-chatgpt-mcp
if [ "$tunnel_changed" -eq 1 ]; then
  stage='recreating_changed_tunnel'
  sudo docker compose up -d --no-deps --force-recreate cloudflared
else
  test "$(sudo docker container inspect -f '{{.State.StartedAt}}' ha-chatgpt-cloudflared)" = "$prior_tunnel_started"
fi
test "$(sudo docker container inspect -f '{{.Image}}' ha-chatgpt-mcp)" = "$tested_image_id"
test "$(sudo docker image inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
  "$tested_image_id")" = "$release_commit"

stage='waiting_for_mcp_health'
for attempt in $(seq 1 30); do
  if curl --fail --silent --max-time 5 http://127.0.0.1:8000/healthz > /tmp/ha-mcp-health.json; then
    break
  fi
  sleep 1
done
curl --fail --silent --max-time 5 http://127.0.0.1:8000/healthz > /tmp/ha-mcp-health.json
python3 - <<'PY'
import json
with open('/tmp/ha-mcp-health.json', encoding='utf-8') as handle:
    payload = json.load(handle)
assert payload.get('status') == 'ok'
assert payload.get('home_assistant', {}).get('reachable') is True
assert payload.get('service_version') == '2.7.3'
PY
rm -f /tmp/ha-mcp-health.json
curl --fail --silent --max-time 5 http://127.0.0.1:8123/ >/dev/null
stage='validating_fixed_routes'
ha_public_status=$(curl --silent --output /dev/null --max-time 10 --write-out '%{http_code}' __PUBLIC_FRONTEND_URL__/)
case "$ha_public_status" in
  200|302|403) ;;
  *) exit 1 ;;
esac
curl --fail --silent --max-time 10 __PUBLIC_MCP_URL__/healthz >/dev/null
curl --fail --silent --max-time 5 http://127.0.0.1:49312/metrics >/dev/null
sudo docker compose exec -T ha-chatgpt-mcp python -m scripts.production_mcp_verify
test "$(sudo docker container inspect -f '{{.State.StartedAt}}' homeassistant)" = "$homeassistant_started_before"
test "$(sudo docker container inspect -f '{{.State.StartedAt}}' caddy)" = "$caddy_started_before"
if [ "$tunnel_changed" -eq 1 ]; then
  test "$(sudo docker container inspect -f '{{.Image}}' ha-chatgpt-cloudflared)" = "$desired_tunnel_image_id"
else
  test "$(sudo docker container inspect -f '{{.State.StartedAt}}' ha-chatgpt-cloudflared)" = "$prior_tunnel_started"
fi

stage='validating_runtime_hardening'
sudo systemctl is-enabled --quiet ha-host-diagnostics.service
sudo systemctl is-active --quiet ha-host-diagnostics.service
test "$(sudo stat -c '%u:%g:%a' "$collector_state")" = '0:10001:750'
test "$(sudo stat -c '%u:%g:%a' "$collector_state/state")" = '0:0:700'
test "$(sudo stat -c '%u:%g:%a' "$collector_state/export")" = '0:10001:750'
sudo find "$collector_state/export" -type f -printf '%u:%g:%m %p\n' | \
  awk '$1 != "root:10001:640" { bad=1 } END { exit bad }'
sudo python3 - <<'PY'
import datetime as dt
import json
from pathlib import Path
export = Path('/var/lib/ha-host-diagnostics/export')
current = export / 'current.json'
assert current.stat().st_size <= 256 * 1024
with current.open(encoding='utf-8') as handle:
    payload = json.load(handle)
observed = (payload.get('collector') or {}).get('observed_at') or payload.get('timestamp')
assert isinstance(observed, str)
stamp = dt.datetime.fromisoformat(observed.replace('Z', '+00:00'))
assert dt.datetime.now(dt.timezone.utc) - stamp < dt.timedelta(minutes=3)
segments = list(export.glob('*.jsonl'))
assert all(path.stat().st_size <= 4 * 1024 * 1024 for path in segments)
assert sum(path.stat().st_size for path in export.iterdir() if path.is_file()) <= 32 * 1024 * 1024
cutoff = dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=7)
assert not any(dt.date.fromisoformat(path.stem[-10:]) < cutoff for path in segments)
PY

unit_properties=$(sudo systemctl show ha-host-diagnostics.service \
  -p NoNewPrivileges -p ProtectHome -p ProtectSystem -p PrivateTmp \
  -p ProtectKernelTunables -p ProtectKernelModules -p ProtectControlGroups \
  -p RestrictSUIDSGID -p LockPersonality)
for expected in \
  'NoNewPrivileges=yes' 'ProtectHome=yes' 'ProtectSystem=strict' 'PrivateTmp=yes' \
  'ProtectKernelTunables=yes' 'ProtectKernelModules=yes' 'ProtectControlGroups=yes' \
  'RestrictSUIDSGID=yes' 'LockPersonality=yes'; do
  grep -Fxq "$expected" <<<"$unit_properties"
done

sudo docker inspect ha-chatgpt-mcp | python3 -c '
import json, sys
container = json.load(sys.stdin)[0]
mounts = container["Mounts"]
forbidden = {"/var/run/docker.sock", "/run/docker.sock", "/proc", "/sys", "/run/log/journal", "/var/log/journal"}
assert not any(mount.get("Source") in forbidden for mount in mounts)
diagnostics = [mount for mount in mounts if mount.get("Destination") == "/host-diagnostics"]
assert len(diagnostics) == 1 and diagnostics[0].get("RW") is False
'
if sudo ss -H -lnt | awk '$4 ~ /(^|:)8000$/ && $4 !~ /^127\.0\.0\.1:8000$/ { exit 1 }'; then :; else
  echo 'MCP port 8000 is not limited to loopback.' >&2
  exit 1
fi
if sudo ss -H -lnt | awk '$4 ~ /(^|:)49312$/ && $4 !~ /^127\.0\.0\.1:49312$/ { exit 1 }'; then :; else
  echo 'Cloudflared metrics port 49312 is not limited to loopback.' >&2
  exit 1
fi
if sudo ss -H -lntp | grep -F 'ha_host_diagnostics' >/dev/null; then
  echo 'The host diagnostics collector unexpectedly opened a listener.' >&2
  exit 1
fi

sudo docker inspect -f 'image={{.Config.Image}} status={{.State.Status}} restarts={{.RestartCount}}' ha-chatgpt-mcp
sudo docker inspect -f 'status={{.State.Status}} restarts={{.RestartCount}}' ha-chatgpt-cloudflared
sudo docker inspect -f 'status={{.State.Status}} oom_killed={{.State.OOMKilled}} started={{.State.StartedAt}}' homeassistant
stage='recording_completion_marker'
record_marker completed
record_status complete
mutated=0
trap - EXIT
cleanup_staging
'@
$remoteScript = $remoteScript.Replace(
    '__PUBLIC_FRONTEND_URL__', $PublicFrontendUrl.TrimEnd('/')
).Replace(
    '__PUBLIC_MCP_URL__', $PublicMcpUrl.TrimEnd('/')
).Replace(
    '__RELEASE_COMMIT__', $releaseCommit
).Replace(
    '__OVERLAY_ARCHIVE_NAME__', $overlayArchiveName
).Replace(
    '__OVERLAY_SCRIPT_NAME__', $overlayScriptName
)

try {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    # git archive guarantees that ignored, untracked, and private helper files
    # cannot enter the public release payload or its Docker build context.
    & $gitExe -C $sourceRoot archive '--format=tar.gz' "--output=$archivePath" $releaseCommit
    if ($LASTEXITCODE -ne 0) { throw 'Could not build the deployment archive.' }
    $archiveSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    & $gitExe -C $sourceRoot archive '--format=tar.gz' "--output=$overlayArchivePath" `
        $releaseCommit 'home_assistant/wyzeapi_overlay'
    if ($LASTEXITCODE -ne 0) { throw 'Could not build the exact overlay archive.' }
    $overlayArchiveSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $overlayArchivePath).Hash.ToLowerInvariant()
    $overlaySource = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'deploy-wyzeapi-overlay.ps1')
    $overlayMatch = [regex]::Match(
        $overlaySource,
        "(?s)\`$remoteScript = @'\r?\n(.*?)\r?\n'@"
    )
    if (-not $overlayMatch.Success) { throw 'Could not extract the reviewed overlay remote script.' }
    $overlayStageBasename = ".wyzeapi-overlay-candidate-$releaseCommit"
    $renderedOverlayScript = $overlayMatch.Groups[1].Value.Replace(
        '__RELEASE_COMMIT__', $releaseCommit
    ).Replace('__ARCHIVE_SHA256__', $overlayArchiveSha).Replace(
        '__ARCHIVE_NAME__', $overlayArchiveName
    ).Replace('__SCRIPT_NAME__', $overlayScriptName).Replace(
        '__STAGE_BASENAME__', $overlayStageBasename
    )
    [IO.File]::WriteAllText(
        $overlayScriptPath,
        (($renderedOverlayScript -replace "`r`n", "`n") + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    $preflightFlag = if ($PreflightOnly) { '1' } else { '0' }
    $reuseOverlayFlag = if ($ReuseVerifiedWyzeOverlay) { '1' } else { '0' }
    $renderedRemoteScript = $remoteScript.Replace('__ARCHIVE_SHA256__', $archiveSha256).Replace(
        '__PREFLIGHT_ONLY__', $preflightFlag
    ).Replace(
        '__REUSE_VERIFIED_OVERLAY__', $reuseOverlayFlag
    )
    [IO.File]::WriteAllText(
        $remoteScriptPath,
        (($renderedRemoteScript -replace "`r`n", "`n") + "`n"),
        [Text.UTF8Encoding]::new($false)
    )

    $access = & $awsExe lightsail get-instance-access-details --profile $AwsProfile --region $AwsRegion `
        --instance-name $InstanceName --protocol ssh --output json | ConvertFrom-Json
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

    # A detached, bounded fail-safe closes this exact /32 even if the parent
    # process is terminated so abruptly that PowerShell cannot execute finally.
    $failsafeBody = @"
`$ErrorActionPreference = 'SilentlyContinue'
Start-Sleep -Seconds 1200
& '$awsExe' lightsail close-instance-public-ports --profile '$AwsProfile' --region '$AwsRegion' --instance-name '$InstanceName' --port-info 'fromPort=22,toPort=22,protocol=tcp,cidrs=$temporarySshCidr' --output json | Out-Null
"@
    [IO.File]::WriteAllText(
        $sshFailsafePath,
        (($failsafeBody -replace "`r`n", "`n") + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    $sshFailsafeProcess = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $sshFailsafePath) `
        -WindowStyle Hidden -PassThru

    $target = "$($access.accessDetails.username)@$($access.accessDetails.ipAddress)"
    $sshOptions = @(
        '-i', $keyPath,
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=60',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', "UserKnownHostsFile=$knownHostsPath"
    )
    & $scpExe @sshOptions $archivePath "${target}:/tmp/$archiveName"
    if ($LASTEXITCODE -ne 0) { throw 'Could not upload the deployment archive.' }
    & $scpExe @sshOptions $remoteScriptPath "${target}:/tmp/$remoteScriptName"
    if ($LASTEXITCODE -ne 0) { throw 'Could not upload the deployment script.' }
    & $scpExe @sshOptions $overlayArchivePath "${target}:/tmp/$overlayArchiveName"
    if ($LASTEXITCODE -ne 0) { throw 'Could not upload the exact overlay archive.' }
    & $scpExe @sshOptions $overlayScriptPath "${target}:/tmp/$overlayScriptName"
    if ($LASTEXITCODE -ne 0) { throw 'Could not upload the overlay deployment script.' }
    if ($secretRoot) {
        foreach ($name in $requiredSecrets) {
            & $scpExe @sshOptions (Join-Path $secretRoot $name) "${target}:/tmp/$name"
            if ($LASTEXITCODE -ne 0) { throw "Could not upload $name." }
        }
    }

    $priorErrorActionPreference = $ErrorActionPreference
    $priorNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $PSNativeCommandUseErrorActionPreference = $false
        $remoteOutput = & $sshExe @sshOptions $target "bash /tmp/$remoteScriptName" 2>&1
        $remoteExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorErrorActionPreference
        $PSNativeCommandUseErrorActionPreference = $priorNativeErrorPreference
    }
    foreach ($line in $remoteOutput) {
        [Console]::Out.WriteLine([string]$line)
    }
    if ($remoteExitCode -ne 0) { throw 'Production deployment failed and the remote rollback was invoked.' }
}
finally {
    $firewallCloseFailed = $false
    if ($firewallOpened -and $temporarySshCidr) {
        & $awsExe lightsail close-instance-public-ports --profile $AwsProfile --region $AwsRegion `
            --instance-name $InstanceName `
            --port-info "fromPort=22,toPort=22,protocol=tcp,cidrs=$temporarySshCidr" --output json | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $firewallCloseFailed = $true
        }
    }
    if (-not $firewallCloseFailed -and $sshFailsafeProcess -and -not $sshFailsafeProcess.HasExited) {
        Stop-Process -Id $sshFailsafeProcess.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $sshFailsafeProcess.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $tempDir) {
        $resolved = [IO.Path]::GetFullPath($tempDir)
        if (-not $resolved.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase) -or
            -not ([IO.Path]::GetFileName($resolved)).StartsWith('ha-mcp-deploy-')) {
            throw "Refusing to remove unexpected temporary path: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    if ($firewallCloseFailed) {
        throw 'Could not close the temporary SSH firewall rule.'
    }
}
