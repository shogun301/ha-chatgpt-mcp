param(
    [string]$SecretStagingPath,
    [Parameter(Mandatory)][string]$AwsProfile,
    [Parameter(Mandatory)][string]$AwsRegion,
    [Parameter(Mandatory)][string]$InstanceName,
    [Parameter(Mandatory)][ValidatePattern('^https://')][string]$PublicFrontendUrl,
    [Parameter(Mandatory)][ValidatePattern('^https://')][string]$PublicMcpUrl
)

$ErrorActionPreference = 'Stop'

$releaseVersion = '2.6.3'
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
    'collector/README.md'
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
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempDir = Join-Path $tempBase ("ha-mcp-deploy-" + [guid]::NewGuid().ToString('N'))
$keyPath = Join-Path $tempDir 'lightsail'
$certPath = "$keyPath-cert.pub"
$knownHostsPath = Join-Path $tempDir 'known_hosts'
$archiveName = "ha-chatgpt-mcp-$releaseVersion.tar.gz"
$remoteScriptName = "ha-chatgpt-mcp-deploy-$releaseVersion.sh"
$archivePath = Join-Path $tempDir $archiveName
$remoteScriptPath = Join-Path $tempDir $remoteScriptName
$sshFailsafePath = Join-Path $tempDir 'close-temporary-ssh.ps1'
$firewallOpened = $false
$temporarySshCidr = $null
$sshFailsafeProcess = $null

$remoteScript = @'
#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

release_version='2.6.3'
release_commit='__RELEASE_COMMIT__'
archive_sha256='__ARCHIVE_SHA256__'
archive_path='/tmp/ha-chatgpt-mcp-2.6.3.tar.gz'
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
mutated=0
collector_existed=0
unit_existed=0
prior_image_id=''
prior_image_ref=''
tested_image_id=''
smoke_container="ha-mcp-release-smoke-$stamp"
prior_collector_enabled='disabled'
prior_collector_active='inactive'
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
  sudo docker rm -f "$smoke_container" >/dev/null 2>&1 || true
  sudo docker image rm "$candidate_tag" >/dev/null 2>&1 || true
  sudo rm -rf -- "$release_stage"
  sudo rm -f -- "$archive_path" "/tmp/ha-chatgpt-mcp-deploy-$release_version.sh"
  for secret_name in solaredge_client_id solaredge_client_secret solaredge_token_key solaredge_bridge_secret; do
    sudo rm -f -- "/tmp/$secret_name"
  done
}

rollback() {
  set +e
  record_marker rolled_back
  sudo systemctl stop ha-host-diagnostics.service >/dev/null 2>&1
  if [ -f "$app_backup" ]; then
    sudo find "$app_root" -mindepth 1 -maxdepth 1 \
      ! -name secrets ! -name data ! -name logs ! -name backups \
      -exec rm -rf -- {} +
    sudo tar -xzf "$app_backup" -C "$app_root"
  fi
  if [ "$collector_existed" -eq 1 ] && [ -f "$collector_backup" ]; then
    sudo rm -rf -- "$collector_root"
    sudo tar -xzf "$collector_backup" -C /
  else
    sudo rm -rf -- "$collector_root"
  fi
  if [ "$unit_existed" -eq 1 ] && [ -f "$unit_backup" ]; then
    sudo install -o root -g root -m 0644 "$unit_backup" "$collector_unit"
  else
    sudo rm -f -- "$collector_unit"
  fi
  sudo systemctl daemon-reload
  if [ "$unit_existed" -eq 1 ]; then
    if [[ "$prior_collector_enabled" == enabled* ]]; then
      sudo systemctl enable ha-host-diagnostics.service >/dev/null 2>&1
    else
      sudo systemctl disable ha-host-diagnostics.service >/dev/null 2>&1
    fi
    if [ "$prior_collector_active" = 'active' ]; then
      sudo systemctl restart ha-host-diagnostics.service >/dev/null 2>&1
    fi
  else
    sudo systemctl disable ha-host-diagnostics.service >/dev/null 2>&1
  fi
  if [ -n "$prior_image_id" ] && [ -n "$prior_image_ref" ]; then
    sudo docker image tag "$rollback_tag" "$prior_image_ref"
  fi
  if [ -f "$app_root/docker-compose.yml" ]; then
    cd "$app_root"
    sudo docker compose up -d --no-deps --force-recreate ha-chatgpt-mcp cloudflared >/dev/null 2>&1
  fi
  set -e
}

on_exit() {
  local exit_code=$?
  trap - EXIT
  if [ "$exit_code" -ne 0 ] && [ "$mutated" -eq 1 ]; then
    record_status failed
    rollback
  fi
  cleanup_staging
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

sudo install -d -o root -g root -m 0700 "$backup_root"
sudo tar -czf "$app_backup" \
  --exclude='./secrets' --exclude='./data' --exclude='./logs' --exclude='./backups' \
  -C "$app_root" .
if [ -d "$collector_root" ]; then
  collector_existed=1
  sudo tar -czf "$collector_backup" -C / "${collector_root#/}"
fi
if [ -f "$collector_unit" ]; then
  unit_existed=1
  sudo cp --preserve=mode,ownership,timestamps "$collector_unit" "$unit_backup"
  prior_collector_enabled=$(sudo systemctl is-enabled ha-host-diagnostics.service 2>/dev/null || true)
  prior_collector_active=$(sudo systemctl is-active ha-host-diagnostics.service 2>/dev/null || true)
fi
if sudo docker container inspect ha-chatgpt-mcp >/dev/null 2>&1; then
  prior_image_id=$(sudo docker container inspect -f '{{.Image}}' ha-chatgpt-mcp)
  prior_image_ref=$(sudo docker container inspect -f '{{.Config.Image}}' ha-chatgpt-mcp)
  sudo docker image tag "$prior_image_id" "$rollback_tag"
fi
homeassistant_started_before=$(sudo docker container inspect -f '{{.State.StartedAt}}' homeassistant)
caddy_started_before=$(sudo docker container inspect -f '{{.State.StartedAt}}' caddy)

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
stage='starting_collector'
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
stage='recording_start_marker'
record_marker started

cd "$app_root"
stage='validating_compose'
sudo docker compose config --quiet
stage='running_host_security_tests'
sudo /usr/bin/python3 -m unittest tests.test_deployment_security -v
stage='recreating_mcp_and_tunnel'
sudo docker compose up -d --no-deps --force-recreate ha-chatgpt-mcp cloudflared
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
assert payload.get('service_version') == '2.6.3'
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
sudo docker compose exec -T ha-chatgpt-mcp python scripts/production_mcp_verify.py
test "$(sudo docker container inspect -f '{{.State.StartedAt}}' homeassistant)" = "$homeassistant_started_before"
test "$(sudo docker container inspect -f '{{.State.StartedAt}}' caddy)" = "$caddy_started_before"

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
)

try {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    # git archive guarantees that ignored, untracked, and private helper files
    # cannot enter the public release payload or its Docker build context.
    & $gitExe -C $sourceRoot archive '--format=tar.gz' "--output=$archivePath" $releaseCommit
    if ($LASTEXITCODE -ne 0) { throw 'Could not build the deployment archive.' }
    $archiveSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    $renderedRemoteScript = $remoteScript.Replace('__ARCHIVE_SHA256__', $archiveSha256)
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
