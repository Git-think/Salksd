#!/bin/bash
# Only synthetic backups in a fresh fixture. No production data or platform calls.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/lib/unbound-secure.sh"
if [[ "$(uname -s)" == MINGW* ]]; then
    unset MSYS_NO_PATHCONV
    # Windows fixture paths use C:/ for jq.exe; GNU tar otherwise treats C: as a host.
    tar() { command tar --force-local "$@"; }
fi
TEST_ROOT=${SALKSD_BACKUP_TEST_ROOT:-$(mktemp -d)}
WORKDIR="$TEST_ROOT/site/logs"; FILE_PATH="$TEST_ROOT/site/public_html"
SALKSD_STATE_DIR="$TEST_ROOT/state";USERNAME=fixture;CURRENT_DOMAIN=example.test
TLS_SERVER_NAME=api.fixture.example.test
mkdir -p "$WORKDIR" "$FILE_PATH/.salksd-data"
secure_prepare_certificate
printf 'fixture-only\n' > "$WORKDIR/keepalive.conf"
printf 'fixture-only\n' > "$FILE_PATH/index.html"
secure_jq -n '{inbounds:[{type:"tuic",users:[]}]}' > "$SECURE_STATE/server.json"
printf '%064d\n' 0 > "$SECURE_STATE/token"
make_backup() {
    local name=$1 dest="$SECURE_STATE/backups/$1"
    mkdir "$dest"
    cp "$SECURE_STATE/"{cert.pem,private.key,server.json,token} "$dest/"
    tar -czf "$dest/site.tgz" -C "$TEST_ROOT/site" logs public_html
}
for number in 01 02 03 04; do make_backup "202601${number}-000000-123-abcdef"; done
printf '%s\n' "$SECURE_STATE/backups/20260102-000000-123-abcdef" > "$SECURE_STATE/last-backup"
mkdir "$SECURE_STATE/backups/landing-keep" "$SECURE_STATE/backups/manual-keep" "$TEST_ROOT/outside"
printf 'outside\n' > "$TEST_ROOT/outside/sentinel"
has_symlinks=true
if ! MSYS=winsymlinks:nativestrict ln -s "$TEST_ROOT/outside" "$SECURE_STATE/backups/20260105-000000-123-abcdef"; then
    [[ "$(uname -s)" == MINGW* ]] || exit 1
    has_symlinks=false
    echo 'SKIP: Windows cannot create symlinks; the Linux workflow must exercise these cases'
fi
secure_backups_refresh
secure_jq -e '(.items|length)==4 and .can_prune and ([.items[]|select(.protected)]|length)==2' "$FILE_PATH/.salksd-data/backups.json" >/dev/null
make_request() { secure_jq --argjson keep "$1" '{keep:$keep,revision:.revision}' "$FILE_PATH/.salksd-data/backups.json" > "$SECURE_STATE/request.json"; }
make_request 1
# Changing the inventory after preview must reject the entire request.
make_backup 20260106-000000-123-abcdef
if secure_backups_prune "$SECURE_STATE/request.json"; then exit 1; fi
[[ -d "$SECURE_STATE/backups/20260101-000000-123-abcdef" ]]
make_request 0
if secure_backups_prune "$SECURE_STATE/request.json"; then exit 1; fi
secure_backups_refresh
make_request 1
secure_backups_prune "$SECURE_STATE/request.json"
[[ -d "$SECURE_STATE/backups/20260106-000000-123-abcdef" && -d "$SECURE_STATE/backups/20260102-000000-123-abcdef" ]]
[[ ! -e "$SECURE_STATE/backups/20260101-000000-123-abcdef" && ! -e "$SECURE_STATE/backups/20260103-000000-123-abcdef" ]]
[[ -d "$SECURE_STATE/backups/landing-keep" && -d "$SECURE_STATE/backups/manual-keep" ]]
[[ "$has_symlinks" == false || -L "$SECURE_STATE/backups/20260105-000000-123-abcdef" ]]
grep -qx outside "$TEST_ROOT/outside/sentinel"
echo 'PASS: retention and recovery pointer preserved; stale preview and zero retention refused'
# A corrupt newest archive must not displace the last complete recovery point.
make_backup 20260107-000000-123-abcdef
printf 'broken archive\n' > "$SECURE_STATE/backups/20260107-000000-123-abcdef/site.tgz"
secure_backups_refresh
secure_jq -e 'any(.items[]; .id=="20260106-000000-123-abcdef" and .reason=="最近完整恢复点")' "$FILE_PATH/.salksd-data/backups.json" >/dev/null
make_request 1
secure_backups_prune "$SECURE_STATE/request.json"
[[ -d "$SECURE_STATE/backups/20260106-000000-123-abcdef" ]]
echo 'PASS: broken newest snapshot cannot remove the last complete recovery point'
# Candidate entries are preflighted before any deletion, without recursive rm.
if [[ "$has_symlinks" == true ]]; then
    make_backup 20260101-000000-123-abcdef
    MSYS=winsymlinks:nativestrict ln -s "$TEST_ROOT/outside/sentinel" "$SECURE_STATE/backups/20260101-000000-123-abcdef/link"
    secure_backups_refresh; make_request 1
    if secure_backups_prune "$SECURE_STATE/request.json"; then exit 1; fi
    [[ -s "$SECURE_STATE/backups/20260101-000000-123-abcdef/site.tgz" ]]
    grep -qx outside "$TEST_ROOT/outside/sentinel"
    echo 'PASS: nested symlinks reject cleanup before removing any snapshot files'
fi
# Exercise the real transaction dispatch: cleanup/refresh cannot back up or restart.
load_config() { :; }
secure_backup() { echo 'ERROR: cleanup created a backup' >&2; return 1; }
secure_prepare_certificate() { echo 'ERROR: cleanup entered restart path' >&2; return 1; }
secure_backups_refresh
make_request 1000
secure_operation --backup-prune all "$SECURE_STATE/request.json"
secure_operation --backup-refresh all "$SECURE_STATE/request.json"
[[ ! -d "$SECURE_STATE/operation.lock" ]]
echo 'PASS: real cleanup dispatch neither creates backup nor restarts core'
