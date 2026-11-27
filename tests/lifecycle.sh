#!/bin/bash
# Offline FreeBSD process/port regression. Platform and process operations are mocked.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/lib/unbound-secure.sh"
TEST_ROOT=${SALKSD_LIFECYCLE_ROOT:-$(mktemp -d)}
WORKDIR="$TEST_ROOT/site/logs"
FILE_PATH="$TEST_ROOT/site/public_html"
SALKSD_STATE_DIR="$TEST_ROOT/state"
mkdir -p "$WORKDIR" "$FILE_PATH"
secure_init
SECURE_BACKUP="$TEST_ROOT/backup"
mkdir -p "$SECURE_BACKUP"
ps() {
    [[ "$1" == -U ]] || { echo 'FreeBSD ps: wrong owner flag' >&2; return 1; }
    [[ "$3" == -o && "$4" == pid= && "$5" == -o && "$6" == args= ]] || { echo 'FreeBSD ps: combined empty-header fields are not portable' >&2; return 1; }
    printf '99101 /bin/bash %s/unbound_start.sh\n' "$WORKDIR"
    printf '99102 /bin/bash /other/unbound_start.sh\n'
    printf '99103 /bin/bash %s/unbound_start.sh --restart\n' "$WORKDIR"
    printf '99104 python unrelated.py\n'
}
pgrep() { printf '99110\n99111\n'; }
procstat() {
    if [[ "$2" == 99110 ]]; then
        printf '99110 unbound cwd v d flags ref offset pro %s\n' "$(cd "$WORKDIR" && pwd -P)"
    else
        printf '99111 unbound cwd v d flags ref offset pro /other\n'
    fi
}
[[ "$(secure_worker_pids)" == 99101 ]]
[[ "$(secure_core_pids)" == 99110 ]]
printf 'tcp 40001\nudp 40002\nudp 40003\n' > "$TEST_ROOT/ports"
VLESS_PORT=40001; TUIC_PORT=40002; HY2_PORT=40003
CONFIG_FILE="$WORKDIR/unbound.conf"
secure_jq -n '{inbounds:[{type:"vless",listen_port:40001},{type:"tuic",listen_port:40002},{type:"hysteria2",listen_port:40003}]}' > "$CONFIG_FILE"
devil() {
    [[ "$1" == port ]] || return 1
    case "$2" in
      list) awk '{print $2,$1}' "$TEST_ROOT/ports" ;;
      del) grep -vx "$3 $4" "$TEST_ROOT/ports" > "$TEST_ROOT/ports.new" || :; mv "$TEST_ROOT/ports.new" "$TEST_ROOT/ports" ;;
      add) if [[ "${FAIL_UDP:-0}" == 1 && "$3" == udp && "$4" != 40002 ]]; then return 1; fi
           printf '%s %s\n' "$3" "$4" >> "$TEST_ROOT/ports" ;;
    esac
}
shuf() {
    local next
    next=$(cat "$TEST_ROOT/next" 2>/dev/null || echo 41000)
    next=$((next+1)); printf '%s\n' "$next" > "$TEST_ROOT/next"; printf '%s\n' "$next"
}
secure_replace_ports
[[ "$VLESS_PORT" == 41001 && "$TUIC_PORT" == 41002 && "$HY2_PORT" == 41003 ]]
secure_jq -e '[.inbounds[].listen_port]==[41001,41002,41003]' "$CONFIG_FILE" >/dev/null
secure_ports_rollback
[[ "$(sort "$TEST_ROOT/ports")" == "$(printf 'tcp 40001\nudp 40002\nudp 40003\n' | sort)" ]]
VLESS_PORT=40001; TUIC_PORT=40002; HY2_PORT=40003
FAIL_UDP=1
if secure_replace_ports; then echo 'ERROR: failed port allocation reported success'; exit 1; fi
secure_ports_rollback
[[ "$(sort "$TEST_ROOT/ports")" == "$(printf 'tcp 40001\nudp 40002\nudp 40003\n' | sort)" ]]
echo 'PASS: FreeBSD process selection, unrelated process exclusion, port update and rollback after partial allocation failure'
FAIL_UDP=0
for target in vless tuic hysteria2; do
    VLESS_PORT=40001; TUIC_PORT=40002; HY2_PORT=40003
    secure_replace_ports "$target"
    case "$target" in
        vless) [[ "$VLESS_PORT" != 40001 && "$TUIC_PORT" == 40002 && "$HY2_PORT" == 40003 ]] ;;
        tuic) [[ "$VLESS_PORT" == 40001 && "$TUIC_PORT" != 40002 && "$HY2_PORT" == 40003 ]] ;;
        hysteria2) [[ "$VLESS_PORT" == 40001 && "$TUIC_PORT" == 40002 && "$HY2_PORT" != 40003 ]] ;;
    esac
    [[ $(wc -l < "$SECURE_BACKUP/added-ports") -eq 1 && $(wc -l < "$SECURE_BACKUP/removed-ports") -eq 1 ]]
    secure_ports_rollback
    [[ "$(sort "$TEST_ROOT/ports")" == "$(printf 'tcp 40001\nudp 40002\nudp 40003\n' | sort)" ]]
done
echo 'PASS: individual VLESS/TUIC/HY2 changes leave both unselected ports unchanged'
# In-process web tasks must not kill their worker/subshells with inherited argv.
secure_worker_pids() { printf '99190\n99191\n'; }
secure_core_pids() { [[ -f "$TEST_ROOT/core-stopped" ]] || printf '99192\n'; }
kill() {
    [[ "$1" == -0 ]] && return 1
    [[ "$1" == 99192 ]] || { echo 'ERROR: web operation killed its worker'; return 1; }
    touch "$TEST_ROOT/core-stopped"
}
sleep() { :; }
SALKSD_PANEL_IN_WORKER=1 secure_stop_managed
[[ -f "$TEST_ROOT/core-stopped" ]]
echo 'PASS: web task stops the core while preserving its own worker and subshells'
