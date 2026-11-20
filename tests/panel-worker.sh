#!/bin/bash
# The real queue consumer with a mocked service operation: never changes a port.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/lib/unbound-secure.sh"
TEST_ROOT=$(mktemp -d)
WORKDIR="$TEST_ROOT/site/logs"
FILE_PATH="$TEST_ROOT/site/public_html"
SALKSD_STATE_DIR="$TEST_ROOT/state"
mkdir -p "$WORKDIR" "$FILE_PATH"
secure_init
secure_panel_init
data="$FILE_PATH/.salksd-data"
load_config() { :; }
secure_operation() {
    [[ "$SALKSD_PANEL_IN_WORKER" == 1 ]]
    case "$1" in --change-ports|--share-create|--share-revoke) ;; *) return 1 ;; esac
    printf '%s\n' "${2:-all}" >> "$TEST_ROOT/operations"
    [[ "${FAIL_OPERATION:-0}" == 0 ]]
}
queue() {
    jq -n --argjson at "${1:-$(date +%s)}" '{action:"change-ports",id:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",created_at:$at}' > "$data/request.json"
}
queue
mkdir "$data/queue.lock"
secure_panel_poll
[[ -f "$data/request.json" && ! -f "$TEST_ROOT/operations" ]]
rmdir "$data/queue.lock"
secure_panel_poll
[[ ! -f "$data/request.json" && ! -f "$data/running.json" ]]
jq -e '.status=="success"' "$data/result.json" >/dev/null
secure_panel_poll
[[ $(wc -l < "$TEST_ROOT/operations") -eq 1 ]]
queue
jq '.protocol="tuic"' "$data/request.json" > "$data/request.new"
mv "$data/request.new" "$data/request.json"
secure_panel_poll
[[ "$(tail -n 1 "$TEST_ROOT/operations")" == tuic ]]
queue 1
secure_panel_poll
jq -e '.status=="expired"' "$data/result.json" >/dev/null
printf '{"action":"reset-system"}' > "$data/request.json"
if secure_panel_poll; then echo 'ERROR: accepted invalid command'; exit 1; fi
jq -e '.status=="rejected"' "$data/result.json" >/dev/null
[[ $(wc -l < "$TEST_ROOT/operations") -eq 2 ]]
FAIL_OPERATION=1
queue
secure_panel_poll
jq -e '.status=="failed"' "$data/result.json" >/dev/null
[[ ! -f "$data/running.json" ]]
echo 'PASS: queue claim, one execution, expiry, fixed action allowlist and error result'
