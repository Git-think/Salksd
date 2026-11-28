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
    case "$1" in --change-ports|--share-create|--share-revoke|--share-delete|--share-prune|--backup-refresh|--backup-prune|--rules-save) ;; *) return 1 ;; esac
    printf '%s\n' "${2:-all}" >> "$TEST_ROOT/operations"
    [[ "${FAIL_OPERATION:-0}" == 0 ]]
}
queue() {
    secure_jq -n --argjson at "${1:-$(date +%s)}" '{action:"change-ports",id:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",created_at:$at}' > "$data/request.json"
}
queue
mkdir "$data/queue.lock"
secure_panel_poll
[[ -f "$data/request.json" && ! -f "$TEST_ROOT/operations" ]]
rmdir "$data/queue.lock"
secure_panel_poll
[[ ! -f "$data/request.json" && ! -f "$data/running.json" ]]
secure_jq -e '.status=="success"' "$data/result.json" >/dev/null
secure_panel_poll
[[ $(wc -l < "$TEST_ROOT/operations") -eq 1 ]]
queue
secure_jq '.protocol="tuic"' "$data/request.json" > "$data/request.new"
mv "$data/request.new" "$data/request.json"
secure_panel_poll
[[ "$(tail -n 1 "$TEST_ROOT/operations")" == tuic ]]
queue 1
secure_panel_poll
secure_jq -e '.status=="expired"' "$data/result.json" >/dev/null
printf '{"action":"reset-system"}' > "$data/request.json"
if secure_panel_poll; then echo 'ERROR: accepted invalid command'; exit 1; fi
secure_jq -e '.status=="rejected"' "$data/result.json" >/dev/null
[[ $(wc -l < "$TEST_ROOT/operations") -eq 2 ]]
FAIL_OPERATION=1
queue
secure_panel_poll
secure_jq -e '.status=="failed"' "$data/result.json" >/dev/null
[[ ! -f "$data/running.json" ]]
echo 'PASS: queue claim, one execution, expiry, fixed action allowlist and error result'
FAIL_OPERATION=0
for action in share-delete share-prune; do
    secure_jq -n --arg action "$action" --argjson now "$(date +%s)" \
      '{action:$action,id:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",created_at:$now} +
       (if $action=="share-delete" then {share_id:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"} else {} end)' > "$data/request.json"
    secure_panel_poll
    secure_jq -e --arg action "$action" '.status=="success" and .action==$action' "$data/result.json" >/dev/null
done
secure_jq -n --argjson now "$(date +%s)" '{action:"share-prune",id:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",created_at:$now,all:true}' > "$data/request.json"
if secure_panel_poll; then echo 'ERROR: accepted unlisted cleanup fields'; exit 1; fi
echo 'PASS: delete/prune actions accepted; unlisted cleanup fields rejected'
for action in backup-refresh backup-prune; do
    secure_jq -n --arg action "$action" --argjson now "$(date +%s)" \
      '{action:$action,id:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",created_at:$now} +
      (if $action=="backup-prune" then {keep:3,revision:("a"*64)} else {} end)' > "$data/request.json"
    secure_panel_poll
    secure_jq -e --arg action "$action" '.status=="success" and .action==$action' "$data/result.json" >/dev/null
done
for payload in '{keep:0,revision:("a"*64)}' '{keep:3,revision:"wrong"}' '{keep:3,revision:("a"*64),path:"/tmp"}'; do
    secure_jq -n --argjson now "$(date +%s)" '{action:"backup-prune",id:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",created_at:$now} + '"$payload" > "$data/request.json"
    if secure_panel_poll; then echo 'ERROR: accepted invalid backup cleanup request'; exit 1; fi
done
echo 'PASS: backup actions require bounded retention and exact snapshot; paths rejected'
secure_jq -n --argjson now "$(date +%s)" '{action:"rules-save",id:("a"*32),created_at:$now,rules:{mode:"custom",ini:"[custom]"}}' > "$data/request.json"
secure_seal "$data/request.json"
secure_panel_poll
secure_jq -e '.status=="success" and .action=="rules-save"' "$data/result.json" >/dev/null
echo 'PASS: encoded template task reaches only the fixed local compiler action'
secure_jq -n --argjson now "$(date +%s)" '{action:"rules-save",id:("a"*32),created_at:$now,rules:{mode:"url",url:"https://rules.fixture.test/default.ini",ini:"[custom]"}}' > "$data/request.json"
secure_seal "$data/request.json"
secure_panel_poll
secure_jq -e '.status=="success" and .action=="rules-save"' "$data/result.json" >/dev/null
for rules in '{mode:"url",ini:"[custom]"}' '{mode:"url",url:"",ini:"[custom]"}' '{mode:"url",url:"https://example.com/a",ini:"[custom]",path:"/tmp"}'; do
    secure_jq -n --argjson now "$(date +%s)" '{action:"rules-save",id:("a"*32),created_at:$now,rules:'"$rules"'}' > "$data/request.json"
    if secure_panel_poll; then echo 'ERROR: accepted invalid URL template task'; exit 1; fi
done
echo 'PASS: URL template tasks accepted with exact fields; missing/empty URL and unlisted fields rejected'
