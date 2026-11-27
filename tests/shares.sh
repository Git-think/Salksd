#!/bin/bash
# Offline share isolation, expiry and revocation; no platform operations.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export SALKSD_TEST_ROOT=${SALKSD_SHARE_TEST_ROOT:-$(mktemp -d)}
bash "$ROOT/tests/security.sh"
source "$ROOT/lib/unbound-secure.sh"
WORKDIR="$SALKSD_TEST_ROOT/site/logs"
FILE_PATH="$SALKSD_TEST_ROOT/site/public_html"
SALKSD_STATE_DIR="$SALKSD_TEST_ROOT/state"
USERNAME=fixture; CURRENT_DOMAIN=example.test; TLS_SERVER_NAME=api.fixture.example.test
secure_init
secure_shares_init
cp "$SECURE_STATE/server.json" "$SECURE_STATE/owner-before.json"
for id in aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; do
    secure_jq -n --arg id "$id" '{id:$id,duration:3600,label:"<friend> \"你好\""}' > "$SECURE_STATE/request-test.json"
    secure_share_edit --share-create "$SECURE_STATE/request-test.json"
done
[[ $(secure_jq length "$SECURE_STATE/shares.json") -eq 2 ]]
# Active shares cannot be deleted even if a caller bypasses the panel.
secure_jq -n '{share_id:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' > "$SECURE_STATE/remove-test.json"
if secure_share_remove --share-delete "$SECURE_STATE/remove-test.json"; then exit 1; fi
[[ $(secure_jq length "$SECURE_STATE/shares.json") -eq 2 ]]
secure_share_edit --share-create "$SECURE_STATE/request-test.json"
[[ $(secure_jq length "$SECURE_STATE/shares.json") -eq 2 ]]
# Resource/RNG failures must never replace the good ledger with empty credentials.
cp "$SECURE_STATE/shares.json" "$SECURE_STATE/shares-before-rng.json"
secure_jq -n '{id:"cccccccccccccccccccccccccccccccc",duration:3600,label:"RNG regression"}' > "$SECURE_STATE/request-test.json"
(
    openssl() { [[ "$*" != 'rand -hex 32' ]] || return 1; command openssl "$@"; }
    if secure_share_edit --share-create "$SECURE_STATE/request-test.json"; then exit 1; fi
)
cmp "$SECURE_STATE/shares.json" "$SECURE_STATE/shares-before-rng.json"
(
    secure_share_uuid() { return 1; }
    if secure_share_edit --share-create "$SECURE_STATE/request-test.json"; then exit 1; fi
)
cmp "$SECURE_STATE/shares.json" "$SECURE_STATE/shares-before-rng.json"
(
    secure_share_uuid() { printf ''; }
    if secure_share_edit --share-create "$SECURE_STATE/request-test.json"; then exit 1; fi
)
cmp "$SECURE_STATE/shares.json" "$SECURE_STATE/shares-before-rng.json"
[[ -z $(find "$SECURE_STATE" -maxdepth 1 -name '.shares.*' -print) ]]
echo 'PASS: failed or malformed random generation leaves the ledger unchanged'
secure_shares_apply "$SECURE_STATE/server.json"
secure_jq -e 'all(.inbounds[];.users|length==3)' "$SECURE_STATE/server.json" >/dev/null
cmp <(secure_jq -S '[.inbounds[].users[0]]' "$SECURE_STATE/owner-before.json") <(secure_jq -S '[.inbounds[].users[0]]' "$SECURE_STATE/server.json")
secure_publish
"${PYTHON:-python3}" - "$SECURE_STATE" "$FILE_PATH" <<'PY'
import base64,hashlib,json,sys
sys.path.insert(0,"tests")
from storage_codec import read
from pathlib import Path
s,w=map(Path,sys.argv[1:]); ledger=json.loads(read(s/'shares.json'))
bundle=json.loads(read(w/'.salksd-data/bundle.json'))
assert len(bundle['shares'])==2
owner=json.loads(bundle['content']['p08'])['outbounds']
owner_passwords={n.get('uuid') for n in owner}|{n.get('password') for n in owner}
for share in ledger:
    content=bundle['shares'][hashlib.sha256(share['token'].encode()).hexdigest()]['content']
    nodes=json.loads(content['p08'])['outbounds']
    assert len(nodes)==5 and len(base64.b64decode(content['p07']).decode().splitlines())==5
    for n in nodes:
        assert n.get('uuid') not in owner_passwords if n.get('uuid') else True
        assert n.get('password') not in owner_passwords if n.get('password') else True
        assert 'PRIVATE KEY' not in json.dumps(n)
    assert next(n for n in nodes if n['type']=='tuic')['uuid']==share['tuic_uuid']
print('PASS: two independent share accounts; owner credentials never appear in share payloads')
PY
cp "$SECURE_STATE/server.json" "$SECURE_STATE/share-active-server.json"
cp "$FILE_PATH/.salksd-data/bundle.json" "$SECURE_STATE/share-active-bundle.json"
secure_jq '.[0].expires_at=1' "$SECURE_STATE/shares.json" > "$SECURE_STATE/expired.json"
mv "$SECURE_STATE/expired.json" "$SECURE_STATE/shares.json"
secure_jq -n '{share_id:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}' > "$SECURE_STATE/request-test.json"
secure_share_edit --share-revoke "$SECURE_STATE/request-test.json"
# Do not clean history until the associated server users have been removed.
if secure_share_remove --share-prune "$SECURE_STATE/request-test.json"; then exit 1; fi
[[ $(secure_jq length "$SECURE_STATE/shares.json") -eq 2 ]]
secure_shares_apply "$SECURE_STATE/server.json"
secure_jq -e 'all(.inbounds[];.users|length==1)' "$SECURE_STATE/server.json" >/dev/null
secure_publish
secure_jq -e '.shares|length==0' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
cmp <(secure_jq -S '[.inbounds[].users[0]]' "$SECURE_STATE/owner-before.json") <(secure_jq -S '[.inbounds[].users[0]]' "$SECURE_STATE/server.json")
echo 'PASS: expiry and revocation remove all three protocol accounts; owner retained'
# Deletion keeps an independent active share and never restarts/modifies the core.
retired_token=$(secure_jq -r '.[0].token' "$SECURE_STATE/shares.json")
secure_jq -n '{id:"cccccccccccccccccccccccccccccccc",duration:3600,label:"still active"}' > "$SECURE_STATE/request-test.json"
secure_share_edit --share-create "$SECURE_STATE/request-test.json"
secure_shares_apply "$SECURE_STATE/server.json"
cp "$SECURE_STATE/server.json" "$SECURE_STATE/before-removal.json"
secure_jq '[.[]|select(.id=="cccccccccccccccccccccccccccccccc")]' "$SECURE_STATE/shares.json" > "$SECURE_STATE/active-share.json"
secure_share_remove --share-delete "$SECURE_STATE/remove-test.json"
[[ $(secure_jq length "$SECURE_STATE/shares.json") -eq 2 ]]
secure_share_remove --share-delete "$SECURE_STATE/remove-test.json"
secure_share_remove --share-prune "$SECURE_STATE/remove-test.json"
cmp <(secure_read "$SECURE_STATE/active-share.json") <(secure_read "$SECURE_STATE/shares.json")
cmp "$SECURE_STATE/before-removal.json" "$SECURE_STATE/server.json"
[[ $(secure_jq length "$SECURE_STATE/share-retired.json") -eq 2 ]]
if secure_share_token_available "$retired_token"; then exit 1; fi
secure_publish
secure_jq -e '.share_index|length==1' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
echo 'PASS: individual/repeated/bulk deletion preserves active accounts and reserves old URLs'
# Failing to save the retired-token list must leave the record intact.
secure_jq -n '{share_id:"cccccccccccccccccccccccccccccccc"}' > "$SECURE_STATE/remove-test.json"
secure_share_edit --share-revoke "$SECURE_STATE/remove-test.json"
secure_shares_apply "$SECURE_STATE/server.json"
cp "$SECURE_STATE/shares.json" "$SECURE_STATE/before-failed-removal.json"
(
    mv() { [[ "${2:-}" != "$SECURE_STATE/share-retired.json" ]] || return 1; command mv "$@"; }
    if secure_share_remove --share-delete "$SECURE_STATE/remove-test.json"; then exit 1; fi
)
cmp "$SECURE_STATE/before-failed-removal.json" "$SECURE_STATE/shares.json"
secure_share_remove --share-delete "$SECURE_STATE/remove-test.json"
secure_jq -n '{id:"dddddddddddddddddddddddddddddddd",duration:60,label:"collision"}' > "$SECURE_STATE/request-test.json"
(
    openssl() { if [[ "$*" == 'rand -base64 6' ]]; then printf '%s\n' "$retired_token"; else command openssl "$@"; fi; }
    if secure_share_edit --share-create "$SECURE_STATE/request-test.json"; then exit 1; fi
)
[[ $(secure_jq length "$SECURE_STATE/shares.json") -eq 0 ]]
secure_jq '.id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$SECURE_STATE/request-test.json" > "$SECURE_STATE/replayed-request.json"
if secure_share_edit --share-create "$SECURE_STATE/replayed-request.json"; then exit 1; fi
secure_publish
echo 'PASS: deletion failure leaves record intact; old tokens and create IDs cannot be reused'
(
    SECURE_STATE="$SALKSD_TEST_ROOT/capacity-state"
    mkdir -p "$SECURE_STATE"
    cp "$SALKSD_TEST_ROOT/state/server.json" "$SECURE_STATE/server.json"
    "${PYTHON:-python3}" - "$SECURE_STATE/shares.json" <<'PY'
import json,sys
from pathlib import Path
records=[dict(id=f'{i+1024:032x}',token=f'{i:08x}',label='',created_at=0,expires_at=1,revoked_at=0,
 vless_uuid=f'00000000-0000-4000-8000-{i:012x}',tuic_uuid=f'00000000-0000-4000-8000-{i+128:012x}',
 tuic_password=f'{i:064x}',hy2_password=f'{i+128:064x}') for i in range(128)]
Path(sys.argv[1]).write_text(json.dumps(records),encoding='utf-8')
PY
    if secure_share_edit --share-create "$SALKSD_TEST_ROOT/state/request-test.json"; then exit 1; fi
    secure_share_remove --share-prune "$SALKSD_TEST_ROOT/state/request-test.json"
    secure_share_edit --share-create "$SALKSD_TEST_ROOT/state/request-test.json"
    [[ $(secure_jq length "$SECURE_STATE/shares.json") -eq 1 ]]
    [[ $(secure_jq length "$SECURE_STATE/share-retired.json") -eq 128 ]]
)
echo 'PASS: clearing 128 inactive records restores capacity for new shares'
# Watchdog checks both lease generation and process start identity before signalling.
secure_jq -n '{pid:777,deadline:1,start:"fixture start",generation:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' > "$SECURE_STATE/core-lease"
ps() { printf 'fixture start\n'; }
sleep() { :; }
kill() { [[ "$1" == -0 ]] || printf '%s\n' "$*" >> "$SECURE_STATE/signals"; }
secure_share_watch aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
grep -qx '777' "$SECURE_STATE/signals"
before=$(wc -l < "$SECURE_STATE/signals")
secure_share_watch bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
[[ $(wc -l < "$SECURE_STATE/signals") -eq $before ]]
echo 'PASS: deadline stops its own core; obsolete lease cannot signal replacement'
