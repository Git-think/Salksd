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
    jq -n --arg id "$id" '{id:$id,duration:3600,label:"<friend> \"你好\""}' > "$SECURE_STATE/request-test.json"
    secure_share_edit --share-create "$SECURE_STATE/request-test.json"
done
[[ $(jq length "$SECURE_STATE/shares.json") -eq 2 ]]
secure_share_edit --share-create "$SECURE_STATE/request-test.json"
[[ $(jq length "$SECURE_STATE/shares.json") -eq 2 ]]
# Resource/RNG failures must never replace the good ledger with empty credentials.
cp "$SECURE_STATE/shares.json" "$SECURE_STATE/shares-before-rng.json"
jq -n '{id:"cccccccccccccccccccccccccccccccc",duration:3600,label:"RNG regression"}' > "$SECURE_STATE/request-test.json"
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
jq -e 'all(.inbounds[];.users|length==3)' "$SECURE_STATE/server.json" >/dev/null
cmp <(jq -S '[.inbounds[].users[0]]' "$SECURE_STATE/owner-before.json") <(jq -S '[.inbounds[].users[0]]' "$SECURE_STATE/server.json")
secure_publish
"${PYTHON:-python3}" - "$SECURE_STATE" "$FILE_PATH" <<'PY'
import base64,hashlib,json,sys
from pathlib import Path
s,w=map(Path,sys.argv[1:]); ledger=json.loads((s/'shares.json').read_text(encoding='utf-8'))
bundle=json.loads((w/'.salksd-data/bundle.json').read_text(encoding='utf-8'))
assert len(bundle['shares'])==2
owner=json.loads(bundle['content']['singbox-all.json'])['outbounds']
owner_passwords={n.get('uuid') for n in owner}|{n.get('password') for n in owner}
for share in ledger:
    content=bundle['shares'][hashlib.sha256(share['token'].encode()).hexdigest()]['content']
    nodes=json.loads(content['singbox-all.json'])['outbounds']
    assert len(nodes)==5 and len(base64.b64decode(content['v2.log']).decode().splitlines())==5
    for n in nodes:
        assert n.get('uuid') not in owner_passwords if n.get('uuid') else True
        assert n.get('password') not in owner_passwords if n.get('password') else True
        assert 'PRIVATE KEY' not in json.dumps(n)
    assert next(n for n in nodes if n['type']=='tuic')['uuid']==share['tuic_uuid']
print('PASS: two independent share accounts; owner credentials never appear in share payloads')
PY
cp "$SECURE_STATE/server.json" "$SECURE_STATE/share-active-server.json"
cp "$FILE_PATH/.salksd-data/bundle.json" "$SECURE_STATE/share-active-bundle.json"
jq '.[0].expires_at=1' "$SECURE_STATE/shares.json" > "$SECURE_STATE/expired.json"
mv "$SECURE_STATE/expired.json" "$SECURE_STATE/shares.json"
jq -n '{share_id:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}' > "$SECURE_STATE/request-test.json"
secure_share_edit --share-revoke "$SECURE_STATE/request-test.json"
secure_shares_apply "$SECURE_STATE/server.json"
jq -e 'all(.inbounds[];.users|length==1)' "$SECURE_STATE/server.json" >/dev/null
secure_publish
jq -e '.shares|length==0' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
cmp <(jq -S '[.inbounds[].users[0]]' "$SECURE_STATE/owner-before.json") <(jq -S '[.inbounds[].users[0]]' "$SECURE_STATE/server.json")
echo 'PASS: expiry and revocation remove all three protocol accounts; owner retained'
# Watchdog checks both lease generation and process start identity before signalling.
jq -n '{pid:777,deadline:1,start:"fixture start",generation:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' > "$SECURE_STATE/core-lease"
ps() { printf 'fixture start\n'; }
sleep() { :; }
kill() { [[ "$1" == -0 ]] || printf '%s\n' "$*" >> "$SECURE_STATE/signals"; }
secure_share_watch aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
grep -qx '777' "$SECURE_STATE/signals"
before=$(wc -l < "$SECURE_STATE/signals")
secure_share_watch bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
[[ $(wc -l < "$SECURE_STATE/signals") -eq $before ]]
echo 'PASS: deadline stops its own core; obsolete lease cannot signal replacement'
