#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/lib/unbound-secure.sh"
TEST_ROOT=${SALKSD_STORAGE_TEST_ROOT:-$(mktemp -d)}
SALKSD_AUDIT_BACKUP_DIR="$TEST_ROOT/audit-fixture"
WORKDIR="$TEST_ROOT/site/logs"; FILE_PATH="$TEST_ROOT/site/public_html"
SALKSD_STATE_DIR="$TEST_ROOT/state"; mkdir -p "$WORKDIR" "$FILE_PATH"
secure_init
printf 'fixture password: %%$\\"\n\000\377end' > "$TEST_ROOT/input"
secure_store "$TEST_ROOT/input" "$TEST_ROOT/stored"
secure_read "$TEST_ROOT/stored" > "$TEST_ROOT/output"
cmp "$TEST_ROOT/input" "$TEST_ROOT/output"
if grep -q 'fixture password' "$TEST_ROOT/stored"; then exit 1; fi
before=$(openssl dgst -sha256 "$TEST_ROOT/stored")
secure_seal "$TEST_ROOT/stored"
[[ "$before" == "$(openssl dgst -sha256 "$TEST_ROOT/stored")" ]]
secure_php_runtime_source > "$TEST_ROOT/runtime.php"
php -n -r 'require $argv[1]; echo stored_decode(file_get_contents($argv[2]));' "$TEST_ROOT/runtime.php" "$TEST_ROOT/stored" > "$TEST_ROOT/php-out"
cmp "$TEST_ROOT/input" "$TEST_ROOT/php-out"
php -n -r 'require $argv[1]; echo stored_encode(file_get_contents($argv[2]));' "$TEST_ROOT/runtime.php" "$TEST_ROOT/input" > "$TEST_ROOT/php-store"
cmp "$TEST_ROOT/stored" "$TEST_ROOT/php-store"
sed '1s/STORE-1:/STORE-2:/' "$TEST_ROOT/stored" > "$TEST_ROOT/wrong-version"
sed '1s/:./:z/' "$TEST_ROOT/stored" > "$TEST_ROOT/corrupt"
for file in wrong-version corrupt; do
    if secure_read "$TEST_ROOT/$file" > "$TEST_ROOT/rejected"; then exit 1; fi
    [[ ! -s "$TEST_ROOT/rejected" ]]
    if php -n -r 'require $argv[1]; try { stored_decode(file_get_contents($argv[2])); } catch (Throwable $e) {exit(2);}' "$TEST_ROOT/runtime.php" "$TEST_ROOT/$file"; then exit 1; fi
done
printf '{"secret":"fixture-value"}\n' > "$TEST_ROOT/input.json"
secure_store "$TEST_ROOT/input.json" "$TEST_ROOT/data"
secure_jq -e --slurpfile a "$TEST_ROOT/data" --rawfile b "$TEST_ROOT/data" '.secret=="fixture-value" and $a[0].secret==.secret and ($b|fromjson)==.' "$TEST_ROOT/data" >/dev/null
printf '%s\n' 'export UUID=fixture-kept' | base64 > "$WORKDIR/keepalive.conf"
secure_seal "$WORKDIR/keepalive.conf"
secure_load_keepalive "$WORKDIR/keepalive.conf"
[[ "$UUID" == fixture-kept ]]
secure_store_stream "$TEST_ROOT/streamed" < "$TEST_ROOT/input"
cmp "$TEST_ROOT/stored" "$TEST_ROOT/streamed"
# Migration touches only this service; keeps recoverable bytes before each replacement.
mkdir -p "$SECURE_STATE/subscriptions-old" "$FILE_PATH/.salksd-data" "$TEST_ROOT/unrelated"
printf '%s\n' 'fixture-old-secret' > "$SECURE_STATE/token"
printf '%s\n' 'fixture client configuration' > "$FILE_PATH/clash.yaml"
printf '%s\n' 'old parser content' > "$SECURE_STATE/subscriptions-old/nekobox.json"
printf '%s\n' 'do not change' > "$TEST_ROOT/unrelated/weights.bin"
printf '%s\n' 'unrelated website PHP' > "$FILE_PATH/longapplication.php"
secure_storage_migrate
[[ ! -f "$FILE_PATH/clash.yaml" && ! -f "$SECURE_STATE/subscriptions-old/nekobox.json" ]]
[[ "$(secure_read "$SECURE_STATE/token")" == fixture-old-secret ]]
[[ -s "$SECURE_STATE/storage-before/map" ]]
grep -qx 'do not change' "$TEST_ROOT/unrelated/weights.bin"
grep -qx 'unrelated website PHP' "$FILE_PATH/longapplication.php"
secure_storage_migrate
if find "$SECURE_STATE" -type f | grep -Eiq 'clash|nekobox|singbox|\.b64'; then exit 1; fi
if grep -raiEq 'clash|nekobox|singbox|\.b64|fixture-old-secret' "$SECURE_STATE"; then exit 1; fi
echo 'PASS: binary/text roundtrip, shell/PHP agreement, corrupt/unknown versions fail closed, encoded jq inputs and old keepalive preserved'
echo 'PASS: migration archives each original, uses neutral names, is repeatable and leaves unrelated data untouched'
