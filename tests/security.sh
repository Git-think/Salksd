#!/bin/bash
# Offline regression tests. Never calls devil, kills processes, or runs an installer.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/lib/unbound-secure.sh"
TEST_ROOT=${SALKSD_TEST_ROOT:-$(mktemp -d)}
export MSYS_NO_PATHCONV=1
WORKDIR="$TEST_ROOT/site/logs"
FILE_PATH="$TEST_ROOT/site/public_html"
SALKSD_STATE_DIR="$TEST_ROOT/state"
USERNAME=fixture
CURRENT_DOMAIN=example.test
HOSTNAME=fixture
TLS_SERVER_NAME=api.fixture.example.test
public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
UUID=11111111-1111-4111-8111-111111111111
TUIC_PORT=45001
HY2_PORT=45002
VLESS_PORT=45003
mkdir -p "$WORKDIR" "$FILE_PATH"
printf 'original homepage\n' > "$FILE_PATH/index.html"
printf 'RewriteEngine On\nRewriteRule ^old12345$ old12345.php [L]\n' > "$FILE_PATH/.htaccess"
secure_prepare_certificate
FIRST=$(openssl x509 -in "$SECURE_STATE/cert.pem" -noout -fingerprint -sha256)
rm "$WORKDIR/cert.pem" "$WORKDIR/private.key"
secure_prepare_certificate
[[ "$FIRST" == "$(openssl x509 -in "$SECURE_STATE/cert.pem" -noout -fingerprint -sha256)" ]]
unset TLS_SERVER_NAME
secure_tls_server_name
[[ "$TLS_SERVER_NAME" == api.fixture.example.test ]]
(
    SECURE_STATE="$TEST_ROOT/not-yet-created"
    unset TLS_SERVER_NAME
    secure_tls_server_name
    [[ "$TLS_SERVER_NAME" == www.bing.com ]]
)
jq -n --arg uuid "$UUID" '{inbounds:[
  {type:"tuic",listen:"127.0.0.1",listen_port:45001,users:[{uuid:$uuid,password:"a\"b\\c$def&g"}],congestion_control:"bbr"},
  {type:"hysteria2",listen:"127.0.0.1",listen_port:45002,users:[{password:"h\"y\\2&$"}]},
  {type:"vless",listen:"127.0.0.1",listen_port:45003,users:[{uuid:$uuid,flow:"xtls-rprx-vision"}],
   tls:{server_name:"www.example.test",reality:{short_id:[""]}}}]}' > "$WORKDIR/unbound.conf"
secure_capture_config "$WORKDIR/unbound.conf"
[[ "$SUB_TOKEN" == "$SECURE_TOKEN" && ${#SUB_TOKEN} -eq 64 ]]
# Old token is archived for rollback; it no longer grants access to owner nodes.
secure_tokens
[[ "$SUB_TOKEN" == "$SECURE_TOKEN" && "$(cat "$SECURE_STATE/legacy-token")" == old12345 ]]
LANDING_BACKUPS=$(find "$SECURE_STATE/backups" -name index.html | wc -l)
secure_publish
cmp "$ROOT/lib/public-index.html" "$FILE_PATH/index.html"
[[ $(find "$SECURE_STATE/backups" -name index.html | wc -l) -eq $((LANDING_BACKUPS+1)) ]]
grep -qx 'original homepage' "$SECURE_STATE"/backups/landing-*/index.html
[[ -s "$FILE_PATH/.salksd-data/bundle.json" ]]
if grep -Fq "$UUID" "$FILE_PATH/secure-sub.php"; then echo 'ERROR: router contains credentials'; exit 1; fi
if grep -q 'BEGIN CERTIFICATE\|PRIVATE KEY' "$FILE_PATH/secure-sub.php"; then echo 'ERROR: router contains identity material'; exit 1; fi
jq -e '.content|keys==["mihomo-all.yaml","singbox-all.json","v2.log"]' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
[[ $(jq -r '.content["v2.log"]' "$FILE_PATH/.salksd-data/bundle.json" | tr -d '\r\n' | base64 -d | wc -l) -eq 5 ]]
jq -e '.content["singbox-all.json"]|fromjson|(.outbounds|length)==5 and
  ([.outbounds[]|select(.tls.insecure==true)]|length)==2 and
  all(.outbounds[]|select(.tls.insecure==true); .tag|contains("不验证证书"))' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
jq -e '.content["mihomo-all.yaml"]|fromjson|(.proxies|length)==5 and
  ([.proxies[]|select(.["skip-cert-verify"]==true)]|length)==2' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
grep -Fq 'RewriteRule ^.*$ secure-sub.php?format=cover [L]' "$FILE_PATH/.htaccess"
if grep -q 'RewriteRule \^sub/' "$FILE_PATH/.htaccess"; then echo 'ERROR: introduced /sub route'; exit 1; fi
OLD_TOKEN=$SECURE_TOKEN
GEN=$(cat "$SECURE_STATE/current")
jq -e 'all(.outbounds[]; .tls.enabled == true and .tls.insecure == false) and
  (.outbounds[]|select(.type=="tuic")|.zero_rtt_handshake==false and .password=="a\"b\\c$def&g")' "$SECURE_STATE/$GEN/nekobox.json" >/dev/null
jq -e 'all(.outbounds[]|select(.type!="vless"); .tls.insecure == true and .tls.server_name=="www.bing.com" and (.tls|has("certificate")|not))' "$SECURE_STATE/$GEN/nekobox-nocert.json" >/dev/null
jq -e 'all(.proxies[]|select(.["skip-cert-verify"]==true); .sni=="www.bing.com")' "$SECURE_STATE/$GEN/mihomo-all.yaml" >/dev/null
jq -e 'all(.proxies[]; .["skip-cert-verify"]==false) and (.proxies[]|select(.type=="tuic")|.["reduce-rtt"]==false and (.fingerprint|length)==64)' "$SECURE_STATE/$GEN/mihomo.yaml" >/dev/null
[[ $(wc -l < "$SECURE_STATE/$GEN/v2rayn.txt") -eq 3 ]]
jq '.inbounds[0].listen_port=45999' "$SECURE_STATE/server.json" > "$WORKDIR/changed.json"
secure_capture_config "$WORKDIR/changed.json"
sleep 1
secure_publish
[[ $(find "$SECURE_STATE/backups" -name index.html | wc -l) -eq $((LANDING_BACKUPS+1)) ]]
[[ "$OLD_TOKEN" == "$SECURE_TOKEN" ]]
[[ "$FIRST" == "$(openssl x509 -in "$SECURE_STATE/cert.pem" -noout -fingerprint -sha256)" ]]
GEN=$(cat "$SECURE_STATE/current")
jq -e '.outbounds[]|select(.type=="tuic")|.server_port==45999' "$SECURE_STATE/$GEN/nekobox.json" >/dev/null
# Broken private state must fail closed, not generate a new identity.
mv "$SECURE_STATE/private.key" "$SECURE_STATE/private.key.test"
if secure_prepare_certificate 2>/dev/null; then echo 'ERROR: silently replaced identity'; exit 1; fi
mv "$SECURE_STATE/private.key.test" "$SECURE_STATE/private.key"
# Keep the generated fixture for client-core tests when a path was explicitly supplied.
printf 'PASS: certificate reuse, stable URLs, escaped payloads, strict and legacy feeds, fail-closed identity\n'
printf 'Fixture: %s\n' "$TEST_ROOT"
