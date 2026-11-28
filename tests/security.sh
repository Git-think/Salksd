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
HOSTNAME=s16.serv00.com
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
secure_jq -n --arg uuid "$UUID" '{inbounds:[
  {type:"tuic",listen:"127.0.0.1",listen_port:45001,users:[{uuid:$uuid,password:"a\"b\\c$def&g"}],congestion_control:"bbr"},
  {type:"hysteria2",listen:"127.0.0.1",listen_port:45002,users:[{password:"h\"y\\2&$"}]},
  {type:"vless",listen:"127.0.0.1",listen_port:45003,users:[{uuid:$uuid,flow:"xtls-rprx-vision"}],
   tls:{server_name:"www.example.test",reality:{short_id:[""]}}}]}' > "$WORKDIR/unbound.conf"
secure_capture_config "$WORKDIR/unbound.conf"
[[ "$SUB_TOKEN" == "$SECURE_TOKEN" && ${#SUB_TOKEN} -eq 64 ]]
# Old token is archived for rollback; it no longer grants access to owner nodes.
secure_tokens
[[ "$SUB_TOKEN" == "$SECURE_TOKEN" && "$(secure_read "$SECURE_STATE/legacy-token")" == old12345 ]]
LANDING_BACKUPS=$(find "$SECURE_STATE/backups" -name index.html | wc -l)
secure_publish
cmp "$ROOT/lib/public-index.html" "$FILE_PATH/index.html"
[[ $(find "$SECURE_STATE/backups" -name index.html | wc -l) -eq $((LANDING_BACKUPS+1)) ]]
grep -qx 'original homepage' "$SECURE_STATE"/backups/landing-*/index.html
[[ -s "$FILE_PATH/.salksd-data/bundle.json" ]]
if grep -Fq "$UUID" "$FILE_PATH/secure-sub.php"; then echo 'ERROR: router contains credentials'; exit 1; fi
if grep -q 'BEGIN CERTIFICATE\|PRIVATE KEY' "$FILE_PATH/secure-sub.php"; then echo 'ERROR: router contains identity material'; exit 1; fi
secure_jq -e '.content|keys==["p07","p08","p09"]' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
[[ $(secure_jq -r '.content["p07"]' "$FILE_PATH/.salksd-data/bundle.json" | tr -d '\r\n' | base64 -d | wc -l) -eq 5 ]]
secure_jq -e '.content["p08"]|fromjson|(.outbounds|length)==5 and
  ([.outbounds[]|select(.tls.insecure==true)]|length)==2 and
  all(.outbounds[]|select(.tls.insecure==true); .tag|endswith(" [SkipVerify]"))' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
secure_jq -e '.content["p08"]|fromjson|[.outbounds[].tag]|sort==[
  "PL-s16-HY2","PL-s16-HY2 [SkipVerify]","PL-s16-TUIC","PL-s16-TUIC [SkipVerify]","PL-s16-VLESS"]' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
secure_jq -e '.content["p09"]|fromjson|[.proxies[].name]|sort==[
  "PL-s16-HY2","PL-s16-HY2 [SkipVerify]","PL-s16-TUIC","PL-s16-TUIC [SkipVerify]","PL-s16-VLESS"]' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
[[ "$(NODE_COUNTRY=DE secure_node_prefix)" == DE-s16 ]]
if NODE_COUNTRY='bad space' secure_node_prefix; then exit 1; fi
secure_jq -e '.content["p09"]|fromjson|(.proxies|length)==5 and
  ([.proxies[]|select(.["skip-cert-verify"]==true)]|length)==2' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
grep -Fq 'RewriteRule ^.*$ secure-sub.php?format=cover [L]' "$FILE_PATH/.htaccess"
if grep -q 'RewriteRule \^sub/' "$FILE_PATH/.htaccess"; then echo 'ERROR: introduced /sub route'; exit 1; fi
OLD_TOKEN=$SECURE_TOKEN
GEN=$(cat "$SECURE_STATE/current")
secure_jq -e 'all(.outbounds[]; .tls.enabled == true and .tls.insecure == false) and
  (.outbounds[]|select(.type=="tuic")|.zero_rtt_handshake==false and .password=="a\"b\\c$def&g")' "$SECURE_STATE/$GEN/p01" >/dev/null
secure_jq -e 'all(.outbounds[]|select(.type!="vless"); .tls.insecure == true and .tls.server_name=="www.bing.com" and (.tls|has("certificate")|not))' "$SECURE_STATE/$GEN/p02" >/dev/null
secure_jq -e 'all(.proxies[]|select(.["skip-cert-verify"]==true); .sni=="www.bing.com")' "$SECURE_STATE/$GEN/p09" >/dev/null
secure_jq -e 'all(.proxies[]; .["skip-cert-verify"]==false) and (.proxies[]|select(.type=="tuic")|.["reduce-rtt"]==false and (.fingerprint|length)==64)' "$SECURE_STATE/$GEN/p05" >/dev/null
[[ $(secure_read "$SECURE_STATE/$GEN/p03" | wc -l) -eq 3 ]]
secure_read "$SECURE_STATE/$GEN/p04" > "$FILE_PATH/list.txt"
secure_refresh_legacy
secure_read "$FILE_PATH/list.txt" | grep -Fq '#PL-s16-TUIC%20%5BSkipVerify%5D'
secure_read "$FILE_PATH/list.txt" | grep -Fq '#PL-s16-HY2%20%5BSkipVerify%5D'
secure_jq '.inbounds[0].listen_port=45999' "$SECURE_STATE/server.json" > "$WORKDIR/changed.json"
secure_capture_config "$WORKDIR/changed.json"
sleep 1
secure_publish
[[ $(find "$SECURE_STATE/backups" -name index.html | wc -l) -eq $((LANDING_BACKUPS+1)) ]]
[[ "$OLD_TOKEN" == "$SECURE_TOKEN" ]]
[[ "$FIRST" == "$(openssl x509 -in "$SECURE_STATE/cert.pem" -noout -fingerprint -sha256)" ]]
GEN=$(cat "$SECURE_STATE/current")
secure_jq -e '.outbounds[]|select(.type=="tuic")|.server_port==45999' "$SECURE_STATE/$GEN/p01" >/dev/null
# Broken private state must fail closed, not generate a new identity.
mv "$SECURE_STATE/private.key" "$SECURE_STATE/private.key.test"
if secure_prepare_certificate 2>/dev/null; then echo 'ERROR: silently replaced identity'; exit 1; fi
mv "$SECURE_STATE/private.key.test" "$SECURE_STATE/private.key"
# Persist a default URL and publish its validated snapshot without any network fetch.
secure_jq '.content.p09|fromjson|.proxies' "$FILE_PATH/.salksd-data/bundle.json" > "$TEST_ROOT/proxies-before.json"
printf '[custom]\ncustom_proxy_group=Custom`select`.*\nruleset=DIRECT,[]GEOIP,CN\nruleset=Custom,[]FINAL\n' > "$TEST_ROOT/fixture.ini"
secure_jq -n --rawfile ini "$TEST_ROOT/fixture.ini" '{rules:{mode:"url",url:"https://rules.fixture.test/default.ini",ini:$ini}}' > "$TEST_ROOT/rules-task.json"
secure_rules_change "$TEST_ROOT/rules-task.json"
secure_jq -e '.mode=="url" and .url=="https://rules.fixture.test/default.ini" and .updated_at>0' "$SECURE_STATE/rules-settings.json" >/dev/null
secure_jq -e --slurpfile before "$TEST_ROOT/proxies-before.json" '.rules.mode=="url" and .rules.url=="https://rules.fixture.test/default.ini" and
  (.content.p09|fromjson|.proxies)==$before[0] and (.content.p09|fromjson|.rules)==["GEOIP,CN,DIRECT","MATCH,Custom"]' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
if grep -q 'rules.fixture.test\|custom_proxy_group' "$SECURE_STATE/rules-settings.json" "$FILE_PATH/.salksd-data/bundle.json"; then exit 1; fi
secure_jq -n '{rules:{mode:"default",ini:""}}' > "$TEST_ROOT/rules-task.json"
secure_rules_change "$TEST_ROOT/rules-task.json"
secure_jq -e '.rules.mode=="default" and (.content.p09|fromjson|.rules|length)==13' "$FILE_PATH/.salksd-data/bundle.json" >/dev/null
echo 'PASS: default URL persists with encoded snapshot, publishes to panel and keeps TLS nodes; builtin reset restores rules'
# Keep the generated fixture for client-core tests when a path was explicitly supplied.
printf 'PASS: certificate reuse, stable URLs, escaped payloads, strict and legacy feeds, fail-closed identity\n'
printf 'Fixture: %s\n' "$TEST_ROOT"
