#!/bin/bash
# Shared source; tools/build_obfuscated.py embeds it in both distributed scripts.
# Never source this file from a subscription or from public_html.
SALKSD_SECURITY_VERSION=1
# SALKSD STORAGE BEGIN
source "$(dirname "${BASH_SOURCE[0]}")/unbound-storage.sh" || return 1
# SALKSD STORAGE END
# SALKSD RULES BEGIN
source "$(dirname "${BASH_SOURCE[0]}")/unbound-rules.sh" || return 1
# SALKSD RULES END
# SALKSD SHARES BEGIN
source "$(dirname "${BASH_SOURCE[0]}")/unbound-shares.sh" || return 1
# SALKSD SHARES END
# SALKSD BACKUPS BEGIN
source "$(dirname "${BASH_SOURCE[0]}")/unbound-backups.sh" || return 1
# SALKSD BACKUPS END

secure_init() {
    WORKDIR=${WORKDIR:-${WORKDIR_PATH:-}}
    [[ -n "$WORKDIR" && "$WORKDIR" != / ]] || return 1
    FILE_PATH=${FILE_PATH:-$(dirname "$WORKDIR")/public_html}
    SECURE_STATE=${SALKSD_STATE_DIR:-$HOME/.config/salksd/$(basename "$(dirname "$WORKDIR")")}
    (umask 077; mkdir -p "$SECURE_STATE" "$SECURE_STATE/backups") || return 1
    chmod 700 "$SECURE_STATE" "$SECURE_STATE/backups" || return 1
}

secure_backup() {
    secure_init || return 1
    SECURE_BACKUP="$SECURE_STATE/backups/$(date +%Y%m%d-%H%M%S)-$$-$(openssl rand -hex 3)"
    (umask 077; mkdir "$SECURE_BACKUP") || return 1
    local item
    for item in cert.pem private.key server.json identity.json token legacy-token shares.json share-retired.json rules-settings.json current published-fingerprint; do
        [[ -f "$SECURE_STATE/$item" ]] || continue
        case "$item" in
            private.key|server.json|token|legacy-token|shares.json|rules-settings.json) secure_store "$SECURE_STATE/$item" "$SECURE_BACKUP/$item" || return 1 ;;
            *) cp -p "$SECURE_STATE/$item" "$SECURE_BACKUP/$item" || return 1 ;;
        esac
    done
    # Keep the complete affected website and worker files, including the old script.
    local paths=()
    [[ ! -d "$WORKDIR" ]] || paths+=(logs)
    [[ ! -d "$FILE_PATH" ]] || paths+=(public_html)
    if (( ${#paths[@]} )); then
        (set -o pipefail; tar -czf - -C "$(dirname "$WORKDIR")" "${paths[@]}" | secure_store_stream "$SECURE_BACKUP/site.tgz") || return 1
    fi
    devil port list > "$SECURE_BACKUP/ports.txt" 2>/dev/null || :
    for item in private.key server.json token legacy-token shares.json rules-settings.json; do
        [[ ! -f "$SECURE_BACKUP/$item" ]] || secure_seal "$SECURE_BACKUP/$item" || return 1
    done
    chmod 600 "$SECURE_BACKUP"/*
    printf '%s\n' "$SECURE_BACKUP" > "$SECURE_STATE/last-backup"
}

secure_cert_valid() {
    local cert=$1 key=$2 name=$3 a b
    [[ -s "$cert" && -s "$key" ]] || return 1
    openssl x509 -in "$cert" -checkend 0 -noout >/dev/null 2>&1 || return 1
    # Go ignores a legacy CN: require a SAN, as well as hostname verification.
    openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | grep -q 'DNS:' || return 1
    openssl verify -CAfile "$cert" -purpose sslserver -verify_hostname "$name" "$cert" >/dev/null 2>&1 || return 1
    a=$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)
    b=$(set -o pipefail; secure_read "$key" | openssl pkey -pubout -outform DER 2>/dev/null | openssl dgst -sha256) || return 1
    [[ -n "$a" && "$a" == "$b" ]]
}

secure_tls_server_name() {
    # Preserve the baseline proxy SNI for new identities. A previously published
    # identity keeps its saved name; do not rotate certificates to change SNI.
    [[ -z "${TLS_SERVER_NAME:-}" ]] || return 0
    local candidate
    if [[ -s "$SECURE_STATE/cert.pem" ]]; then
        for candidate in www.bing.com "api.${USERNAME}.${CURRENT_DOMAIN}"; do
            if secure_cert_valid "$SECURE_STATE/cert.pem" "$SECURE_STATE/private.key" "$candidate"; then
                TLS_SERVER_NAME=$candidate
                return 0
            fi
        done
        return 1
    fi
    TLS_SERVER_NAME=www.bing.com
}

secure_prepare_certificate() {
    # Called only during installation/migration/restart, never by the HTTP reader.
    secure_init || return 1
    mkdir -p "$WORKDIR" || return 1
    secure_tls_server_name || return 1
    [[ "$TLS_SERVER_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]+$ ]] || return 1
    local cert="$SECURE_STATE/cert.pem" key="$SECURE_STATE/private.key" stage
    if secure_cert_valid "$cert" "$key" "$TLS_SERVER_NAME"; then
        :
    elif [[ -e "$cert" || -e "$key" ]]; then
        # A persisted identity must never rotate silently (including partial/corrupt state).
        echo '持久化证书失效或不匹配；已停止。请备份后显式迁移证书。' >&2
        return 1
    elif secure_cert_valid "$WORKDIR/cert.pem" "$WORKDIR/private.key" "$TLS_SERVER_NAME"; then
        (umask 077; cp "$WORKDIR/cert.pem" "$cert"; secure_store "$WORKDIR/private.key" "$key") || return 1
    else (
        stage=$(mktemp -d "$SECURE_STATE/.certificate.XXXXXX") || return 1
        trap "rm -f -- $(printf '%q' "$stage")/*; rmdir $(printf '%q' "$stage") 2>/dev/null || :" EXIT
        # A legacy CN-only pair remains in the transaction backup. Reuse its key when possible.
        if [[ -s "$WORKDIR/private.key" ]] && openssl pkey -in "$WORKDIR/private.key" -noout >/dev/null 2>&1; then
            cp "$WORKDIR/private.key" "$stage/private.key" || return 1
        else
            openssl ecparam -genkey -name prime256v1 -out "$stage/private.key" || return 1
        fi
        cat > "$stage/openssl.cnf" <<EOF
[req]
distinguished_name=dn
x509_extensions=server
prompt=no
[dn]
CN=$TLS_SERVER_NAME
[server]
subjectAltName=DNS:$TLS_SERVER_NAME
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EOF
        openssl req -new -x509 -sha256 -days 3650 -key "$stage/private.key" -out "$stage/cert.pem" -config "$stage/openssl.cnf" || return 1
        secure_cert_valid "$stage/cert.pem" "$stage/private.key" "$TLS_SERVER_NAME" || return 1
        chmod 600 "$stage/private.key" "$stage/cert.pem"
        secure_store "$stage/private.key" "$key" && rm -f "$stage/private.key" && mv "$stage/cert.pem" "$cert" || return 1
        rm -f "$stage/openssl.cnf"
        rmdir "$stage"
        echo '已建立持久化 TLS 身份；旧版客户端请更新专用订阅。' >&2
    ) || return 1
    fi
    secure_seal "$key" || return 1
    chmod 600 "$cert" "$key"
    # Temporary copies keep the original launch paths and cleanup behaviour intact.
    cp "$cert" "$WORKDIR/cert.pem" && secure_read "$key" > "$WORKDIR/private.key" || return 1
    chmod 600 "$WORKDIR/cert.pem" "$WORKDIR/private.key"
}

secure_legacy_token() {
    # Avoid BRE anchor escaping differences between GNU sed and FreeBSD sed.
    [[ -f "$FILE_PATH/.htaccess" ]] || return 0
    awk '$1=="RewriteRule" && substr($2,1,1)=="^" && substr($2,length($2),1)=="$" {
        token=substr($2,2,length($2)-2)
        if (token ~ /^[A-Za-z0-9_-]+$/ && $3==token ".php") { print token; exit }
    }' "$FILE_PATH/.htaccess"
}

secure_tokens() {
    secure_init || return 1
    if [[ ! -s "$SECURE_STATE/token" ]]; then
        (umask 077; openssl rand -hex 32 > "$SECURE_STATE/token") || return 1
    fi
    secure_seal "$SECURE_STATE/token" || return 1
    SECURE_TOKEN=$(secure_read "$SECURE_STATE/token") || return 1
    [[ "$SECURE_TOKEN" =~ ^[0-9a-f]{64}$ ]] || return 1
    local previous
    previous=$(secure_legacy_token) || return 1
    if [[ -n "$previous" ]]; then
        # The existing public rewrite rule is authoritative: it is the URL users
        # already subscribed to, including when migrating an inconsistent state file.
        if [[ ! -s "$SECURE_STATE/legacy-token" ]]; then
            (umask 077; printf '%s\n' "$previous" > "$SECURE_STATE/legacy-token.new") || return 1
            secure_store "$SECURE_STATE/legacy-token.new" "$SECURE_STATE/legacy-token" && rm -f "$SECURE_STATE/legacy-token.new" || return 1
        fi
    fi
    SUB_TOKEN=$SECURE_TOKEN
}

secure_node_prefix() {
    local country="${NODE_COUNTRY:-PL}" host="${HOSTNAME:-$(hostname)}"
    host=${host%%.*}
    [[ "$country" =~ ^[A-Z]{2}$ && "$host" =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]] || return 1
    printf '%s-%s' "$country" "$host"
}

secure_capture_config() {
    secure_init || return 1
    secure_jq -e '.inbounds | any(.type == "tuic")' "$1" >/dev/null || return 1
    # Keep the validated server configuration outside the disposable runtime directory.
    (umask 077; cp "$1" "$SECURE_STATE/server.json.new") || return 1
    secure_store "$SECURE_STATE/server.json.new" "$SECURE_STATE/server.json" && rm -f "$SECURE_STATE/server.json.new" || return 1
    if [[ -n "${public_key:-}" ]]; then
        local node_name
        node_name=$(secure_node_prefix) || return 1
        (umask 077; secure_jq -n --arg public_key "$public_key" --arg name "$node_name" '{public_key:$public_key,name:$name}' > "$SECURE_STATE/identity.json") || return 1
    fi
    secure_tokens
}

secure_write_keepalive() {
    # %q preserves special characters; base64 is storage encoding, not encryption.
    local var
    (umask 077
      for var in UUID VLESS_PORT TUIC_PORT HY2_PORT PROXYIP USERNAME CURRENT_DOMAIN private_key public_key SUB_TOKEN available_ip TLS_SERVER_NAME NODE_COUNTRY; do
          printf 'export %s=%q\n' "$var" "${!var-}"
      done | base64 | tr -d '\n' > "$WORKDIR/keepalive.conf.new"
    ) || return 1
    secure_store "$WORKDIR/keepalive.conf.new" "$WORKDIR/keepalive.conf" && rm -f "$WORKDIR/keepalive.conf.new"
}

secure_restore_identity() {
    secure_init || return 1
    if [[ -s "$SECURE_STATE/server.json" ]]; then
        available_ip=$(secure_jq -r '.inbounds[] | select(.type=="tuic") | .listen' "$SECURE_STATE/server.json")
        UUID=$(secure_jq -r '.inbounds[] | select(.type=="tuic") | .users[0].uuid' "$SECURE_STATE/server.json")
        TUIC_PORT=$(secure_jq -r '.inbounds[] | select(.type=="tuic") | .listen_port' "$SECURE_STATE/server.json")
        HY2_PORT=$(secure_jq -r '.inbounds[] | select(.type=="hysteria2") | .listen_port' "$SECURE_STATE/server.json")
        VLESS_PORT=$(secure_jq -r '.inbounds[] | select(.type=="vless") | .listen_port' "$SECURE_STATE/server.json")
    elif [[ -s "$FILE_PATH/list.txt" ]]; then
        # The baseline deletes its config; recover the advertised IP and Reality public key.
        available_ip=$(secure_read "$FILE_PATH/list.txt" | sed -n 's|^vless://[^@]*@\([^:]*\):.*|\1|p' | head -1)
        public_key=$(secure_read "$FILE_PATH/list.txt" | sed -n 's/.*[?&]pbk=\([^& #]*\).*/\1/p' | head -1)
    fi
    if [[ -s "$SECURE_STATE/identity.json" ]]; then
        public_key=$(secure_jq -r '.public_key' "$SECURE_STATE/identity.json")
    fi
    secure_tokens
}

secure_validate_state() {
    [[ "$UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || return 1
    [[ "${private_key:-}" =~ ^[A-Za-z0-9_-]{43}=?$ ]] || return 1
    [[ "${public_key:-}" =~ ^[A-Za-z0-9_-]{43}=?$ ]] || return 1
    [[ "${available_ip:-}" =~ ^[0-9a-fA-F:.]+$ ]] || return 1
    local port
    for port in "$VLESS_PORT" "$TUIC_PORT" "$HY2_PORT"; do
        [[ "$port" =~ ^[0-9]+$ ]] && (( port > 0 && port < 65536 )) || return 1
    done
}

secure_render_payload() {
    secure_tls_server_name || return 1
    local stage=$1 source=$2 name="$TLS_SERVER_NAME" fingerprint prefix
    prefix=$(secure_node_prefix) || return 1
    secure_cert_valid "$SECURE_STATE/cert.pem" "$SECURE_STATE/private.key" "$name" || return 1
    fingerprint=$(openssl x509 -in "$SECURE_STATE/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
    [[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]] || return 1
    secure_jq -n --slurpfile config "$source" --slurpfile identity "$SECURE_STATE/identity.json" \
      --rawfile cert "$SECURE_STATE/cert.pem" --arg sni "$name" --arg prefix "$prefix" '
      {outbounds: [$config[0].inbounds[] | . as $i |
        if .type == "tuic" then
          {type:"tuic",tag:"TUIC",server:.listen,server_port:.listen_port,uuid:.users[0].uuid,password:.users[0].password,
           congestion_control:(.congestion_control // "bbr"),udp_relay_mode:"native",zero_rtt_handshake:false,
           tls:{enabled:true,server_name:$sni,insecure:false,alpn:["h3"],certificate:[$cert]}}
        elif .type == "hysteria2" then
          {type:"hysteria2",tag:"HY2",server:.listen,server_port:.listen_port,password:.users[0].password,
           tls:{enabled:true,server_name:$sni,insecure:false,alpn:["h3"],certificate:[$cert]}}
        elif .type == "vless" then
          {type:"vless",tag:"VLESS",server:.listen,server_port:.listen_port,uuid:.users[0].uuid,flow:.users[0].flow,
           tls:{enabled:true,server_name:.tls.server_name,insecure:false,utls:{enabled:true,fingerprint:"chrome"},
                reality:{enabled:true,public_key:$identity[0].public_key,short_id:(.tls.reality.short_id[0] // "")}}}
        else empty end | .tag = ($prefix + "-" + .tag)]}' > "$stage/p01" || return 1
    # Explicit legacy compatibility feed requested by the operator. Never merge it into the secure feed.
    secure_jq '.outbounds |= map(if .type=="vless" then . else del(.tls.certificate) | .tls.insecure=true |
        .tls.server_name="www.bing.com" | .tag += " [SkipVerify]" end)' "$stage/p01" > "$stage/p02" || return 1
    local variant=p01
    for variant in p01; do
        secure_jq -r '.outbounds[] |
          {ConfigVersion:4,ConfigType:(if .type=="tuic" then 8 elif .type=="hysteria2" then 7 else 5 end),CoreType:24,
           Remarks:.tag,Address:.server,Port:.server_port,StreamSecurity:(if .type=="vless" then "reality" else "tls" end),
           AllowInsecure:(.tls.insecure|tostring),Sni:.tls.server_name,Alpn:((.tls.alpn // [])|join(",")),
           Username:(if .type=="tuic" then .uuid else "" end),Password:(if .type=="vless" then .uuid else .password end),
           Cert:((.tls.certificate // [])|join("\n")),PublicKey:(.tls.reality.public_key // ""),ShortId:(.tls.reality.short_id // ""),
           Fingerprint:(if .type=="vless" then "chrome" else "" end),
           ProtoExtraObj:{CongestionControl:(.congestion_control // null),Flow:(.flow // null)}} |
          "v2rayn://" + (if .ConfigType==8 then "tuic" elif .ConfigType==7 then "hysteria2" else "vless" end) + "/" +
          (tojson | @base64 | gsub("\\+";"-") | gsub("/";"_") | gsub("=";""))' \
          "$stage/$variant" > "$stage/p03" || return 1
    done
    # Older GUI releases do not understand v2rayn://. Give the opt-in compatibility
    # feed standard share URIs supported by both apps, with explicit skip flags.
    secure_jq -r '.outbounds[] | . as $o |
      (.server | if contains(":") then "["+.+"]" else . end) as $host |
      (.tag|@uri) as $tag |
      if .type=="tuic" then
        "tuic://"+(.uuid|@uri)+":"+(.password|@uri)+"@"+$host+":"+(.server_port|tostring)+
        "?sni="+(.tls.server_name|@uri)+"&alpn=h3&congestion_control="+(.congestion_control|@uri)+
        "&udp_relay_mode=native&allow_insecure=1#"+$tag
      elif .type=="hysteria2" then
        "hysteria2://"+(.password|@uri)+"@"+$host+":"+(.server_port|tostring)+
        "/?sni="+(.tls.server_name|@uri)+"&alpn=h3&insecure=1#"+$tag
      else
        "vless://"+(.uuid|@uri)+"@"+$host+":"+(.server_port|tostring)+
        "?encryption=none&flow="+(.flow|@uri)+"&security=reality&sni="+(.tls.server_name|@uri)+
        "&fp=chrome&pbk="+(.tls.reality.public_key|@uri)+"&type=tcp&headerType=none#"+$tag
      end' "$stage/p02" > "$stage/p04" || return 1
    # JSON is also valid YAML; building through secure_jq avoids YAML interpolation bugs.
    secure_jq --arg fp "$fingerprint" '
      {"mixed-port":7890,mode:"rule",proxies:[.outbounds[] |
        if .type=="tuic" then
          {name:.tag,type:.type,server:.server,port:.server_port,uuid:.uuid,password:.password,sni:.tls.server_name,
           alpn:.tls.alpn,"skip-cert-verify":false,fingerprint:$fp,"congestion-controller":.congestion_control,
           "udp-relay-mode":"native","reduce-rtt":false,udp:true}
        elif .type=="hysteria2" then
          {name:.tag,type:.type,server:.server,port:.server_port,password:.password,sni:.tls.server_name,
           alpn:.tls.alpn,"skip-cert-verify":false,fingerprint:$fp,udp:true}
        else
          {name:.tag,type:"vless",server:.server,port:.server_port,uuid:.uuid,flow:.flow,tls:true,udp:true,
           servername:.tls.server_name,"skip-cert-verify":false,"client-fingerprint":"chrome",
           "reality-opts":{"public-key":.tls.reality.public_key,"short-id":.tls.reality.short_id}}
        end],"proxy-groups":[{name:"PROXY",type:"select",proxies:[.outbounds[].tag]}],rules:["MATCH,PROXY"]}' \
      "$stage/p01" > "$stage/p05" || return 1
    local f
    for f in p01 p02 p05; do secure_jq -e . "$stage/$f" >/dev/null || return 1; done
    # Fail closed if any server private material or verification bypass slips into output.
    if grep -Eq 'PRIVATE KEY|"private_key"|"key_path"' "$stage"/*; then return 1; fi
    if grep -Eq '"insecure" *: *true|"skip-cert-verify" *: *true' "$stage/p01" "$stage/p05"; then return 1; fi
    # One subscription contains VLESS + secure/legacy TUIC + secure/legacy HY2.
    # Standard links keep old clients usable; v2rayN also imports the native PEM nodes.
    cat "$stage/p04" > "$stage/p06" || return 1
    grep -E '^v2rayn://(tuic|hysteria2)/' "$stage/p03" >> "$stage/p06" || return 1
    base64 < "$stage/p06" | tr -d '\n' > "$stage/p07"
    secure_jq --slurpfile legacy "$stage/p02" \
      '.outbounds += [$legacy[0].outbounds[] | select(.type!="vless")]' "$stage/p01" > "$stage/p08" || return 1
    secure_jq '.proxies += [.proxies[] | select(.type!="vless") | del(.fingerprint) |
        .["skip-cert-verify"]=true | .sni="www.bing.com" | .name += " [SkipVerify]"] |
        .["proxy-groups"][0].proxies=[.proxies[].name]' "$stage/p05" > "$stage/p09" || return 1
    secure_jq -e '.outbounds|length==5' "$stage/p08" >/dev/null || return 1
    secure_jq -e '.proxies|length==5' "$stage/p09" >/dev/null || return 1
    secure_rules_apply "$stage/p09" "$stage/p09" || return 1
    chmod 600 "$stage"/*
}

secure_publish() (
    set -o pipefail
    # No certificate creation; each share is rendered from its own protocol users.
    secure_init && secure_tokens && secure_shares_init || return 1
    local stage source="${SALKSD_PUBLISH_CONFIG:-$SECURE_STATE/server.json}" fingerprint
    stage=$(mktemp -d "$SECURE_STATE/.subscriptions.XXXXXX") || return 1
    trap "if [[ -d $(printf '%q' "$stage") ]]; then rm -f -- $(printf '%q' "$stage")/*; rmdir $(printf '%q' "$stage"); fi" EXIT
    secure_render_payload "$stage" "$source" || return 1
    secure_share_payloads "$stage" "$source" || return 1
    fingerprint=$(openssl x509 -in "$SECURE_STATE/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
    if [[ "${SALKSD_STAGE_ONLY:-0}" == 1 ]]; then
        rm -f "$stage"/*
        rmdir "$stage"
        return 0
    fi
    local generation="subscriptions-$(date +%s)-$$-$RANDOM"
    local stored
    for stored in "$stage"/*; do secure_seal "$stored" || return 1; done
    mv "$stage" "$SECURE_STATE/$generation" || return 1
    # Save a relative generation name; a single rename publishes all formats atomically.
    printf '%s\n' "$generation" > "$SECURE_STATE/current.new"
    mv "$SECURE_STATE/current.new" "$SECURE_STATE/current" || return 1
    secure_install_http || return 1
    printf '%s\n' "$fingerprint" > "$SECURE_STATE/published-fingerprint"
)

secure_install_http() {
    local -
    set -o pipefail
    mkdir -p "$FILE_PATH" || return 1
    secure_install_landing || return 1
    # Serv00 PHP is restricted to public_html by open_basedir; the front-end also
    # requires a readable PHP entrypoint. Keep its code separate from client secrets.
    # The data directory is 700, its bundle is 600 and HTTP access is denied.
    secure_panel_init || return 1
    local generation file bundle token_hash
    generation=$(cat "$SECURE_STATE/current") || return 1
    [[ "$generation" =~ ^subscriptions-[0-9]+-[0-9]+-[0-9]+$ ]] || return 1
    token_hash=$(printf '%s' "$SECURE_TOKEN" | openssl dgst -sha256 -r | awk '{print $1}')
    bundle=$(mktemp "$SECURE_STATE/.http.XXXXXX") || return 1
    secure_jq -nc --rawfile b "$SECURE_STATE/$generation/p07" --rawfile s "$SECURE_STATE/$generation/p08" \
      --rawfile c "$SECURE_STATE/$generation/p09" --arg hash "$token_hash" --slurpfile shares "$SECURE_STATE/$generation/shares.json" \
      --slurpfile index "$SECURE_STATE/$generation/share-index.json" --slurpfile server "$SECURE_STATE/server.json" \
      '{token_hash:$hash,shares:$shares[0],share_index:$index[0],ports:($server[0].inbounds|map({key:.type,value:.listen_port})|from_entries),content:{p07:$b,p08:$s,p09:$c}}' | secure_store_stream "$bundle" || return 1
    local handler="$SECURE_STATE/secure-sub.php.new" data_dir="$FILE_PATH/.salksd-data"
    {
      secure_php_runtime_source | sed '1d'
      {
    # SALKSD HTTP BEGIN
    cat "$(dirname "${BASH_SOURCE[0]}")/sub-router.php"
    # SALKSD HTTP END
      } | sed -e '1d' -e '/^declare(strict_types=1);/d' -e '/^require_once __DIR__/d'
    } | secure_php_wrapper > "$handler" || return 1
    if command -v php >/dev/null; then php -l "$handler" >/dev/null || return 1; fi
    (umask 077; mkdir -p "$data_dir") || return 1
    chmod 700 "$data_dir" || return 1
    printf 'Require all denied\n' > "$data_dir/.htaccess" || return 1
    chmod 644 "$data_dir/.htaccess" || return 1
    chmod 600 "$bundle" || return 1
    secure_store "$bundle" "$data_dir/bundle.json" && rm -f "$bundle" || return 1
    # This router contains no UUID, password, token, certificate or server private key.
    chmod 644 "$handler"
    # The private and site directories are on the same home filesystem: atomic rename
    # avoids ever serving a partially written PHP program or a .new source file.
    mv "$handler" "$FILE_PATH/secure-sub.php" || return 1
    # Maintain the baseline rules, replacing only our managed block on subsequent runs.
    cat > "$FILE_PATH/.htaccess.new" <<'APACHE'
# SALKSD SECURE BEGIN
Options -Indexes
RewriteEngine On
RewriteRule ^\.well-known/acme-challenge/ - [L]
RewriteRule ^(?:index\.html|secure-sub\.php)$ - [L]
RewriteRule ^manage/([0-9a-f]{64})/?$ secure-sub.php?token=$1&format=manage [L,QSA]
RewriteRule ^([0-9a-f]{64}|[A-Za-z0-9_-]{8})(/[cbsn])?$ secure-sub.php [L,QSA]
RewriteRule ^.*$ secure-sub.php?format=cover [L]
APACHE
    # Keep the original subscription URL and its authoritative rewrite below.
    # Its client format is now generated locally with the requested five nodes.
    cat >> "$FILE_PATH/.htaccess.new" <<'APACHE'
<FilesMatch "^(list\.txt|p0[789]|cert\.pem|private\.key)$">
    Require all denied
</FilesMatch>
# SALKSD SECURE END
APACHE
    # Serv00's nginx replaces local Apache 403 error bodies. An external redirect
    # reaches the cover page while retaining deny rules and 700/600 permissions.
    local cover_host="api.${USERNAME}.${CURRENT_DOMAIN}"
    [[ "$cover_host" =~ ^[A-Za-z0-9][A-Za-z0-9.-]+$ ]] || return 1
    # Insert before the managed block end so subsequent updates replace these too.
    sed '/^# SALKSD SECURE END$/d' "$FILE_PATH/.htaccess.new" > "$FILE_PATH/.htaccess.rules" || return 1
    printf 'ErrorDocument 403 https://%s/\nErrorDocument 404 https://%s/\n# SALKSD SECURE END\n' "$cover_host" "$cover_host" >> "$FILE_PATH/.htaccess.rules"
    mv "$FILE_PATH/.htaccess.rules" "$FILE_PATH/.htaccess.new" || return 1
    if [[ -f "$FILE_PATH/.htaccess" ]]; then
        # Remove only obsolete generated routes and filenames, preserving other site directives.
        sed '/^# SALKSD SECURE BEGIN$/,/^# SALKSD SECURE END$/d' "$FILE_PATH/.htaccess" |
          awk '!($1=="RewriteRule" && $3 ~ /^[A-Za-z0-9_-]+\.php$/) {
            if ($0 ~ /<FilesMatch/ && $0 ~ /clash|singbox|nekobox/) { print "<FilesMatch \"^(p0[789]|list\\.txt|cert\\.pem|private\\.key)$\">"; next }
            if ($0 ~ /<FilesMatch/ && $0 ~ /[A-Za-z0-9_-]+\\\.php/) print "<FilesMatch \"^index\\.html$\">"; else print
          }' >> "$FILE_PATH/.htaccess.new"
    else
        printf 'DirectoryIndex index.html\n' >> "$FILE_PATH/.htaccess.new"
    fi
    chmod 644 "$FILE_PATH/.htaccess.new"
    mv "$FILE_PATH/.htaccess.new" "$FILE_PATH/.htaccess" || return 1
    # Summary failure must not stop a healthy proxy service; cleanup then stays unavailable.
    secure_backups_refresh || :
}

secure_install_landing() {
    secure_init || return 1
    local landing="$SECURE_STATE/index.html.new" previous
    # SALKSD LANDING BEGIN
    cat "$(dirname "${BASH_SOURCE[0]}")/public-index.html" > "$landing" || return 1
    # SALKSD LANDING END
    if [[ -f "$FILE_PATH/index.html" ]] && cmp -s "$landing" "$FILE_PATH/index.html"; then
        rm -f "$landing"
        return 0
    fi
    if [[ -e "$FILE_PATH/index.html" ]]; then
        previous="$SECURE_STATE/backups/landing-$(date +%Y%m%d-%H%M%S)-$$-$RANDOM"
        (umask 077; mkdir "$previous"; cp -p "$FILE_PATH/index.html" "$previous/index.html") || return 1
    fi
    chmod 644 "$landing"
    mv "$landing" "$FILE_PATH/index.html"
}

secure_panel_init() {
    local data_dir="$FILE_PATH/.salksd-data" settings
    (umask 077; mkdir -p "$data_dir/sessions") || return 1
    chmod 700 "$data_dir" "$data_dir/sessions" || return 1
    printf 'Require all denied\n' > "$data_dir/.htaccess" || return 1
    chmod 644 "$data_dir/.htaccess"
    if [[ ! -e "$data_dir/panel.json" ]]; then
        settings=$(mktemp "$data_dir/.panel.XXXXXX") || return 1
        secure_jq -n --arg revision "$(openssl rand -hex 32)" '{password_hash:"",revision:$revision}' > "$settings" || return 1
        chmod 600 "$settings"
        secure_store "$settings" "$data_dir/panel.json" && rm -f "$settings" || return 1
    fi
    # Corrupt settings must not silently disable an existing password.
    secure_jq -e '(.password_hash|type)=="string" and (.revision|test("^[0-9a-f]{64}$"))' "$data_dir/panel.json" >/dev/null
}

secure_panel_result() {
    local status=$1 id=$2 data_dir="$FILE_PATH/.salksd-data" result
    result=$(mktemp "$data_dir/.result.XXXXXX") || return 1
    secure_jq -n --arg status "$status" --arg id "$id" --arg action "${3:-change-ports}" --argjson at "$(date +%s)" \
      '{status:$status,id:$id,action:$action,updated_at:$at}' > "$result" || return 1
    chmod 600 "$result"
    mv "$result" "$data_dir/result.json"
}

secure_panel_poll() {
    local data_dir="$FILE_PATH/.salksd-data" id now created status protocol action
    [[ -f "$data_dir/request.json" && ! -L "$data_dir/request.json" ]] || return 0
    mkdir "$data_dir/queue.lock" 2>/dev/null || return 0
    if [[ -d "$SECURE_STATE/operation.lock" || -e "$data_dir/running.json" ]]; then
        rmdir "$data_dir/queue.lock"
        return 0
    fi
    # Only the existing worker consumes this fixed command; never eval web input.
    if ! mv "$data_dir/request.json" "$data_dir/running.json"; then
        rmdir "$data_dir/queue.lock"
        return 1
    fi
    rmdir "$data_dir/queue.lock"
    if ! secure_jq -e '(if .action=="change-ports" then
          ((keys-["action","created_at","id","protocol"]|length)==0) and
          ((.protocol // "all") as $p | ["all","vless","tuic","hysteria2"]|index($p)!=null)
        elif .action=="share-create" then
          keys==["action","created_at","duration","id","label"] and
          (.label|type)=="string" and (.label|length)<=80 and
          (.duration|type)=="number" and .duration>=60 and .duration<=31622400 and (.duration|floor)==.duration
        elif .action=="share-revoke" or .action=="share-delete" then
          keys==["action","created_at","id","share_id"] and (.share_id|test("^[0-9a-f]{32}$"))
        elif .action=="share-prune" or .action=="backup-refresh" then
          keys==["action","created_at","id"]
        elif .action=="backup-prune" then
          keys==["action","created_at","id","keep","revision"] and
          (.keep|type)=="number" and .keep>=1 and .keep<=1000 and (.keep|floor)==.keep and
          (.revision|test("^[0-9a-f]{64}$"))
        elif .action=="rules-save" then
          keys==["action","created_at","id","rules"] and
          (.rules|type)=="object" and (.rules|keys)==["ini","mode"] and
          (.rules.mode=="default" or .rules.mode=="custom") and (.rules.ini|type)=="string" and (.rules.ini|length)<=262144
        else false end) and
        (.id|type)=="string" and (.id|test("^[0-9a-f]{32}$")) and
        (.created_at|type)=="number" and (.created_at|floor)==.created_at' "$data_dir/running.json" >/dev/null 2>&1; then
        secure_panel_result rejected invalid
        rm -f "$data_dir/running.json"
        return 1
    fi
    id=$(secure_jq -r '.id' "$data_dir/running.json")
    action=$(secure_jq -r '.action' "$data_dir/running.json")
    created=$(secure_jq -r '.created_at' "$data_dir/running.json")
    protocol=$(secure_jq -r '.protocol // "all"' "$data_dir/running.json")
    now=$(date +%s)
    if (( created < now - 300 || created > now + 30 )); then
        secure_panel_result expired "$id"
        rm -f "$data_dir/running.json"
        return 0
    fi
    secure_panel_result running "$id" "$action" || return 1
    # Keep this worker alive: the transaction still owns the usual operation lock,
    # backup, restart, rollback and runtime cleanup, without starting a second worker.
    if (umask 077; SALKSD_PANEL_IN_WORKER=1 secure_operation "--$action" "$protocol" "$data_dir/running.json" > "$SECURE_STATE/panel-operation.log" 2>&1); then
        status=success
    else
        status=failed
    fi
    secure_panel_result "$status" "$id" "$action" || return 1
    rm -f "$data_dir/running.json"
    load_config
}

secure_panel_wait() {
    # Keep the baseline five-minute maintenance interval; check only the web
    # mailbox between maintenance passes, without adding a resident process.
    local elapsed
    for ((elapsed=0; elapsed<300; elapsed+=5)); do
        secure_shares_poll || :
        secure_panel_poll || :
        sleep 5
    done
}

secure_show_links() {
    secure_tokens || return 1
    printf '\n64 位自用订阅与管理入口（请勿分享）：\nhttps://api.%s.%s/%s\n' "$USERNAME" "$CURRENT_DOMAIN" "$SECURE_TOKEN"
    printf '分享订阅请在管理面板生成，使用独立账号并设置到期时间。\n'
}

secure_core_pids() {
    local pid directory wanted
    wanted=$(cd "$WORKDIR" && pwd -P) || return 1
    for pid in $(pgrep -u "$(id -u)" -x unbound); do
        if [[ -d /proc/$pid ]]; then
            directory=$(readlink "/proc/$pid/cwd")
        else
            directory=$(procstat -f "$pid" 2>/dev/null | awk '$3=="cwd" {print $NF}')
        fi
        [[ "$directory" != "$wanted" ]] || printf '%s\n' "$pid"
    done
}

secure_worker_pids() {
    # Match this worker's exact path; do not kill SSH sessions or other account services.
    local pid command path resolved expected
    expected=$(cd "$WORKDIR" && pwd -P) || return 1
    while read -r pid command path; do
        [[ "$pid" != "$$" && "$command" =~ (^|/)bash$ && "$path" == */unbound_start.sh ]] || continue
        resolved=$(cd "$(dirname "$path")" 2>/dev/null && pwd -P) || continue
        [[ "$resolved" != "$expected" ]] || printf '%s\n' "$pid"
    # FreeBSD treats "pid=,args=" as one field with a literal header; use two -o flags.
    done < <(ps -U "$(id -u)" -o pid= -o args=)
}

secure_stop_managed() {
    local pid targets workers
    # A web task runs inside the existing worker. Its bash subshells inherit the
    # same command line and must not be mistaken for old workers to terminate.
    if [[ "${SALKSD_PANEL_IN_WORKER:-0}" == 1 ]]; then
        workers=
    else
        workers=$(secure_worker_pids)
    fi
    targets="$workers $(secure_core_pids)"
    for pid in $workers; do
        # End only this worker's sleep child, so repeated restarts do not leave
        # orphaned five-minute sleeps consuming the hosting account's process limit.
        targets="$targets $(pgrep -P "$pid" -x sleep)"
    done
    for pid in $targets; do
        kill "$pid" 2>/dev/null || :
    done
    sleep 2
    # Bash may defer TERM while waiting for its 300-second sleep. Only the exact
    # process IDs identified above can be force-stopped, never an account-wide kill.
    for pid in $targets; do
        kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || :
    done
    [[ -z "$(secure_core_pids)" ]]
}

secure_stop_workers() {
    # Old workers cannot read the new persistent encoding. Stop only this service's
    # worker before migration; leave the core accepting connections until checks pass.
    [[ "${SALKSD_PANEL_IN_WORKER:-0}" != 1 ]] || return 0
    local pid targets
    targets=$(secure_worker_pids)
    for pid in $targets; do targets="$targets $(pgrep -P "$pid" -x sleep)"; done
    for pid in $targets; do kill "$pid" 2>/dev/null || :; done
    [[ -z "$targets" ]] || sleep 1
    for pid in $targets; do kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || :; done
}

secure_start_core() {
    secure_shares_apply "$CONFIG_FILE" || return 1
    nohup "$UNBOUND_EXEC" run -c "$CONFIG_FILE" >"${SECURE_BACKUP:-$SECURE_STATE}/startup.log" 2>&1 < /dev/null &
    local started=$!
    sleep 2
    kill -0 "$started" 2>/dev/null || return 1
    secure_share_lease "$started" || { kill "$started" 2>/dev/null || :; return 1; }
}

secure_cleanup_runtime() {
    # Same binary name, deletion, config deletion and cache cleanup as the baseline.
    rm -rf unbound "$CONFIG_FILE" private.key cert.pem sb.log core fake_useragent_0.2.0.json
}

secure_start_worker() {
    [[ "${SALKSD_PANEL_IN_WORKER:-0}" != 1 ]] || return 0
    [[ -z "$(secure_worker_pids)" ]] || return 0
    nohup "$WORKDIR/unbound_start.sh" >"$WORKDIR/keepalive.log" 2>&1 < /dev/null &
    local worker_pid=$!
    sleep 1
    kill -0 "$worker_pid" 2>/dev/null
}

secure_port_snapshot() {
    devil port list | awk '$1 ~ /^[0-9]+$/ && $2 ~ /^(tcp|udp)$/ {print $2 " " $1}'
}

secure_ports_rollback() {
    local proto port failed=0
    while read -r proto port; do
        [[ -z "$proto" ]] || devil port del "$proto" "$port" >/dev/null 2>&1 || failed=1
    done < "$SECURE_BACKUP/added-ports"
    while read -r proto port; do
        [[ -z "$proto" ]] || devil port add "$proto" "$port" >/dev/null 2>&1 || failed=1
    done < "$SECURE_BACKUP/removed-ports"
    (( failed == 0 ))
}

secure_recover_operation() {
    # Called only after the old process was stopped. Do not report recovery until
    # the core and worker have both started; retain diagnostics and backup either way.
    local action=$1
    local ports_ok=0
    if [[ "$action" == --change-ports ]]; then
        secure_ports_rollback || ports_ok=1
    fi
    local pid
    for pid in $(secure_core_pids); do kill -KILL "$pid" 2>/dev/null || :; done
    secure_read "$SECURE_BACKUP/recovered-server.json" > "$CONFIG_FILE" || return 1
    cp "$SECURE_BACKUP/recovered-cert.pem" "$WORKDIR/cert.pem" || return 1
    secure_read "$SECURE_BACKUP/recovered-private.key" > "$WORKDIR/private.key" || return 1
    secure_start_core || return 1
    secure_capture_config "$CONFIG_FILE" || return 1
    secure_restore_identity && secure_write_keepalive || return 1
    secure_publish && secure_refresh_legacy || echo '恢复后的订阅更新失败；旧订阅仍在备份中。' >&2
    secure_cleanup_runtime
    secure_start_worker || return 1
    (( ports_ok == 0 ))
}

secure_replace_ports() {
    local variable proto old candidate attempt added
    local variables=()
    case "${1:-all}" in
        all) variables=(VLESS_PORT TUIC_PORT HY2_PORT) ;;
        vless) variables=(VLESS_PORT) ;;
        tuic) variables=(TUIC_PORT) ;;
        hysteria2) variables=(HY2_PORT) ;;
        *) return 1 ;;
    esac
    : > "$SECURE_BACKUP/added-ports"
    : > "$SECURE_BACKUP/removed-ports"
    secure_port_snapshot > "$SECURE_BACKUP/port-snapshot"
    for variable in "${variables[@]}"; do
        proto=udp; [[ "$variable" != VLESS_PORT ]] || proto=tcp
        old=${!variable}
        if grep -qx "$proto $old" "$SECURE_BACKUP/port-snapshot"; then
            devil port del "$proto" "$old" >/dev/null 2>&1 || return 1
            printf '%s %s\n' "$proto" "$old" >> "$SECURE_BACKUP/removed-ports"
        fi
        added=false
        for attempt in {1..30}; do
            candidate=$(shuf -i 10000-65535 -n 1)
            [[ "$candidate" != "$old" ]] || continue
            if devil port add "$proto" "$candidate" >/dev/null 2>&1 && secure_port_snapshot | grep -qx "$proto $candidate"; then
                printf '%s %s\n' "$proto" "$candidate" >> "$SECURE_BACKUP/added-ports"
                printf -v "$variable" '%s' "$candidate"
                added=true
                break
            fi
        done
        [[ "$added" == true ]] || return 1
    done
    secure_jq --argjson v "$VLESS_PORT" --argjson t "$TUIC_PORT" --argjson h "$HY2_PORT" \
      '.inbounds |= map(if .type=="vless" then .listen_port=$v elif .type=="tuic" then .listen_port=$t elif .type=="hysteria2" then .listen_port=$h else . end)' \
      "$CONFIG_FILE" > "$CONFIG_FILE.new" || return 1
    mv "$CONFIG_FILE.new" "$CONFIG_FILE"
}

secure_operation() (
    # Invoked by the worker with --restart / --change-ports; no installer/reset path.
    umask 077
    local action=$1 protocol=${2:-all} request=${3:-} worker_stopped=0
    case "$protocol" in all|vless|tuic|hysteria2) ;; *) exit 1 ;; esac
    secure_init || exit 1
    if ! mkdir "$SECURE_STATE/operation.lock" 2>/dev/null; then
        echo '已有重启或端口操作在进行；请稍后再试。' >&2
        exit 1
    fi
    trap 'rmdir "$SECURE_STATE/operation.lock" 2>/dev/null || :; if [[ "${worker_stopped:-0}" == 1 ]]; then secure_start_worker || :; fi' EXIT
    load_config || exit 1
    if [[ "$action" == --backup-refresh ]]; then
        secure_backups_refresh
        exit $?
    fi
    if [[ "$action" == --backup-prune ]]; then
        # Removing old backups must not create another full backup or restart the core.
        secure_backups_prune "$request"
        exit $?
    fi
    secure_backup && secure_stop_workers || exit 1
    worker_stopped=1
    secure_storage_migrate && secure_restore_identity && secure_validate_state || exit 1
    secure_shares_init || exit 1
    case "$action" in
        --rules-save) secure_rules_change "$request"; exit $? ;;
        --share-delete|--share-prune)
            secure_share_remove "$action" "$request" && secure_publish
            exit $? ;;
        --share-create|--share-revoke) secure_share_edit "$action" "$request" || exit 1 ;;
        --restart|--change-ports|--sync-shares) ;;
        *) exit 1 ;;
    esac
    # Once revocation is committed, certificate/download/validation failures must
    # never leave a running core accepting the revoked account.
    if [[ "$action" == --sync-shares || "$action" == --share-revoke ]]; then
        secure_stop_managed || exit 1
    fi
    secure_prepare_certificate || exit 1
    if [[ -f "$SECURE_STATE/server.json" ]]; then
        secure_read "$SECURE_STATE/server.json" > "$CONFIG_FILE" || exit 1
    else
        generate_config_file || exit 1
    fi
    # A revocation must never fall back to a configuration with expired accounts.
    secure_shares_apply "$CONFIG_FILE" || exit 1
    [[ -x "$UNBOUND_EXEC" ]] || download_unbound_binary || exit 1
    "$UNBOUND_EXEC" check -c "$CONFIG_FILE" > "$SECURE_BACKUP/check.log" 2>&1 || {
        echo '配置检查失败，未启动新核心；检查记录保存在私有备份目录。' >&2
        exit 1
    }
    # Verify all subscription payloads before stopping a live process.
    # Defer the HTTP installation/current-generation switch until the new core is healthy.
    SALKSD_PUBLISH_CONFIG="$CONFIG_FILE" SALKSD_STAGE_ONLY=1 secure_publish || { echo '订阅预检查失败。' >&2; exit 1; }
    # Record the recovered old configuration before changing any ports.
    secure_store "$CONFIG_FILE" "$SECURE_BACKUP/recovered-server.json" || exit 1
    cp "$SECURE_STATE/cert.pem" "$SECURE_BACKUP/recovered-cert.pem" || exit 1
    cp "$SECURE_STATE/private.key" "$SECURE_BACKUP/recovered-private.key" || exit 1
    secure_stop_managed || exit 1
    if [[ "$action" == --change-ports ]] && ! secure_replace_ports "$protocol"; then
        if secure_recover_operation "$action"; then
            echo '端口更换失败，已恢复原配置和服务；请检查平台端口恢复结果。' >&2
        else
            echo '端口更换失败且自动恢复未完成，请使用已保存的备份恢复。' >&2
        fi
        exit 1
    fi
    if ! secure_start_core; then
        if secure_recover_operation "$action"; then
            echo '新配置启动失败，已恢复原配置和服务。' >&2
        else
            echo '启动失败且自动恢复未完成，请使用已保存的备份恢复。' >&2
        fi
        exit 1
    fi
    if ! secure_capture_config "$CONFIG_FILE" || ! secure_write_keepalive || ! secure_publish || ! secure_refresh_legacy; then
        if secure_recover_operation "$action"; then
            echo '订阅发布失败，已恢复原配置、端口和服务。' >&2
        else
            echo '订阅发布失败且恢复未完成，请使用已保存的备份恢复。' >&2
        fi
        exit 1
    fi
    secure_cleanup_runtime
    secure_start_worker || { echo '核心已启动，但保活未能启动。' >&2; exit 1; }
    echo '操作完成：证书、认证信息和订阅地址保持稳定。'
    echo "恢复备份：$SECURE_BACKUP"
)

secure_refresh_legacy() {
    # Preserve connection parameters while updating ports and requested ASCII labels.
    [[ -f "$FILE_PATH/list.txt" ]] || return 0
    local v t h prefix
    prefix=$(secure_node_prefix) || return 1
    v=$(secure_jq -r '.inbounds[]|select(.type=="vless")|.listen_port' "$SECURE_STATE/server.json")
    t=$(secure_jq -r '.inbounds[]|select(.type=="tuic")|.listen_port' "$SECURE_STATE/server.json")
    h=$(secure_jq -r '.inbounds[]|select(.type=="hysteria2")|.listen_port' "$SECURE_STATE/server.json")
    secure_read "$FILE_PATH/list.txt" | sed -E -e "s#^(vless://[^@]*@[^:]*:)[0-9]+#\\1$v#" \
      -e "s#^(tuic://[^@]*@[^:]*:)[0-9]+#\\1$t#" \
      -e "s#^(hysteria2://[^@]*@[^:]*:)[0-9]+#\\1$h#" \
      -e "s|^(vless://[^#]*)(#.*)?$|\\1#${prefix}-VLESS|" \
      -e "s|^(tuic://[^#]*)(#.*)?$|\\1#${prefix}-TUIC%20%5BSkipVerify%5D|" \
      -e "s|^(hysteria2://[^#]*)(#.*)?$|\\1#${prefix}-HY2%20%5BSkipVerify%5D|" \
      > "$FILE_PATH/list.txt.new" || return 1
    secure_store "$FILE_PATH/list.txt.new" "$FILE_PATH/list.txt" && rm -f "$FILE_PATH/list.txt.new"
    # Keep all old adaptive subscription formats synchronized without sending
    # credentials to a third-party converter. Their URL/token is unchanged.
    local generation
    generation=$(cat "$SECURE_STATE/current") || return 1
    cp "$SECURE_STATE/$generation/p09" "$FILE_PATH/p09" || return 1
    cp "$SECURE_STATE/$generation/p08" "$FILE_PATH/p08" || return 1
    cp "$SECURE_STATE/$generation/p07" "$FILE_PATH/p07" || return 1
}
