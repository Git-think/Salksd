#!/bin/bash
# Included in the two standalone artifacts; no separate server-side installation.
secure_shares_init() {
    if [[ ! -e "$SECURE_STATE/shares.json" ]]; then
        # Losing the ledger must not resurrect accounts already in a saved config.
        if [[ -f "$SECURE_STATE/server.json" ]] && secure_jq -e 'any(.inbounds[].users[]?; (.name // "")|startswith("salksd-share-"))' "$SECURE_STATE/server.json" >/dev/null; then return 1; fi
        (umask 077; printf '[]\n' > "$SECURE_STATE/shares.json") || return 1
    fi
    secure_seal "$SECURE_STATE/shares.json" && secure_shares_validate "$SECURE_STATE/shares.json"
}

secure_shares_validate() {
    secure_jq -e 'def uuid: test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$");
      def timestamp: type=="number" and .>=0 and floor==.;
      type=="array" and length<=128 and all(.[];
      (.id|test("^[0-9a-f]{32}$")) and (.token|test("^[A-Za-z0-9_-]{8}$")) and
      (.label|type)=="string" and (.label|length)<=80 and (.created_at|timestamp) and
      (.expires_at|timestamp) and (.revoked_at|timestamp) and
      (.vless_uuid|uuid) and (.tuic_uuid|uuid) and
      (.tuic_password|test("^[0-9a-f]{64}$")) and (.hy2_password|test("^[0-9a-f]{64}$"))) and
      ([.[].id]|length)==([.[].id]|unique|length) and
      ([.[].token]|length)==([.[].token]|unique|length) and
      ([.[]|.vless_uuid,.tuic_uuid]|length)==([.[]|.vless_uuid,.tuic_uuid]|unique|length) and
      ([.[]|.tuic_password,.hy2_password]|length)==([.[]|.tuic_password,.hy2_password]|unique|length)' "$1" >/dev/null
}

secure_share_uuid() {
    local hex
    hex=$(openssl rand -hex 16) || return 1
    [[ "$hex" =~ ^[0-9a-f]{32}$ ]] || return 1
    printf '%s-%s-4%s-8%s-%s' "${hex:0:8}" "${hex:8:4}" "${hex:13:3}" "${hex:17:3}" "${hex:20:12}"
}

secure_retired_init() {
    if [[ ! -e "$SECURE_STATE/share-retired.json" ]]; then
        (umask 077; printf '[]\n' > "$SECURE_STATE/share-retired.json") || return 1
    fi
    secure_retired_validate "$SECURE_STATE/share-retired.json"
}

secure_retired_validate() {
    secure_jq -e 'type=="array" and all(.[]; keys==["id","token_hash"] and
      (.id|test("^[0-9a-f]{32}$")) and (.token_hash|test("^[0-9a-f]{64}$"))) and
      ([.[].id]|length)==([.[].id]|unique|length) and
      ([.[].token_hash]|length)==([.[].token_hash]|unique|length)' "$1" >/dev/null
}

secure_share_token_available() {
    local token=$1 hash
    [[ ! -f "$SECURE_STATE/legacy-token" || "$token" != "$(secure_read "$SECURE_STATE/legacy-token")" ]] || return 1
    secure_jq -e --arg token "$token" 'all(.[]; .token!=$token)' "$SECURE_STATE/shares.json" >/dev/null || return 1
    hash=$(printf '%s' "$token" | openssl dgst -sha256 -r | awk '{print $1}') || return 1
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || return 1
    secure_jq -e --arg hash "$hash" 'all(.[]; .token_hash!=$hash)' "$SECURE_STATE/share-retired.json" >/dev/null
}

secure_share_remove() (
    # Only remove inactive records whose protocol accounts are already unloaded.
    # Store token hashes first, so interruption cannot make a deleted URL reusable.
    umask 077
    set -o pipefail
    local action=$1 request=$2 now id token hash stage
    secure_shares_init && secure_retired_init || return 1
    now=$(date +%s) || return 1
    stage=$(mktemp -d "$SECURE_STATE/.share-remove.XXXXXX") || return 1
    trap "rm -f -- $(printf '%q' "$stage")/*; rmdir $(printf '%q' "$stage")" EXIT
    if [[ "$action" == --share-delete ]]; then
        id=$(secure_jq -er '.share_id|select(test("^[0-9a-f]{32}$"))' "$request") || return 1
        if ! secure_jq -e --arg id "$id" 'any(.[]; .id==$id)' "$SECURE_STATE/shares.json" >/dev/null; then
            secure_jq -e --arg id "$id" 'any(.[]; .id==$id)' "$SECURE_STATE/share-retired.json" >/dev/null
            return $?
        fi
        secure_jq -e --arg id "$id" --argjson now "$now" 'any(.[]; .id==$id and (.revoked_at>0 or .expires_at<=$now))' \
          "$SECURE_STATE/shares.json" >/dev/null || return 1
        secure_jq --arg id "$id" '[.[]|select(.id==$id)]' "$SECURE_STATE/shares.json" > "$stage/removed.json" || return 1
    elif [[ "$action" == --share-prune ]]; then
        secure_jq --argjson now "$now" '[.[]|select(.revoked_at>0 or .expires_at<=$now)]' \
          "$SECURE_STATE/shares.json" > "$stage/removed.json" || return 1
    else
        return 1
    fi
    secure_jq -e --slurpfile removed "$stage/removed.json" '
      [$removed[0][]|"salksd-share-"+.id] as $names |
      all(.inbounds[].users[]?; (.name // "") as $name | ($names|index($name))==null)' \
      "$SECURE_STATE/server.json" >/dev/null || return 1
    : > "$stage/hashes.jsonl"
    for id in $(secure_jq -r '.[].id' "$stage/removed.json" | tr -d '\r'); do
        token=$(secure_jq -r --arg id "$id" '.[]|select(.id==$id)|.token' "$stage/removed.json") || return 1
        hash=$(printf '%s' "$token" | openssl dgst -sha256 -r | awk '{print $1}') || return 1
        [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || return 1
        secure_jq -cn --arg id "$id" --arg hash "$hash" '{id:$id,token_hash:$hash}' >> "$stage/hashes.jsonl" || return 1
    done
    secure_jq -s '.[0] + .[1:] | unique_by(.id)' "$SECURE_STATE/share-retired.json" "$stage/hashes.jsonl" > "$stage/retired.json" || return 1
    secure_jq --slurpfile removed "$stage/removed.json" '[$removed[0][].id] as $ids |
      map(select(.id as $id | ($ids|index($id))==null))' "$SECURE_STATE/shares.json" > "$stage/shares.json" || return 1
    secure_retired_validate "$stage/retired.json" && secure_shares_validate "$stage/shares.json" || return 1
    chmod 600 "$stage/retired.json" "$stage/shares.json" || return 1
    mv "$stage/retired.json" "$SECURE_STATE/share-retired.json" || return 1
    secure_store "$stage/shares.json" "$SECURE_STATE/shares.json"
)

secure_share_edit() (
    # Validate every random result before atomically replacing the ledger. A failed
    # command substitution passed straight to secure_jq would otherwise become an empty credential.
    umask 077
    local action=$1 request=$2 next token id now vless_uuid tuic_uuid tuic_password hy2_password attempt
    [[ -s "$request" ]] || return 1
    secure_shares_init && secure_retired_init || return 1
    now=$(date +%s) || return 1
    [[ "$now" =~ ^[0-9]+$ ]] || return 1
    next=$(mktemp "$SECURE_STATE/.shares.XXXXXX") || return 1
    trap "rm -f -- $(printf '%q' "$next")" EXIT
    if [[ "$action" == --share-create ]]; then
        secure_jq -e '(.duration|type)=="number" and .duration>=60 and .duration<=31622400 and
            (.duration|floor)==.duration and (.label|type)=="string" and (.label|length)<=80 and
            (.id|test("^[0-9a-f]{32}$"))' "$request" >/dev/null || return 1
        id=$(secure_jq -r '.id' "$request") || return 1
        # Request IDs make a recovered request idempotent; tokens are never recycled.
        if secure_jq -e --arg id "$id" 'any(.[]; .id==$id)' "$SECURE_STATE/shares.json" >/dev/null; then return 0; fi
        secure_jq -e --arg id "$id" 'all(.[]; .id!=$id)' "$SECURE_STATE/share-retired.json" >/dev/null || return 1
        secure_jq -e 'length<128' "$SECURE_STATE/shares.json" >/dev/null || return 1
        for attempt in {1..16}; do
            token=$(openssl rand -base64 6) || return 1
            token=$(printf '%s' "$token" | tr '+/' '-_' | tr -d '\r\n') || return 1
            [[ "$token" =~ ^[A-Za-z0-9_-]{8}$ ]] || return 1
            secure_share_token_available "$token" && break
        done
        secure_share_token_available "$token" || return 1
        vless_uuid=$(secure_share_uuid) || return 1
        tuic_uuid=$(secure_share_uuid) || return 1
        tuic_password=$(openssl rand -hex 32) || return 1
        hy2_password=$(openssl rand -hex 32) || return 1
        [[ "$tuic_password" =~ ^[0-9a-f]{64}$ && "$hy2_password" =~ ^[0-9a-f]{64}$ ]] || return 1
        secure_jq --slurpfile request "$request" --arg token "$token" --argjson now "$now" \
          --arg v "$vless_uuid" --arg t "$tuic_uuid" --arg tp "$tuic_password" --arg hp "$hy2_password" \
          '. + [{id:$request[0].id,token:$token,label:$request[0].label,created_at:$now,
            expires_at:($now+$request[0].duration),revoked_at:0,vless_uuid:$v,tuic_uuid:$t,
            tuic_password:$tp,hy2_password:$hp}]' "$SECURE_STATE/shares.json" > "$next" || return 1
    elif [[ "$action" == --share-revoke ]]; then
        id=$(secure_jq -er '.share_id|select(test("^[0-9a-f]{32}$"))' "$request") || return 1
        secure_jq -e --arg id "$id" 'any(.[];.id==$id)' "$SECURE_STATE/shares.json" >/dev/null || return 1
        secure_jq --arg id "$id" --argjson now "$now" 'map(if .id==$id then .revoked_at=$now else . end)' \
          "$SECURE_STATE/shares.json" > "$next" || return 1
    else
        return 1
    fi
    secure_shares_validate "$next" || return 1
    chmod 600 "$next" || return 1
    secure_store "$next" "$SECURE_STATE/shares.json"
)

secure_shares_apply() {
    local config=$1 next
    secure_shares_init || return 1
    next=$(mktemp "$SECURE_STATE/.users.XXXXXX") || return 1
    secure_jq --slurpfile shares "$SECURE_STATE/shares.json" --argjson now "$(date +%s)" '
      [$shares[0][] | select(.revoked_at==0 and .expires_at>$now)] as $active |
      .inbounds |= map(.type as $type | if (["vless","tuic","hysteria2"]|index($type))!=null then
        .users = ([.users[] | select((.name // "" | startswith("salksd-share-"))|not)] +
          [$active[] | {name:("salksd-share-"+.id)} +
            (if $type=="vless" then {uuid:.vless_uuid,flow:"xtls-rprx-vision"}
             elif $type=="tuic" then {uuid:.tuic_uuid,password:.tuic_password}
             else {password:.hy2_password} end)]) else . end)' "$config" > "$next" || return 1
    chmod 600 "$next"
    if secure_encoded "$config"; then
        secure_store "$next" "$config" && rm -f "$next"
    else
        mv "$next" "$config"
    fi
}

secure_share_payloads() (
    set -o pipefail
    local stage=$1 config=$2 id source='' part='' hash token expires stream index
    stream=$(mktemp "$SECURE_STATE/.share-stream.XXXXXX") || return 1
    trap "rm -f -- $(printf '%q' "$stream")" EXIT
    for id in $(secure_jq -r --argjson now "$(date +%s)" '.[]|select(.revoked_at==0 and .expires_at>$now)|.id' "$SECURE_STATE/shares.json" | tr -d '\r'); do
        # Publish only accounts that are actually installed in all three inbounds.
        secure_jq -e --arg user "salksd-share-$id" '[.inbounds[]|select(.type=="vless" or .type=="tuic" or .type=="hysteria2")|
          any(.users[]; .name==$user)]|length==3 and all(.[];.)' "$config" >/dev/null || continue
        source=$(mktemp "$SECURE_STATE/.share-source.XXXXXX") || return 1
        secure_jq --arg user "salksd-share-$id" '.inbounds |= map(.users=[.users[]|select(.name==$user)])' "$config" > "$source" || return 1
        part=$(mktemp -d "$SECURE_STATE/.share-payload.XXXXXX") || return 1
        trap "rm -f -- $(printf '%q' "$stream") $(printf '%q' "$source") $(printf '%q' "$part")/*; rmdir $(printf '%q' "$part") 2>/dev/null || :" EXIT
        secure_render_payload "$part" "$source" || return 1
        token=$(secure_jq -r --arg id "$id" '.[]|select(.id==$id)|.token' "$SECURE_STATE/shares.json")
        expires=$(secure_jq -r --arg id "$id" '.[]|select(.id==$id)|.expires_at' "$SECURE_STATE/shares.json")
        hash=$(printf '%s' "$token" | openssl dgst -sha256 -r | awk '{print $1}')
        secure_jq -cn --arg hash "$hash" --argjson expires "$expires" --rawfile uri "$part/p07" \
          --rawfile singbox "$part/p08" --rawfile mihomo "$part/p09" \
          '{key:$hash,value:{expires_at:$expires,content:{"p07":$uri,"p08":$singbox,"p09":$mihomo}}}|@base64' >> "$stream" || return 1
        rm -f "$source" "$part"/*
        rmdir "$part"
    done
    secure_jq -s 'map(@base64d|fromjson)|from_entries' "$stream" | secure_store_stream "$stage/shares.json" || return 1
    rm -f "$stream"
    secure_jq 'map({id,token,label,created_at,expires_at,revoked_at})' "$SECURE_STATE/shares.json" > "$stage/share-index.json" || return 1
    chmod 600 "$stage/shares.json" "$stage/share-index.json"
)

secure_share_lease() {
    local pid=$1 deadline generation start
    secure_shares_init || return 1
    deadline=$(secure_jq -r --slurpfile config "$CONFIG_FILE" '
      [$config[0].inbounds[]|select(.type=="tuic")|.users[]|.name // ""] as $names |
      [.[]|select(("salksd-share-"+.id) as $n|$names|index($n)!=null)|.expires_at]|min // 0' "$SECURE_STATE/shares.json") || return 1
    generation=$(openssl rand -hex 16) || return 1
    [[ "$generation" =~ ^[0-9a-f]{32}$ ]] || return 1
    start=$(ps -p "$pid" -o lstart=) || return 1
    [[ -n "$start" ]] || return 1
    (umask 077; secure_jq -n --arg generation "$generation" --arg start "$start" --argjson pid "$pid" --argjson deadline "$deadline" \
      '{generation:$generation,start:$start,pid:$pid,deadline:$deadline}' > "$SECURE_STATE/core-lease.new") || return 1
    mv "$SECURE_STATE/core-lease.new" "$SECURE_STATE/core-lease" || return 1
    (( deadline > 0 )) || return 0
    nohup bash "$WORKDIR/unbound_start.sh" --share-watch "$generation" > "$SECURE_STATE/share-watch.log" 2>&1 < /dev/null &
    local watcher=$!
    sleep 1
    kill -0 "$watcher" 2>/dev/null
}

secure_share_watch() {
    local generation=$1 pid start deadline
    [[ "$generation" =~ ^[0-9a-f]{32}$ ]] || return 1
    pid=$(secure_jq -r '.pid' "$SECURE_STATE/core-lease") || return 1
    start=$(secure_jq -r '.start' "$SECURE_STATE/core-lease") || return 1
    deadline=$(secure_jq -r '.deadline' "$SECURE_STATE/core-lease") || return 1
    [[ "$pid" =~ ^[0-9]+$ && "$deadline" =~ ^[0-9]+$ ]] || return 1
    while kill -0 "$pid" 2>/dev/null; do
        [[ "$(secure_jq -r '.generation' "$SECURE_STATE/core-lease" 2>/dev/null)" == "$generation" ]] || return 0
        [[ "$(ps -p "$pid" -o lstart= 2>/dev/null)" == "$start" ]] || return 0
        if (( $(date +%s) >= deadline )); then
            # End established sessions too. The worker reloads without expired users.
            kill "$pid" 2>/dev/null || :
            sleep 1
            [[ "$(ps -p "$pid" -o lstart= 2>/dev/null)" != "$start" ]] || kill -KILL "$pid" 2>/dev/null || :
            return 0
        fi
        sleep 2
    done
}

secure_shares_poll() {
    [[ -f "$SECURE_STATE/server.json" ]] || return 0
    if ! secure_shares_init; then
        # Unknown account state must not keep expired credentials running.
        SALKSD_PANEL_IN_WORKER=1 secure_stop_managed
        return 1
    fi
    local desired installed
    desired=$(secure_jq -c --argjson now "$(date +%s)" '[.[]|select(.revoked_at==0 and .expires_at>$now)|"salksd-share-"+.id]|sort' "$SECURE_STATE/shares.json") || return 1
    installed=$(secure_jq -c '[.inbounds[]|select(.type=="tuic")|.users[]|.name // ""|select(startswith("salksd-share-"))]|sort' "$SECURE_STATE/server.json") || return 1
    [[ "$desired" != "$installed" ]] || return 0
    [[ ! -d "$SECURE_STATE/operation.lock" ]] || return 0
    (umask 077; SALKSD_PANEL_IN_WORKER=1 secure_operation --sync-shares > "$SECURE_STATE/share-sync.log" 2>&1)
}
