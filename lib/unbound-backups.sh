#!/bin/bash
# Embedded in both published scripts; the PHP panel receives metadata only.
secure_backup_name() {
    [[ "$1" =~ ^[0-9]{8}-[0-9]{6}-[0-9]+-[0-9a-f]{6}$ ]]
}

secure_backup_usable() {
    local path=$1 name
    for name in site.tgz server.json cert.pem private.key token; do
        [[ -s "$path/$name" && ! -L "$path/$name" ]] || return 1
    done
    [[ "$(secure_read "$path/token")" =~ ^[0-9a-f]{64}$ ]] || return 1
    secure_jq -e '.inbounds|type=="array" and any(.[]; .type=="tuic")' "$path/server.json" >/dev/null 2>&1 || return 1
    secure_cert_valid "$path/cert.pem" "$path/private.key" "$TLS_SERVER_NAME" || return 1
    secure_read "$path/site.tgz" | tar -tzf - >/dev/null 2>&1
}

secure_backups_catalog() (
    umask 077
    set -o pipefail
    local output=$1 root path id kib stream rows usable='' latest='' revision
    [[ -d "$SECURE_STATE/backups" && ! -L "$SECURE_STATE/backups" ]] || return 1
    root=$(cd "$SECURE_STATE/backups" && pwd -P) || return 1
    stream=$(mktemp "$SECURE_STATE/.backup-list.XXXXXX") || return 1
    rows=$(mktemp "$SECURE_STATE/.backup-rows.XXXXXX") || return 1
    trap 'rm -f "$stream" "$rows"' EXIT
    for path in "$root"/*; do
        [[ -d "$path" && ! -L "$path" ]] || continue
        id=${path##*/}
        secure_backup_name "$id" || continue
        kib=$(du -sk "$path" | awk '{print $1}') || return 1
        [[ "$kib" =~ ^[0-9]+$ ]] || return 1
        secure_jq -cn --arg id "$id" --argjson kib "$kib" '{id:$id,kib:$kib}' >> "$stream" || return 1
    done
    secure_jq -s 'sort_by(.id)|reverse' "$stream" > "$rows" || return 1
    for id in $(secure_jq -r '.[].id' "$rows" | tr -d '\r'); do
        if secure_backup_usable "$root/$id"; then usable=$id; break; fi
    done
    if [[ -f "$SECURE_STATE/last-backup" ]]; then
        latest=$(cat "$SECURE_STATE/last-backup") || return 1
        latest=${latest##*/}
        secure_backup_name "$latest" || return 1
    fi
    secure_jq --arg usable "$usable" --arg latest "$latest" '
      {items:map(. + {protected:(.id==$usable or .id==$latest),
         reason:(if .id==$usable then "最近完整恢复点" elif .id==$latest then "当前恢复指针" else "" end)}),
       total_kib:([.[].kib]|add // 0),can_prune:($usable!="")}' "$rows" > "$stream" || return 1
    revision=$(openssl dgst -sha256 -r "$stream" | awk '{print $1}') || return 1
    [[ "$revision" =~ ^[0-9a-f]{64}$ ]] || return 1
    secure_jq --arg revision "$revision" '. + {revision:$revision}' "$stream" > "$output"
)

secure_backups_refresh() (
    umask 077
    local data="$FILE_PATH/.salksd-data" temp
    [[ -d "$data" && ! -L "$data" ]] || return 1
    temp=$(mktemp "$data/.backups.XXXXXX") || return 1
    trap 'rm -f "$temp"' EXIT
    secure_backups_catalog "$temp" || return 1
    chmod 600 "$temp" || return 1
    mv "$temp" "$data/backups.json"
)

secure_backups_prune() (
    # secure_operation holds operation.lock. Never accept a path from the panel.
    umask 077
    set -o pipefail
    local request=$1 keep revision catalog root id target member
    secure_jq -e '(.keep|type)=="number" and .keep>=1 and .keep<=1000 and (.keep|floor)==.keep and
      (.revision|test("^[0-9a-f]{64}$"))' "$request" >/dev/null || return 1
    keep=$(secure_jq -r '.keep' "$request") || return 1
    revision=$(secure_jq -r '.revision' "$request") || return 1
    catalog=$(mktemp "$SECURE_STATE/.backup-prune.XXXXXX") || return 1
    trap 'rm -f "$catalog"; secure_backups_refresh || :' EXIT
    secure_backups_catalog "$catalog" || return 1
    secure_jq -e --arg revision "$revision" '.can_prune and .revision==$revision' "$catalog" >/dev/null || {
        echo '备份清单已变化或没有完整恢复点，请刷新面板后重试。' >&2
        return 1
    }
    root=$(cd "$SECURE_STATE/backups" && pwd -P) || return 1
    # Preflight every candidate. These snapshots contain files directly in their
    # directory; refuse links/nested directories instead of following unknown trees.
    for id in $(secure_jq -r --argjson keep "$keep" '.items[$keep:][]|select(.protected|not)|.id' "$catalog" | tr -d '\r'); do
        secure_backup_name "$id" || return 1
        target="$root/$id"
        [[ -d "$target" && ! -L "$target" && "$(cd "$target" && pwd -P)" == "$root/$id" ]] || return 1
        for member in "$target"/* "$target"/.[!.]* "$target"/..?*; do
            [[ -e "$member" || -L "$member" ]] || continue
            [[ -f "$member" && ! -L "$member" ]] || return 1
        done
    done
    for id in $(secure_jq -r --argjson keep "$keep" '.items[$keep:][]|select(.protected|not)|.id' "$catalog" | tr -d '\r'); do
        target="$root/$id"
        [[ -d "$target" && ! -L "$target" && "$(cd "$target" && pwd -P)" == "$root/$id" ]] || return 1
        # No recursive delete: current keys, subscriptions and other directories
        # cannot become operands through a supplied URL or a symlink.
        rm -f -- "$target"/* "$target"/.[!.]* "$target"/..?* || return 1
        rmdir "$target" || return 1
    done
    echo '旧备份清理完成，保留的恢复点仍可用。'
)
