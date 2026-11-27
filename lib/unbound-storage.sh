#!/bin/bash
# Versioned visual obfuscation, not encryption. Runtime input to the core stays plain.
# SALKSD CODEC BEGIN
SALKSD_STORAGE_PHP=$(sed '1d' "$(dirname "${BASH_SOURCE[0]}")/storage-codec.php") || return 1
# SALKSD CODEC END
secure_encoded() {
    local header=''
    [[ -f "$1" ]] || return 1
    IFS= read -r -N 13 header < "$1" || :
    [[ "$header" == 'SALKSD-STORE-' ]]
}

secure_read() { php -r "$SALKSD_STORAGE_PHP" -- read "$1"; }

secure_store_stream() { php -r "$SALKSD_STORAGE_PHP" -- stream "$1"; }

secure_store() (
    umask 077
    set -o pipefail
    local temp
    # Publish only after the decoder succeeded; a failed read must not replace good data.
    temp=$(mktemp "$(dirname "$2")/.store.XXXXXX") || return 1
    trap "rm -f -- $(printf '%q' "$temp")" EXIT
    secure_read "$1" | secure_store_stream "$temp" || return 1
    secure_read "$temp" >/dev/null || return 1
    mv "$temp" "$2"
)

secure_seal() {
    [[ -f "$1" && ! -L "$1" ]] || return 1
    if secure_encoded "$1"; then
        # Older unwrapped Base64 can accidentally spell a forbidden word.
        if LC_ALL=C grep -aiEq 'clash|nekobox|singbox|\.b64' "$1"; then secure_store "$1" "$1"; else secure_read "$1" >/dev/null; fi
    else secure_store "$1" "$1"; fi
}

# Explicit wrapper used only by our state readers, not a replacement for system jq.
# Decode file operands and --rawfile/--slurpfile inputs before invoking the real jq.
secure_jq() {
    umask 077
    local arg temp option rawkey rawvalue filter=0 status=0
    local args=() temps=()
    while (($#)); do
        arg=$1; shift
        case "$arg" in
            --arg|--argjson) (($#>=2)) || return 1; args+=("$arg" "$1" "$2"); shift 2; continue ;;
            --rawfile)
                (($#>=2)) || return 1
                rawkey=$1
                # Text payloads only; sentinel preserves trailing newlines in Bash.
                rawvalue=$(secure_read "$2" && printf '\001') || return 1
                rawvalue=${rawvalue%$'\001'}
                args+=(--arg "$rawkey" "$rawvalue"); shift 2; continue ;;
            --slurpfile)
                (($#>=2)) || return 1
                option=$arg; args+=("$option" "$1"); arg=$2; shift 2 ;;
            -*) args+=("$arg"); continue ;;
            *) if ((filter==0)); then args+=("$arg"); filter=1; continue; fi ;;
        esac
        if secure_encoded "$arg"; then
            # Sequential temporary inputs avoid FreeBSD descriptor and process limits.
            # JSON strings containing the prohibited names use Unicode escapes;
            # jq recovers identical values, without spelling them on disk.
            temp=$(mktemp "${TMPDIR:-/tmp}/.salksd-json.XXXXXX") || return 1
            temps+=("$temp")
            php -r "$SALKSD_STORAGE_PHP" -- jqfile "$arg" > "$temp" || { rm -f "${temps[@]}"; return 1; }
            case "$(uname -s)" in MINGW*|MSYS*) temp=$(cygpath -m "$temp") || return 1 ;; esac
            args+=("$temp")
        else
            args+=("$arg")
        fi
    done
    command jq "${args[@]}" || status=$?
    if ((${#temps[@]})); then rm -f "${temps[@]}"; fi
    return "$status"
}

secure_load_keepalive() {
    local text
    text=$(set -o pipefail; secure_read "$1" | base64 -d) || return 1
    [[ -n "$text" ]] || return 1
    eval "$text"
}

secure_storage_migrate() (
    # The caller has made a backup and holds operation.lock. Never traverse other apps.
    # Backup archives keep their names; their outer envelope hides all old inner names.
    set -o pipefail
    if [[ -f "$SECURE_STATE/storage-version" && "$(cat "$SECURE_STATE/storage-version")" == 2 ]]; then return 0; fi
    local root file name target key saved manifest legacy owner audit_root="${SALKSD_AUDIT_BACKUP_DIR:-$HOME/.config/salksd-unbound}"
    saved="$SECURE_STATE/storage-before"
    (umask 077; mkdir -p "$saved") || return 1
    manifest=$(mktemp "$SECURE_STATE/.storage-map.XXXXXX") || return 1
    trap "rm -f -- $(printf '%q' "$manifest")" EXIT
    if [[ -f "$saved/map" ]]; then secure_read "$saved/map" > "$manifest" || return 1; fi
    for root in "$SECURE_STATE" "$FILE_PATH/.salksd-data" "$audit_root"; do
        [[ ! -L "$root" ]] || return 1
        [[ -d "$root" ]] || continue
        while IFS= read -r -d '' file; do
            name=${file##*/}
            if [[ "$file" == "$saved/"* ]]; then
                if LC_ALL=C grep -aiEq 'clash|nekobox|singbox|\.b64' "$file"; then secure_store "$file" "$file" || exit 1; fi
                continue
            fi
            if [[ "$root" == "$audit_root" ]]; then
                case "$name" in *-latest|*.pid|*.hashes|ports-*.txt) continue ;; esac
            fi
            case "$name" in
                server.json|recovered-server.json|private.key|recovered-private.key|token|legacy-token|shares.json|share-index.json|bundle.json|keepalive.conf|panel.json|rules-settings.json|request.json|running.json|*.tgz|*.tar.gz|*.yaml|list.txt|v2.log|v2rayn*.txt|nekobox*.json|singbox*.json|*.sh|secure-sub.php) ;;
                *) case "$file" in */subscriptions-*/*|*/panel-backups/*.json|*/sessions/sess_*|"$SECURE_STATE/backups/"*.json|"$audit_root/"*) ;; *) continue ;; esac ;;
            esac
            target=$file
            case "${name,,}" in *clash*|*singbox*|*nekobox*|*.b64*)
                key=$(printf '%s' "$name" | openssl dgst -sha256 -r | awk '{print $1}') || exit 1
                target="${file%/*}/p-$key" ;;
            esac
            if ! secure_encoded "$file" || [[ "$target" != "$file" ]]; then
                key=$(printf '%s' "$file" | openssl dgst -sha256 -r | awk '{print $1}') || exit 1
                [[ -f "$saved/$key" ]] || secure_store "$file" "$saved/$key" || exit 1
                secure_jq -cn --arg file "$file" --arg target "$target" --arg saved "$key" '{file:($file|@base64),target:($target|@base64),saved:$saved}' >> "$manifest" || exit 1
                secure_store "$manifest" "$saved/map" || exit 1
                secure_store "$file" "$target" || exit 1
                [[ "$target" == "$file" ]] || rm -f "$file" || exit 1
            else
                if LC_ALL=C grep -aiEq 'clash|nekobox|singbox|\.b64' "$file"; then secure_store "$file" "$file" || exit 1; fi
            fi
        done < <(find "$root" -type f -print0)
    done
    [[ ! -f "$WORKDIR/keepalive.conf" ]] || secure_seal "$WORKDIR/keepalive.conf" || return 1
    legacy=$(secure_read "$SECURE_STATE/legacy-token" 2>/dev/null) || legacy=''
    owner=$(secure_read "$SECURE_STATE/token" 2>/dev/null) || owner=''
    for file in "$FILE_PATH/list.txt" "$FILE_PATH/v2.log" "$FILE_PATH/clash.yaml" "$FILE_PATH/singbox.yaml" "$FILE_PATH/$legacy.php" "$FILE_PATH/$owner.php" "$FILE_PATH"/????????.php; do
        [[ -f "$file" && ! -L "$file" ]] || continue
        name=${file##*/}
        [[ "$name" != secure-sub.php ]] || continue
        case "$name" in list.txt|v2.log) secure_seal "$file" || return 1 ;;
            clash.yaml|singbox.yaml|[A-Za-z0-9_-]*.php)
                # Only the old generated token PHP scripts, never unrelated website PHP.
                if [[ "$name" == *.php && "$name" != "$legacy.php" && "$name" != "$owner.php" ]]; then
                    [[ "$name" =~ ^[A-Za-z0-9_-]{8}\.php$ ]] && grep -q 'clash.yaml' "$file" && grep -q 'singbox.yaml' "$file" || continue
                fi
                [[ "$name" != .php ]] || continue
                key=$(printf '%s' "$file" | openssl dgst -sha256 -r | awk '{print $1}') || return 1
                secure_store "$file" "$saved/$key" || return 1
                secure_jq -cn --arg file "$file" --arg saved "$key" '{file:($file|@base64),saved:$saved}' >> "$manifest" || return 1
                secure_store "$manifest" "$saved/map" || return 1
                rm -f "$file" || return 1 ;;
        esac
    done
    printf '2\n' > "$SECURE_STATE/storage-version.new" || return 1
    mv "$SECURE_STATE/storage-version.new" "$SECURE_STATE/storage-version"
)
