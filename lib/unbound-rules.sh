#!/bin/bash
# The emitted PHP has no clear-text routing code on the deployment filesystem.
secure_php_runtime_source() {
    # SALKSD PHP RUNTIME BEGIN
    cat "$(dirname "${BASH_SOURCE[0]}")/php-runtime.php"
    # SALKSD PHP RUNTIME END
}

secure_php_wrapper() {
    # Serv00 disallows ini_set inside eval. Keep ordinary PHP execution, encode
    # literal strings/HTML containing client names, and remove comments instead.
    php -r '
      $source="<?php\n".stream_get_contents(STDIN);
      foreach(token_get_all($source) as $token) {
        if(!is_array($token)) { echo $token; continue; }
        [$kind,$text]=$token;
        if($kind===T_COMMENT || $kind===T_DOC_COMMENT) { continue; }
        if($kind===T_INLINE_HTML) { echo "<?php echo base64_decode(".var_export(chunk_split(base64_encode($text),4,"\n"),true)."); ?>"; continue; }
        if($kind===T_CONSTANT_ENCAPSED_STRING && preg_match("/clash|singbox|sing-box|nekobox|\\.b64/i",$text)) {
          $value=eval("return ".$text.";");
          echo "base64_decode(".var_export(chunk_split(base64_encode($value),4,"\n"),true).")";
        } else { echo $text; }
      }'
}

secure_rules_apply() (
    umask 077
    local input=$1 output=$2 settings=${3:-$SECURE_STATE/rules-settings.json} runner result
    runner=$(mktemp "$SECURE_STATE/.processor.XXXXXX") || return 1
    result=$(mktemp "$SECURE_STATE/.render.XXXXXX") || { rm -f "$runner"; return 1; }
    trap "rm -f -- $(printf '%q' "$runner") $(printf '%q' "$result")" EXIT
    {
        secure_php_runtime_source | sed '1d'
        cat <<'PHP'
try {
    $base=json_decode(stored_decode(file_get_contents($argv[1])),true,512,JSON_THROW_ON_ERROR);
    $settings=is_file($argv[2]) ? json_decode(stored_decode(file_get_contents($argv[2])),true,512,JSON_THROW_ON_ERROR) : ['mode'=>'default'];
    $ini=($settings['mode'] ?? '')==='default' ? acl_default() : ($settings['ini'] ?? '');
    echo stored_encode(json_encode(acl_compile($ini,$base),JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR)."\n");
} catch (Throwable $e) { fwrite(STDERR,"规则模板处理失败，请在面板检查模板。\n"); exit(1); }
PHP
    } | secure_php_wrapper > "$runner" || return 1
    php "$runner" "$input" "$settings" > "$result" || return 1
    secure_jq -e '(.rules|length)>1 and (.proxies|length)>0' "$result" >/dev/null || return 1
    mv "$result" "$output"
)

secure_rules_change() (
    umask 077
    set -o pipefail
    local request=$1 previous next test input
    next=$(mktemp "$SECURE_STATE/.rules-next.XXXXXX") || return 1
    previous=$(mktemp "$SECURE_STATE/.rules-before.XXXXXX") || return 1
    test=$(mktemp "$SECURE_STATE/.rules-test.XXXXXX") || return 1
    trap "rm -f -- $(printf '%q' "$next") $(printf '%q' "$previous") $(printf '%q' "$test")" EXIT
    secure_jq -e '(.rules|type)=="object" and (.rules.mode=="default" or (.rules.mode=="custom" and (.rules.ini|type)=="string" and (.rules.ini|length)<=262144))' "$request" >/dev/null || return 1
    secure_jq '.rules' "$request" | secure_store_stream "$next" || return 1
    input="$SECURE_STATE/$(cat "$SECURE_STATE/current")/p09"
    secure_rules_apply "$input" "$test" "$next" || return 1
    local existed=0
    if [[ -f "$SECURE_STATE/rules-settings.json" ]]; then cp "$SECURE_STATE/rules-settings.json" "$previous" || return 1; existed=1; fi
    secure_store "$next" "$SECURE_STATE/rules-settings.json" || return 1
    if ! secure_publish || ! secure_refresh_legacy; then
        if ((existed)); then mv "$previous" "$SECURE_STATE/rules-settings.json"; else rm -f "$SECURE_STATE/rules-settings.json"; fi
        secure_publish && secure_refresh_legacy || :
        return 1
    fi
)
