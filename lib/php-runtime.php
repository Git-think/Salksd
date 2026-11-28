<?php
// Shared by the web reader and the local template compiler. No optional extensions.
function stored_encode(string $value): string {
    return 'SALKSD-STORE-1:' . hash('sha256', $value) . "\n" . ($value==='' ? '' : chunk_split(strtr(base64_encode($value),
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234_-'), 4, "\n"));
}
function stored_decode(string $value): string {
    if (!str_starts_with($value, 'SALKSD-STORE-')) { return $value; }
    if (!preg_match('/^SALKSD-STORE-1:([0-9a-f]{64})\n([A-Za-z0-9_\-=\n]*)$/D', $value, $m)) {
        throw new RuntimeException('invalid storage');
    }
    $plain = base64_decode(strtr(str_replace("\n", "", $m[2]),
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234_-',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'), true);
    if ($plain === false || !hash_equals($m[1], hash('sha256', $plain))) { throw new RuntimeException('invalid storage'); }
    return $plain;
}
class StoredSessions extends SessionHandler {
    public function read(string $id): string|false {
        $value = parent::read($id);
        if ($value === false) { return false; }
        try { return stored_decode($value); } catch (Throwable $e) { return false; }
    }
    public function write(string $id, string $data): bool { return parent::write($id, stored_encode($data)); }
}

function acl_default(): string {
    // Public ACL4SSR rule lists, merged locally; no subscription is sent to their host.
    $root = 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/';
    $text = "[custom]\nenable_rule_generator=true\noverwrite_original_rules=true\n";
    foreach (['LocalAreaNetwork'=>'DIRECT','UnBan'=>'DIRECT','BanAD'=>'REJECT','BanProgramAD'=>'REJECT',
        'GoogleCN'=>'DIRECT','Ruleset/SteamCN'=>'DIRECT','Telegram'=>'Messaging','ProxyMedia'=>'Media',
        'ProxyLite'=>'PROXY','ChinaDomain'=>'DIRECT','ChinaCompanyIp'=>'DIRECT'] as $list=>$group) {
        $text .= 'ruleset=' . $group . ',' . $root . $list . ".list\n";
    }
    return $text . "ruleset=DIRECT,[]GEOIP,CN\nruleset=Final,[]FINAL\n" .
        "custom_proxy_group=PROXY`select`[]AUTO`.*\n" .
        "custom_proxy_group=AUTO`url-test`^(?!.*\\[SkipVerify\\]).*`https://www.gstatic.com/generate_204`300,,50\n" .
        "custom_proxy_group=Media`select`[]PROXY`[]DIRECT`.*\n" .
        "custom_proxy_group=Messaging`select`[]PROXY`[]DIRECT`.*\n" .
        "custom_proxy_group=Final`select`[]PROXY`[]DIRECT\n";
}

function acl_url(string $url): array {
    $u = parse_url($url);
    if (strlen($url)>2048 || preg_match('/[\x00-\x20\x7f]/', $url) || !is_array($u) ||
        ($u['scheme'] ?? '') !== 'https' || isset($u['user'], $u['pass']) || isset($u['user']) ||
        isset($u['pass']) || isset($u['fragment']) || (int)($u['port'] ?? 443)!==443 ||
        !preg_match('/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/iD', $u['host'] ?? '')) {
        throw new RuntimeException('模板和规则集地址必须为不含账号的公网 HTTPS 地址。');
    }
    return $u;
}

function acl_fetch(string $url): string {
    // Resolve and connect to the same public IP. Every redirect is checked again.
    // Do not pass the subscription URL, token, cookies, referrer or client headers.
    for ($redirect=0; $redirect<4; $redirect++) {
        $u=acl_url($url); $host=$u['host'];
        $ips=gethostbynamel($host);
        if (!$ips) { throw new RuntimeException('模板域名无法解析。'); }
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4|FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE) ||
                str_starts_with($ip, '169.254.') || (ip2long($ip)>=ip2long('100.64.0.0') && ip2long($ip)<=ip2long('100.127.255.255'))) {
                throw new RuntimeException('模板地址不能指向内网或保留地址。');
            }
        }
        $context=stream_context_create(['http'=>['timeout'=>8,'follow_location'=>0,'ignore_errors'=>true,
            'header'=>"Host: $host\r\nUser-Agent: LocalTemplate/1\r\nConnection: close\r\n"],
            'ssl'=>['verify_peer'=>true,'verify_peer_name'=>true,'peer_name'=>$host,'SNI_enabled'=>true]]);
        $stream=@fopen('https://'.$ips[0].($u['path'] ?? '/').(isset($u['query'])?'?'.$u['query']:''), 'rb', false, $context);
        if ($stream===false) { throw new RuntimeException('模板下载失败，原订阅和默认模板未改变。'); }
        $metadata=stream_get_meta_data($stream); $headers=$metadata['wrapper_data'] ?? [];
        $body=stream_get_contents($stream, 262145); fclose($stream);
        if ($body===false || strlen($body)>262144) { throw new RuntimeException('模板为空、超时或超过 256 KiB。'); }
        preg_match('~^HTTP/\S+ (\d{3})~', $headers[0] ?? '', $status);
        $code=(int)($status[1] ?? 0);
        if ($code===200 && $body!=='') { return $body; }
        if (!in_array($code,[301,302,303,307,308],true)) { throw new RuntimeException('模板下载失败。'); }
        $next=''; foreach ($headers as $header) { if (stripos($header,'Location:')===0) { $next=trim(substr($header,9)); } }
        if (str_starts_with($next,'/') && !str_starts_with($next,'//')) { $next='https://'.$host.$next; }
        $url=$next;
    }
    throw new RuntimeException('模板重定向过多。');
}

function acl_saved_ini(array $settings): string {
    $mode=$settings['mode'] ?? 'default';
    if ($mode==='default') { return acl_default(); }
    if (!in_array($mode,['custom','url'],true) || !is_string($settings['ini'] ?? null)) {
        throw new RuntimeException('默认模板设置无效。');
    }
    if ($mode==='url') { acl_url($settings['url'] ?? ''); }
    return $settings['ini'];
}

function acl_cached_compile(string $directory, string $url, array $base): array {
    acl_url($url);
    if (!is_dir($directory) && !mkdir($directory,0700)) { throw new RuntimeException('模板缓存不可用。'); }
    $cache=$directory.'/'.hash('sha256',$url);
    foreach (glob($directory.'/*') ?: [] as $old) {
        if (!is_link($old) && is_file($old) && preg_match('/^[a-f0-9]{64}$/D',basename($old)) && filemtime($old)<time()-3600) { unlink($old); }
    }
    if (!is_file($cache) && count(glob($directory.'/*') ?: [])>=32) { throw new RuntimeException('模板缓存已满，请稍后重试。'); }
    if (is_file($cache) && filemtime($cache)>time()-3600) {
        return acl_compile(stored_decode(file_get_contents($cache)),$base);
    }
    $ini=acl_fetch($url);
    $result=acl_compile($ini,$base);
    $temp=tempnam($directory,'.cache-');
    if ($temp===false) { throw new RuntimeException('模板缓存不可用。'); }
    try {
        $bytes=stored_encode($ini);
        if (file_put_contents($temp,$bytes)!==strlen($bytes) || !rename($temp,$cache)) { throw new RuntimeException('模板缓存不可用。'); }
    } finally { if (is_file($temp)) { unlink($temp); } }
    return $result;
}

function acl_live_state(array $settings, string $path): array {
    $revision=hash('sha256',json_encode($settings));
    $state=['revision'=>$revision,'ini'=>acl_saved_ini($settings),'updated_at'=>(int)($settings['updated_at'] ?? 0),
        'checked_at'=>(int)($settings['updated_at'] ?? 0),'status'=>'ok','failed_at'=>0,'retry_at'=>0,'error'=>''];
    if (is_file($path)) {
        try {
            $saved=json_decode(stored_decode(file_get_contents($path)),true,512,JSON_THROW_ON_ERROR);
            if (is_array($saved) && ($saved['revision'] ?? '')===$revision && is_string($saved['ini'] ?? null) &&
                strlen($saved['ini'])<=262144 && in_array($saved['status'] ?? '',['ok','stale'],true) &&
                is_int($saved['updated_at'] ?? null) && is_int($saved['checked_at'] ?? null) &&
                is_int($saved['failed_at'] ?? null) && is_int($saved['retry_at'] ?? null) && is_string($saved['error'] ?? null)) { $state=$saved; }
        } catch (Throwable $e) { /* The verified save remains available if runtime state is damaged. */ }
    }
    return $state;
}

function acl_status(array $settings, string $path): ?array {
    if (($settings['mode'] ?? '')!=='url') { return null; }
    $state=acl_live_state($settings,$path);
    unset($state['ini'],$state['revision']);
    return $state;
}

function acl_store_state(string $path, array $state): void {
    $temp=tempnam(dirname($path),'.rules-');
    if ($temp===false) { throw new RuntimeException('模板状态无法保存。'); }
    try {
        $bytes=stored_encode(json_encode($state,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR));
        if (file_put_contents($temp,$bytes)!==strlen($bytes) || !chmod($temp,0600) || !rename($temp,$path)) {
            throw new RuntimeException('模板状态无法保存。');
        }
    } finally { if (is_file($temp)) { unlink($temp); } }
}

function acl_subscription(array $settings, array $base, string $directory, ?array &$status=null): array {
    if (($settings['mode'] ?? '')!=='url') { return $base; }
    $path=$directory.'/rules-state.json';
    $state=acl_live_state($settings,$path);
    $result=acl_compile($state['ini'],$base);
    $status=array_diff_key($state,['ini'=>true,'revision'=>true]);
    $now=time();
    if (($state['status']==='ok' && $state['checked_at']>$now-3600) ||
        ($state['status']==='stale' && $state['retry_at']>$now)) { return $result; }
    // Refresh only on subscription requests. Concurrent clients use the current
    // snapshot instead of downloading repeatedly or waiting behind one another.
    $lock=@fopen($directory.'/rules-refresh.lock','c');
    if ($lock===false || !flock($lock,LOCK_EX|LOCK_NB)) {
        if (is_resource($lock)) { fclose($lock); }
        return $result;
    }
    try {
        $state=acl_live_state($settings,$path);
        $result=acl_compile($state['ini'],$base);
        if (($state['status']==='ok' && $state['checked_at']>$now-3600) ||
            ($state['status']==='stale' && $state['retry_at']>$now)) {
            $status=array_diff_key($state,['ini'=>true,'revision'=>true]); return $result;
        }
        try {
            $ini=acl_fetch($settings['url']);
            $fresh=acl_compile($ini,$base);
        } catch (Throwable $e) {
            $state['status']='stale';$state['failed_at']=$now;$state['checked_at']=$now;$state['retry_at']=$now+300;
            $state['error']='链接下载或模板校验失败；继续使用最后一次成功验证的模板。';
            acl_store_state($path,$state);
            $status=array_diff_key($state,['ini'=>true,'revision'=>true]);
            return $result;
        }
        $state=['revision'=>$state['revision'],'ini'=>$ini,'updated_at'=>$now,'checked_at'=>$now,
            'status'=>'ok','failed_at'=>0,'retry_at'=>0,'error'=>''];
        acl_store_state($path,$state);
        $status=array_diff_key($state,['ini'=>true,'revision'=>true]);
        return $fresh;
    } finally { flock($lock,LOCK_UN);fclose($lock); }
}

function subscription_notices(?array $rulesStatus): array {
    // A single presentation path for current and future operator notices.
    $notices=[];
    if (($rulesStatus['status'] ?? '')==='stale') { $notices[]=['en'=>'Rules update failed - using saved rules','zh'=>'规则更新失败，正在使用已保存规则']; }
    return $notices;
}

function subscription_notice(string $response, string $format, array $notices): string {
    if (!$notices) { return $response; }
    $labels=['[NOTICE] '.implode(' | ',array_column($notices,'en')),'[提醒] '.implode('；',array_column($notices,'zh'))];
    $uuid='00000000-0000-4000-8000-000000000000';
    // Reserved .invalid destination and synthetic identity: this is informational,
    // never a route to the operator's service. Append after the normal first node.
    if ($format==='p07') {
        $plain=base64_decode($response,true);
        if ($plain===false) { throw new RuntimeException('订阅内容无效。'); }
        $plain=rtrim($plain,"\r\n")."\n";
        foreach ($labels as $i=>$label) { $host=$i===0?'notice-en.invalid':'notice-zh.invalid'; $plain.='vless://'.$uuid.'@'.$host.':1?encryption=none&security=tls&sni='.$host.'&type=tcp&allowInsecure=0#'.rawurlencode($label)."\n"; }
        return base64_encode($plain);
    }
    $value=json_decode($response,true,512,JSON_THROW_ON_ERROR);
    if ($format==='p08') {
        foreach ($labels as $i=>$label) { $host=$i===0?'notice-en.invalid':'notice-zh.invalid'; $value['outbounds'][]=['type'=>'vless','tag'=>$label,'server'=>$host,'server_port'=>1,'uuid'=>$uuid,
            'tls'=>['enabled'=>true,'server_name'=>$host,'insecure'=>false]]; }
    } elseif ($format==='p09') {
        foreach ($labels as $i=>$label) { $host=$i===0?'notice-en.invalid':'notice-zh.invalid'; $value['proxies'][]=['name'=>$label,'type'=>'vless','server'=>$host,'port'=>1,'uuid'=>$uuid,
            'tls'=>true,'servername'=>$host,'skip-cert-verify'=>false]; }
        // Compile rules before adding this node. It cannot enter any wildcard
        // selector, url-test, fallback, load-balance or existing routing group.
        $group='[NOTICE] Messages';
        $names=array_merge(array_column($value['proxy-groups'] ?? [],'name'),array_column($value['proxies'],'name'));
        while (in_array($group,$names,true)) { $group.='.'; }
        $value['proxy-groups'][]=['name'=>$group,'type'=>'select','proxies'=>$labels];
    }
    return json_encode($value,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR);
}

function acl_compile(string $ini, array $base): array {
    if (strlen($ini)>262144 || str_contains($ini,"\0")) { throw new RuntimeException('模板大小或内容无效。'); }
    $groups=[]; $sets=[]; $section=''; $nodes=array_column($base['proxies'] ?? [],'name');
    foreach (preg_split('/\r?\n/', $ini) as $line) {
        $line=trim($line, "\xEF\xBB\xBF \t\r\n");
        if ($line==='' || $line[0]===';' || $line[0]==='#') { continue; }
        if ($line[0]==='[') { $section=$line; if ($section!=='[custom]') { throw new RuntimeException('仅支持 [custom] 规则模板。'); } continue; }
        if ($section!=='[custom]' || !str_contains($line,'=')) { throw new RuntimeException('模板 INI 格式无效。'); }
        [$key,$value]=array_map('trim',explode('=',$line,2));
        if (in_array($key,['enable_rule_generator','overwrite_original_rules'],true)) {
            if ($value!=='true') { throw new RuntimeException('本地规则生成必须启用。'); } continue;
        }
        if ($key==='ruleset') { $sets[]=$value; continue; }
        if ($key!=='custom_proxy_group') { throw new RuntimeException('模板含未支持的选项：'.$key); }
        $parts=explode('`',$value); $name=array_shift($parts); $type=array_shift($parts);
        if (!$name || str_contains($name,',') || in_array($name,['DIRECT','REJECT','REJECT-DROP','PASS'],true) || isset($groups[$name]) || in_array($name,$nodes,true)) {
            throw new RuntimeException('策略组名称无效或重复。');
        }
        if (!in_array($type,['select','url-test','fallback','load-balance'],true)) { throw new RuntimeException('不支持的策略组类型。'); }
        $group=['name'=>$name,'type'=>$type,'proxies'=>[]];
        if ($type!=='select') {
            $timing=explode(',',(string)array_pop($parts)); $probe=(string)array_pop($parts);
            if (!preg_match('~^https?://[^\s]+$~D',$probe) || !preg_match('/^[1-9][0-9]{0,5}$/D',$timing[0] ?? '') || count($timing)>3) {
                throw new RuntimeException('测速地址或间隔无效。');
            }
            $group['url']=$probe; $group['interval']=(int)$timing[0];
            foreach ([1=>'timeout',2=>'tolerance'] as $i=>$field) {
                if (($timing[$i] ?? '')!=='') {
                    if (!preg_match('/^[0-9]{1,6}$/D',$timing[$i])) { throw new RuntimeException('测速参数无效。'); }
                    if ($field==='timeout') { $group[$field]=(int)$timing[$i]*1000; }
                    elseif ($type==='url-test') { $group[$field]=(int)$timing[$i]; }
                }
            }
        }
        foreach ($parts as $selector) {
            if (str_starts_with($selector,'[]')) { $group['proxies'][]=substr($selector,2); continue; }
            if ($selector==='' || str_starts_with($selector,'!!') || str_starts_with($selector,'script:')) { throw new RuntimeException('不支持导入或脚本节点选择器。'); }
            $regex='~'.str_replace('~','\\~',$selector).'~u';
            if (@preg_match($regex,'')===false) { throw new RuntimeException('节点筛选正则无效。'); }
            foreach ($nodes as $node) { if (preg_match($regex,$node)===1) { $group['proxies'][]=$node; } }
        }
        $group['proxies']=array_values(array_unique($group['proxies']));
        // Empty regional groups are harmless and remain selectable explicitly.
        if (!$group['proxies']) { $group['proxies']=['DIRECT']; }
        $groups[$name]=$group;
        if (count($groups)>128) { throw new RuntimeException('策略组过多。'); }
    }
    if (!$groups || !$sets || count($sets)>512) { throw new RuntimeException('模板必须含策略组和分流规则。'); }
    $known=array_merge($nodes,array_keys($groups),['DIRECT','REJECT','REJECT-DROP','PASS']);
    $done=[];
    $visit=function(string $name,array $path=[]) use (&$visit,&$done,$groups,$known):void {
        if (isset($path[$name])) { throw new RuntimeException('策略组存在循环引用。'); }
        if (isset($done[$name]) || !isset($groups[$name])) { return; } $path[$name]=true;
        foreach ($groups[$name]['proxies'] as $member) {
            if (!in_array($member,$known,true)) { throw new RuntimeException('策略组引用不存在的节点或组。'); }
            $visit($member,$path);
        }
        $done[$name]=true;
    };
    foreach (array_keys($groups) as $name) { $visit($name); }
    $rules=[]; $providers=[]; $final=false;
    foreach ($sets as $set) {
        if ($final || !str_contains($set,',')) { throw new RuntimeException('兜底规则须位于最后，规则格式须有效。'); }
        [$target,$source]=array_map('trim',explode(',',$set,2));
        if (!in_array($target,$known,true)) { throw new RuntimeException('规则引用不存在的策略组。'); }
        if (str_starts_with($source,'[]')) {
            $rule=substr($source,2); $parts=explode(',',$rule); $kind=array_shift($parts);
            if (in_array($kind,['FINAL','MATCH'],true) && !$parts) { $rules[]='MATCH,'.$target; $final=true; continue; }
            if (!in_array($kind,['DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','GEOIP','GEOSITE','IP-CIDR','IP-CIDR6','SRC-IP-CIDR','DST-PORT','SRC-PORT','PROCESS-NAME','PROCESS-PATH','NETWORK'],true) ||
                count($parts)<1 || count($parts)>2 || $parts[0]==='' || (isset($parts[1]) && $parts[1]!=='no-resolve')) {
                throw new RuntimeException('不支持的内联规则。');
            }
            $rules[]=$kind.','.$parts[0].','.$target.(isset($parts[1])?',no-resolve':'');
        } else {
            acl_url($source);
            $id='r'.substr(hash('sha256',$source),0,20);
            $providers[$id]=['type'=>'http','behavior'=>'classical','format'=>'text','url'=>$source,'path'=>'./rules/'.$id.'.txt','interval'=>86400];
            $rules[]='RULE-SET,'.$id.','.$target;
        }
    }
    if (!$final) { throw new RuntimeException('模板缺少最后的 FINAL 或 MATCH 兜底规则。'); }
    // Do not allow a routing template to override credentials or TLS verification.
    $base['proxy-groups']=array_values($groups); $base['rule-providers']=$providers; $base['rules']=$rules;
    $base['mode']='rule';
    return $base;
}
