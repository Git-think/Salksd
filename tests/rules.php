<?php
require __DIR__.'/../lib/php-runtime.php';
function check(bool $value):void { if (!$value) { throw new RuntimeException('test failed'); } }
$base=['mixed-port'=>7890,'dns'=>['enable'=>true,'nameserver'=>['1.1.1.1']],
    'proxies'=>[['name'=>'PL-s16-TUIC','type'=>'tuic','fingerprint'=>str_repeat('a',64),'skip-cert-verify'=>false],
    ['name'=>'PL-s16-TUIC [SkipVerify]','type'=>'tuic','skip-cert-verify'=>true]]];
$out=acl_compile(acl_default(),$base);
check(count($out['rules'])===13 && count($out['rule-providers'])===11 && count($out['proxy-groups'])===5);
check($out['proxies']===$base['proxies'] && $out['dns']===$base['dns']);
check($out['proxy-groups'][1]['proxies']===['PL-s16-TUIC']);
check($out['rules'][12]==='MATCH,Final');
check(count(array_filter($out['rule-providers'],fn($p)=>$p['format']==='text' && $p['behavior']==='classical'))===11);
$custom="[custom]\ncustom_proxy_group=Custom`select`.*\nruleset=DIRECT,[]IP-CIDR,10.0.0.0/8,no-resolve\nruleset=Custom,[]FINAL\n";
$out=acl_compile($custom,$base);
check($out['rules']===['IP-CIDR,10.0.0.0/8,DIRECT,no-resolve','MATCH,Custom'] && $out['proxies']===$base['proxies']);
foreach ([str_replace('[]FINAL','[]NOT-A-RULE',$custom), str_replace('Custom,[]FINAL','Missing,[]FINAL',$custom),
    $custom.'ruleset=DIRECT,[]GEOIP,CN', '[custom]', str_replace('select`.*','select`[]Custom',$custom),
    str_replace('select`.*','select`script:/tmp/a',$custom), $custom."\nunknown_option=true"] as $bad) {
    try { acl_compile($bad,$base); throw new LogicException('bad template accepted'); }
    catch (LogicException $e) { throw $e; } catch (RuntimeException $e) {}
}
foreach (['http://example.com/r','file:///etc/passwd','https://user:pass@example.com/r','https://example.com:444/r',"https://example.com/\r\nx"] as $bad) {
    try { acl_url($bad); throw new LogicException('bad URL accepted'); }
    catch (LogicException $e) { throw $e; } catch (RuntimeException $e) {}
}
try { acl_fetch('https://127.0.0.1/private'); throw new LogicException('private address accepted'); }
catch (LogicException $e) { throw $e; } catch (RuntimeException $e) {}
echo "PASS: local ACL4SSR groups/rules/providers, strict default AUTO, TLS/DNS preserved, custom rules, invalid/cyclic/script templates and private URLs rejected\n";
