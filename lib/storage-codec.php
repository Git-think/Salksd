<?php
// Streaming codec: bounded memory and one PHP process even for large backups.
function decode_stream($input, $output): void {
    $prefix=fread($input,13); rewind($input);
    if ($prefix!=='SALKSD-STORE-') {
        if (stream_copy_to_stream($input,$output)===false) { throw new RuntimeException(); }
        return;
    }
    $header=fgets($input,100);
    if (!preg_match('/^SALKSD-STORE-1:([0-9a-f]{64})\n$/D',$header,$m)) { throw new RuntimeException(); }
    $offset=ftell($input); $alphabet='NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234_-';
    // Verify before emitting any byte; keep the same open inode for both passes.
    for ($pass=0;$pass<2;$pass++) {
        fseek($input,$offset); $hash=hash_init('sha256'); $pending='';
        while (!feof($input)) {
            $part=fread($input,65536); if ($part===false) { throw new RuntimeException(); }
            $pending.=str_replace("\n",'', $part);
            $size=intdiv(strlen($pending),4)*4;
            $block=substr($pending,0,$size); $pending=substr($pending,$size);
            $plain=base64_decode(strtr($block,$alphabet,'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'),true);
            if ($plain===false) { throw new RuntimeException(); }
            if ($pass===0) { hash_update($hash,$plain); }
            elseif ($plain!=='' && fwrite($output,$plain)!==strlen($plain)) { throw new RuntimeException(); }
        }
        if ($pending!=='' || ($pass===0 && !hash_equals($m[1],hash_final($hash)))) { throw new RuntimeException(); }
    }
}
try {
    $mode=$argv[1];
    if ($mode==='read' || $mode==='jqfile') {
        if (is_link($argv[2]) || !is_file($argv[2])) { throw new RuntimeException(); }
        $input=fopen($argv[2],'rb');
        if ($mode==='read') { decode_stream($input,STDOUT); }
        else {
            $memory=fopen('php://memory','w+b'); decode_stream($input,$memory); rewind($memory);
            $text=stream_get_contents($memory); fclose($memory);
            if (preg_match('/clash|singbox|sing-box|nekobox|\.b64/i',$text)) {
                json_decode($text,true,512,JSON_THROW_ON_ERROR);
                $text=preg_replace_callback('/clash|singbox|sing-box|nekobox|\.b64/i',function($match) {
                    $out=''; foreach(str_split($match[0]) as $char) { $out.=sprintf('\\u%04x',ord($char)); } return $out;
                },$text);
            }
            echo $text;
        }
        fclose($input); exit;
    }
    if ($mode!=='stream') { throw new RuntimeException(); }
    $target=$argv[2]; if (is_link($target)) { throw new RuntimeException(); }
    $temp=tempnam(dirname($target),'.store-'); if ($temp===false) { throw new RuntimeException(); }
    try {
        chmod($temp,0600); $output=fopen($temp,'w+b');
        $header='SALKSD-STORE-1:'.str_repeat('0',64)."\n";
        if (fwrite($output,$header)!==strlen($header)) { throw new RuntimeException(); }
        $hash=hash_init('sha256'); $pending='';
        while (!feof(STDIN)) {
            $data=fread(STDIN,49152); if ($data===false) { throw new RuntimeException(); }
            hash_update($hash,$data); $pending.=$data; $size=intdiv(strlen($pending),3)*3;
            $block=substr($pending,0,$size); $pending=substr($pending,$size);
            $encoded=strtr(base64_encode($block),'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234_-');
            $encoded=$encoded==='' ? '' : chunk_split($encoded,4,"\n");
            if ($encoded!=='' && fwrite($output,$encoded)!==strlen($encoded)) { throw new RuntimeException(); }
        }
        if ($pending!=='') {
            $tail=chunk_split(strtr(base64_encode($pending),'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234_-'),4,"\n");
            if (fwrite($output,$tail)!==strlen($tail)) { throw new RuntimeException(); }
        }
        if (fseek($output,15)!==0 || fwrite($output,hash_final($hash))!==64 || !fflush($output)) { throw new RuntimeException(); }
        rewind($output); $sink=fopen(PHP_OS_FAMILY==='Windows'?'NUL':'/dev/null','wb');
        decode_stream($output,$sink); fclose($sink); fclose($output);
        if (!rename($temp,$target)) { throw new RuntimeException(); }
    } finally { if (is_file($temp)) { unlink($temp); } }
} catch (Throwable $e) { fwrite(STDERR,"Stored data could not be read or written.\n"); exit(1); }
