<?php
declare(strict_types=1);
require_once __DIR__ . '/php-runtime.php';

// Embedded in both distributed scripts. This file contains no account secrets.
ini_set('display_errors', '0');
umask(0077);
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('Vary: Accept, User-Agent, Sec-Fetch-Mode');
class PanelError extends RuntimeException {}

function field(array $values, string $key): string {
    return isset($values[$key]) && is_string($values[$key]) ? $values[$key] : '';
}
function read_json(string $path): ?array {
    try { $value = json_decode(stored_decode((string)@file_get_contents($path)), true); }
    catch (Throwable $e) { return null; }
    return is_array($value) ? $value : null;
}
function write_json(string $path, array $value): void {
    $temp = tempnam(dirname($path), '.write-');
    if ($temp === false) { throw new RuntimeException('storage'); }
    try {
        $json = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        if (in_array(basename($path), ['panel.json','bundle.json','request.json','running.json','rules-settings.json'], true) ||
            basename(dirname($path)) === 'panel-backups') { $json = stored_encode($json); }
        if (file_put_contents($temp, $json) !== strlen($json) || !chmod($temp, 0600) || !rename($temp, $path)) {
            throw new RuntimeException('storage');
        }
    } finally {
        if (is_file($temp)) { @unlink($temp); }
    }
}
function stop_request(int $code, string $message = ''): void {
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo $message;
    exit;
}
function cover(): void {
    http_response_code(200);
    header('Content-Type: text/html; charset=utf-8');
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') { readfile(__DIR__ . '/index.html'); }
    exit;
}
function proxy_format(string $agent): ?string {
    // Identification controls presentation only; secrets and revocation enforce access.
    if (preg_match('/nekobox|nekoray|sing-box|\bSFM\b|\bSFI\b|\bSFA\b|karing|hiddify/i', $agent)) { return 'p08'; }
    if (preg_match('/clash|mihomo/i', $agent)) { return 'p09'; }
    if (preg_match('/v2rayn|v2rayng|shadowrocket|streisand|loon|happ|v2box/i', $agent)) { return 'p07'; }
    return null;
}
function h(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function settings(string $directory): array {
    $value = read_json($directory . '/panel.json');
    if ($value === null || !isset($value['password_hash'], $value['revision']) ||
        !is_string($value['password_hash']) || !is_string($value['revision']) ||
        !preg_match('/^[a-f0-9]{64}$/D', $value['revision'])) {
        stop_request(503, '面板设置无法读取；为保留密码保护，已停止访问。');
    }
    return $value;
}
function authorised(array $settings, bool $strong): bool {
    if ($settings['password_hash'] === '' && $strong) { return true; }
    return is_string($_SESSION['auth_revision'] ?? null) &&
        hash_equals($settings['revision'], $_SESSION['auth_revision']) &&
        (int)($_SESSION['auth_until'] ?? 0) > time();
}
function redirect_panel(string $path, string $message): void {
    $_SESSION['notice'] = $message;
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
    header('Location: ' . $path, true, 303);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = (string)parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
if (!preg_match('~^/(?:manage/)?([a-f0-9]{64}|[A-Za-z0-9_-]{8})(?:/([cbsn]))?$~D', $path, $match)) { cover(); }
if (!in_array(strtolower((string)($_SERVER['HTTPS'] ?? '')), ['on', '1'], true)) { cover(); }
$directory = __DIR__ . '/.salksd-data';
$bundle = read_json($directory . '/bundle.json');
if ($bundle === null) { cover(); }
$token = $match[1];
$format = str_starts_with($path, '/manage/') ? 'manage' : 'auto';
$strong = strlen($token) === 64 && hash_equals($bundle['token_hash'] ?? '', hash('sha256', $token));
$agent = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
$clientFormat = proxy_format($agent);
$formats = ['c'=>'p09', 'b'=>'p07', 's'=>'p08', 'n'=>'p08'];
$suffix = $match[2] ?? '';
$requested = field($_GET, 'f');
if (($requested !== '' && !isset($formats[$requested])) || ($suffix !== '' && $requested !== '' && $suffix !== $requested) ||
    ($format === 'manage' && ($suffix !== '' || $requested !== '' || field($_GET, 'a') !== ''))) { cover(); }
$forced = $formats[$suffix !== '' ? $suffix : $requested] ?? null;
$content = $bundle['content'] ?? [];
if (!$strong) {
    $share = $bundle['shares'][hash('sha256', $token)] ?? null;
    if ($format !== 'auto' || $clientFormat === null || !in_array($method, ['GET','HEAD'], true) ||
        !is_array($share) || (int)($share['expires_at'] ?? 0) <= time()) { cover(); }
    $content = $share['content'] ?? [];
    header('Subscription-Userinfo: expire=' . (int)$share['expires_at']);
}
if (!in_array($method, ['GET', 'HEAD', 'POST'], true)) { cover(); }
$browser = stripos((string)($_SERVER['HTTP_ACCEPT'] ?? ''), 'text/html') !== false &&
    stripos($agent, 'Mozilla') !== false &&
    !preg_match('/v2ray|nekobox|nekoray|mihomo|clash|sing-box|shadowrocket|karing|loon|streisand/i', $agent);
$panel = $strong && ($format === 'manage' || $method === 'POST' || ($browser && $forced === null && field($_GET, 'raw') !== '1'));
if (!$panel) {
    $name = $forced ?? $clientFormat ?? 'p07';
    if (!isset($content[$name])) { cover(); }
    $response = $content[$name];
    if ($name === 'p07' && preg_match('/v2rayng|shadowrocket|streisand|loon|happ|v2box/i', $agent)) {
        // These readers must not receive v2rayN's PEM-only internal DTO links.
        // Keep the explicitly labelled legacy nodes; never relabel them as verified.
        $lines=explode("\n", (string)base64_decode($response, true));
        $ng=stripos($agent,'v2rayng')!==false;
        $lines=array_values(array_filter($lines,static fn($line)=>preg_match($ng ? '~^(vless|hysteria2)://~' : '~^(vless|tuic|hysteria2)://~',$line)===1));
        $response=base64_encode(implode("\n",$lines)."\n");
        header('X-Subscription-Compatibility: legacy-uris');
    }
    if (field($_GET, 'a') !== '') {
        if ($name !== 'p09') { stop_request(400, '临时规则模板仅适用于 c 格式。'); }
        try {
            $address=field($_GET,'a');
            if (!preg_match('/^[A-Za-z0-9_-]{1,2732}$/D',$address)) { throw new RuntimeException('a 参数须为模板 HTTPS 地址的 Base64URL 编码。'); }
            $url=base64_decode(strtr($address,'-_','+/'),true);
            if ($url===false) { throw new RuntimeException('模板地址编码无效。'); } acl_url($url);
            $response=json_encode(acl_cached_compile($directory.'/templates',$url,json_decode($response,true,512,JSON_THROW_ON_ERROR)),JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR);
        } catch (Throwable $e) { stop_request(422,'临时模板无法应用；默认模板未改变。'.$e->getMessage()); }
    }
    $rulesStatus=acl_status($bundle['rules'] ?? [],$directory.'/rules-state.json');
    if (($bundle['rules']['mode'] ?? '')==='url' && field($_GET,'a')==='') {
        try {
            $compiled=acl_subscription($bundle['rules'],json_decode($content['p09'],true,512,JSON_THROW_ON_ERROR),$directory,$rulesStatus);
            if ($name==='p09') { $response=json_encode($compiled,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR); }
        } catch (Throwable $e) { stop_request(422,'默认链接模板无法更新；已保存的设置未改变。'.$e->getMessage()); }
    }
    if ($rulesStatus!==null) {
        header('X-Subscription-Rules-Status: '.($rulesStatus['status']==='stale'?'cached-fallback':'ok'));
        header('X-Subscription-Rules-Updated: '.(int)$rulesStatus['updated_at']);
    }
    $response=subscription_notice($response,$name,subscription_notices($rulesStatus));
    header('Content-Type: ' . ($name === 'p08' ? 'application/json' : 'text/plain') . '; charset=utf-8');
    if ($method !== 'HEAD') { echo $response; }
    exit;
}
if ($method === 'HEAD') { header('Content-Type: text/html; charset=utf-8'); exit; }

$nonce = base64_encode(random_bytes(18));
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; script-src 'nonce-$nonce'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.gc_maxlifetime', '1800');
session_name('SALKSDPANEL');
session_save_path($directory . '/sessions');
session_set_save_handler(new StoredSessions(), true);
session_set_cookie_params(['lifetime'=>0, 'path'=>'/', 'secure'=>true, 'httponly'=>true, 'samesite'=>'Strict']);
if (!session_start()) { stop_request(503); }
if (!is_string($_SESSION['csrf'] ?? null)) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); }
$config = settings($directory);
$access = authorised($config, $strong);
$panelPath = $format === 'manage' ? '/manage/' . $token : '/' . rawurlencode($token);

if ($method === 'POST') {
    if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 1048576) { stop_request(413); }
    if (!hash_equals($_SESSION['csrf'], field($_POST, 'csrf'))) { stop_request(403, '页面已过期，请刷新后重试。'); }
    if (strtolower((string)($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '')) === 'cross-site') { stop_request(403); }
    // Serialize settings changes and logins. Never send passwords to a shell.
    $lock = @fopen($directory . '/panel.lock', 'c');
    if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) { stop_request(409, '另一项操作正在提交，请稍后重试。'); }
    try {
        $config = settings($directory);
        $access = authorised($config, $strong);
        $action = field($_POST, 'action');
        if ($action === 'login') {
            $rate = read_json($directory . '/login-rate.json') ?? ['since'=>time(), 'failures'=>0];
            if (time() - (int)$rate['since'] >= 60) { $rate = ['since'=>time(), 'failures'=>0]; }
            if ((int)$rate['failures'] >= 5) { stop_request(429, '尝试次数过多，请一分钟后重试。'); }
            $secret = field($_POST, 'secret');
            $valid = $config['password_hash'] !== ''
                ? (strlen($secret) <= 72 && password_verify($secret, $config['password_hash']))
                : (strlen($secret) === 64 && hash_equals($bundle['token_hash'], hash('sha256', $secret)));
            if (!$valid) {
                $rate['failures']++;
                write_json($directory . '/login-rate.json', $rate);
                stop_request(401, '密码或管理密钥不正确。请返回面板重试。');
            }
            write_json($directory . '/login-rate.json', ['since'=>time(), 'failures'=>0]);
            session_regenerate_id(true);
            $_SESSION['auth_revision'] = $config['revision'];
            $_SESSION['auth_until'] = time() + 1800;
            redirect_panel($panelPath, '已登录管理面板。');
        }
        if (!$access) { stop_request(401, '请先登录管理面板。'); }
        if ($action === 'logout') {
            $_SESSION = [];
            session_regenerate_id(true);
            redirect_panel($panelPath, '已退出。');
        }
        if ($action === 'password') {
            if ($config['password_hash'] !== '' && !password_verify(field($_POST, 'current_password'), $config['password_hash'])) {
                stop_request(401, '当前密码不正确，设置未更改。');
            }
            $mode = field($_POST, 'mode');
            if (!in_array($mode, ['set', 'remove'], true)) { stop_request(400); }
            $password = field($_POST, 'new_password');
            if ($mode === 'set' && (strlen($password) < 8 || strlen($password) > 72 ||
                str_contains($password, "\0") || $password !== field($_POST, 'confirm_password'))) {
                stop_request(400, '新密码须为 8–72 字节，且两次输入相同。');
            }
            $backupDirectory = $directory . '/panel-backups';
            if (!is_dir($backupDirectory) && !mkdir($backupDirectory, 0700)) { throw new RuntimeException('storage'); }
            write_json($backupDirectory . '/' . time() . '-' . bin2hex(random_bytes(6)) . '.json', $config);
            $config = ['password_hash'=>$mode === 'set' ? password_hash($password, PASSWORD_DEFAULT) : '',
                'revision'=>bin2hex(random_bytes(32))];
            write_json($directory . '/panel.json', $config);
            session_regenerate_id(true);
            $_SESSION['auth_revision'] = $config['revision'];
            $_SESSION['auth_until'] = time() + 1800;
            redirect_panel($panelPath, $mode === 'set' ? '管理密码已设置，其他登录已失效。' : '已取消额外密码；请保管好私密管理链接。');
        }
        if (!in_array($action, ['change-ports','share-create','share-revoke','share-delete','share-prune','backup-refresh','backup-prune','rules-save'], true)) { stop_request(400); }
        $task = ['id'=>bin2hex(random_bytes(16)), 'action'=>$action, 'created_at'=>time()];
        if ($action === 'rules-save') {
            $mode=field($_POST,'rules-mode');
            if (!in_array($mode,['default','paste','url'],true)) { stop_request(400); }
            try {
                $ini=$mode==='default' ? acl_default() : ($mode==='url' ? acl_fetch(trim(field($_POST,'rules-url'))) : field($_POST,'rules-ini'));
                acl_compile($ini,json_decode($bundle['content']['p09'],true,512,JSON_THROW_ON_ERROR));
            } catch (Throwable $e) { throw new PanelError($e->getMessage(),422); }
            $task['rules']=['mode'=>$mode==='url'?'url':($mode==='default'?'default':'custom'),'ini'=>$ini];
            if ($mode==='url') { $task['rules']['url']=trim(field($_POST,'rules-url')); }
        } elseif ($action === 'change-ports') {
            $protocol = field($_POST, 'protocol');
            if (!in_array($protocol, ['all', 'vless', 'tuic', 'hysteria2'], true)) { stop_request(400); }
            $task['protocol'] = $protocol;
        } elseif ($action === 'share-create') {
            $minutes = field($_POST, 'minutes');
            $label = trim(field($_POST, 'label'));
            if (!preg_match('/^[0-9]+$/D', $minutes) || (int)$minutes < 1 || (int)$minutes > 527040 ||
                !preg_match('/^.{0,80}$/usD', $label)) {
                stop_request(400, '有效期须为 1–527040 分钟，名称不超过 80 个汉字。');
            }
            $task['duration'] = (int)$minutes * 60;
            $task['label'] = $label;
        } elseif ($action === 'backup-prune') {
            $keep = field($_POST, 'keep');
            $revision = field($_POST, 'revision');
            if (!preg_match('/^[0-9]+$/D', $keep) || (int)$keep < 1 || (int)$keep > 1000 ||
                !preg_match('/^[0-9a-f]{64}$/D', $revision)) {
                stop_request(400, '保留数量须为 1–1000，请先刷新备份清单。');
            }
            $task['keep'] = (int)$keep;
            $task['revision'] = $revision;
        } elseif ($action === 'share-revoke' || $action === 'share-delete') {
            $id = field($_POST, 'share_id');
            if (!preg_match('/^[0-9a-f]{32}$/D', $id)) { stop_request(400); }
            if ($action === 'share-delete') {
                foreach ($bundle['share_index'] ?? [] as $entry) {
                    if (($entry['id'] ?? '') === $id && (int)($entry['revoked_at'] ?? 0) === 0 &&
                        (int)($entry['expires_at'] ?? 0) > time()) {
                        stop_request(409, '有效分享请先撤销，再删除记录。');
                    }
                }
            }
            $task['share_id'] = $id;
        }
        // Shared with the worker's atomic claim. Only a fixed command is queued.
        if (!@mkdir($directory . '/queue.lock', 0700)) { stop_request(409, '请求正在处理，请稍后重试。'); }
        try {
            if (is_file($directory . '/request.json') || is_file($directory . '/running.json')) {
                throw new PanelError('已有操作排队或执行中，请等待结果。', 409);
            }
            $last = read_json($directory . '/result.json');
            if ($action === 'change-ports' && $last !== null && time() - (int)($last['updated_at'] ?? 0) < 60) {
                throw new PanelError('请等待上次操作结束至少一分钟后再更换端口。', 429);
            }
            write_json($directory . '/result.json', ['id'=>$task['id'], 'status'=>'queued', 'action'=>$action, 'updated_at'=>time()]);
            write_json($directory . '/request.json', $task);
        } finally {
            @rmdir($directory . '/queue.lock');
        }
        redirect_panel($panelPath, '已提交操作，页面会自动更新结果。');
    } catch (PanelError $error) {
        stop_request($error->getCode(), $error->getMessage());
    } catch (Throwable $error) {
        stop_request(503, '无法保存操作，请稍后重试。');
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

$result = read_json($directory . '/result.json') ?? ['status'=>'idle', 'updated_at'=>0];
$state = $result['status'] ?? 'idle';
$messages = ['idle'=>'尚未提交操作。', 'queued'=>'已排队，等待保活处理（通常约 5 秒）。',
    'running'=>'正在备份并应用更改，请稍候。', 'success'=>'操作完成，请在客户端更新订阅。',
    'failed'=>'操作失败。请检查服务状态和私有备份中的记录，再决定是否重试。',
    'expired'=>'请求已过期，未执行。', 'rejected'=>'请求格式无效，未执行。'];
$message = $messages[$state] ?? '状态未知，请检查服务。';
if ($state === 'success' && in_array($result['action'] ?? '', ['share-delete','share-prune'], true)) {
    $message = '已清理失效分享记录。';
}
if ($state === 'success' && ($result['action'] ?? '') === 'backup-prune') { $message = '旧备份清理完成。'; }
if ($state === 'success' && ($result['action'] ?? '') === 'backup-refresh') { $message = '备份清单已更新。'; }
if ($state === 'success' && ($result['action'] ?? '') === 'rules-save') { $message = '规则模板已保存，请更新 c 格式订阅。'; }
if (in_array($state, ['queued', 'running'], true) && time() - (int)($result['updated_at'] ?? 0) > 600) {
    $message = '等待超时，无法确认操作结果。请检查保活状态；系统不会自动重复执行。';
}
$ports = array_intersect_key($bundle['ports'] ?? [], array_flip(['vless', 'tuic', 'hysteria2']));
$rules = $bundle['rules'] ?? ['mode'=>'default'];
$rulesRevision = hash('sha256',json_encode($rules));
$rulesStatus = acl_status($rules,$directory.'/rules-state.json');
if (field($_GET, 'view') === 'status') {
    if (!$access) { stop_request(401); }
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['status'=>$state, 'message'=>$message, 'ports'=>$ports,'shares'=>$bundle['share_index'] ?? [],
        'backups'=>read_json($directory . '/backups.json'),'rules_revision'=>$rulesRevision,'rules_status'=>$rulesStatus,
        'notices'=>subscription_notices($rulesStatus)], JSON_UNESCAPED_UNICODE);
    exit;
}
$notice = (string)($_SESSION['notice'] ?? '');
unset($_SESSION['notice']);
$rulesMode = ($rules['mode'] ?? 'default')==='custom' ? 'paste' : ($rules['mode'] ?? 'default');
$subscriptionBase = 'https://' . (string)($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME']) . '/' . $token;
$csrf = $_SESSION['csrf'];
session_write_close();
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>节点管理</title>
<style nonce="<?= h($nonce) ?>">
:root{color-scheme:light dark;font:16px/1.6 system-ui,sans-serif}body{margin:0;background:#111827;color:#e5e7eb}
main{max-width:680px;margin:44px auto;padding:0 20px 40px}h1{font-size:28px;margin-bottom:6px}h2{font-size:20px}
section{background:#1f2937;border:1px solid #374151;border-radius:12px;padding:22px;margin:20px 0}
p{margin:10px 0}.muted{color:#b7c2d2}label{display:block;margin:14px 0 6px}input,select,button{font:inherit;border-radius:7px;box-sizing:border-box}
input,select,textarea{width:100%;padding:9px;background:#111827;color:#fff;border:1px solid #596579}textarea{min-height:180px;box-sizing:border-box;resize:vertical}
button{padding:10px 18px;margin-top:16px;border:0;background:#93c5fd;color:#102239;cursor:pointer}button:disabled{opacity:.5;cursor:wait}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #374151}
.notice{padding:12px;border-left:3px solid #93c5fd;background:#1f2937}small{display:block;margin-top:9px;color:#b7c2d2}
.warning{border-left-color:#fbbf24;color:#fde68a}
.backup-list{max-height:280px;overflow:auto} .backup-list td{font-size:14px}
</style>
</head>
<body><main><h1>节点管理</h1><p class="muted">更换端口后，订阅地址保持不变。</p>
<?php if ($notice !== ''): ?><p class="notice"><?= h($notice) ?></p><?php endif ?>
<?php if (!$access): ?>
<section><h2>登录管理面板</h2>
<p>请输入管理密码。客户端订阅更新不需要这个密码。</p>
<form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="login">
<label for="secret"><?= $config['password_hash'] !== '' ? '管理密码' : '管理密钥' ?></label>
<input id="secret" name="secret" type="password" autocomplete="current-password" required maxlength="72"><button>登录</button></form></section>
<?php else: ?>
<section><h2>当前端口</h2><table><thead><tr><th>协议</th><th>端口</th><th>操作</th></tr></thead><tbody>
<?php foreach (['vless'=>'VLESS / TCP', 'tuic'=>'TUIC / UDP', 'hysteria2'=>'HY2 / UDP'] as $protocol=>$label): ?>
<tr><td><?= h($label) ?></td><td id="port-<?= h($protocol) ?>"><?= h((string)($ports[$protocol] ?? '—')) ?></td><td>
<form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="change-ports"><input type="hidden" name="protocol" value="<?= h($protocol) ?>">
<button class="port-action" aria-label="更换 <?= h($protocol === 'hysteria2' ? 'HY2' : strtoupper($protocol)) ?> 端口" <?= in_array($state, ['queued','running'], true) ? 'disabled' : '' ?>>更换</button></form></td></tr>
<?php endforeach ?></tbody></table><p id="status" role="status"><?= h($message) ?></p>
<form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="change-ports">
<input type="hidden" name="protocol" value="all"><button class="port-action" id="change-ports" <?= in_array($state, ['queued','running'], true) ? 'disabled' : '' ?>>更换全部端口</button></form>
<small>单独更换只改变选中端口，其余端口保持不变。操作前自动备份，重启时连接会短暂中断。完成后请更新客户端订阅。</small></section>
<section><h2>管理密码</h2><p><?= $config['password_hash'] === '' ? '当前未设置额外密码。持有完整私密管理链接的人可以更换端口和设置密码。' : '已开启密码保护。修改或取消密码需要验证当前密码。' ?></p>
<form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="password">
<?php if ($config['password_hash'] !== ''): ?><label for="current_password">当前密码</label><input id="current_password" name="current_password" type="password" autocomplete="current-password" required maxlength="72"><?php endif ?>
<label for="mode">保护方式</label><select id="mode" name="mode"><option value="set">设置 / 更换密码</option><option value="remove">不设额外密码</option></select>
<label for="new_password">新密码（8–72 字节）</label><input id="new_password" name="new_password" type="password" autocomplete="new-password" maxlength="72">
<label for="confirm_password">再次输入新密码</label><input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" maxlength="72"><button>保存密码设置</button></form>
<?php if ($config['password_hash'] !== '' || !$strong): ?><form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="logout"><button>退出登录</button></form><?php endif ?>
</section>
<section><h2>限时分享</h2><p>分享使用独立账号。到期或撤销后，已导入的分享节点也会失效。创建和撤销会重启核心，现有连接短暂中断；删除失效记录仅清理历史记录。</p>
<form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="share-create">
<label for="share-label">分享名称</label><input id="share-label" name="label" maxlength="80" placeholder="例如：朋友的手机">
<label for="share-minutes">有效期（分钟）</label><input id="share-minutes" name="minutes" type="number" min="1" max="527040" value="1440" required>
<small>1440 分钟为一天，10080 分钟为七天。</small><button class="share-action" <?= in_array($state, ['queued','running'], true) ? 'disabled' : '' ?>>生成分享订阅</button></form>
<p id="share-count" class="muted"></p>
<form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="share-prune">
<button id="prune-shares">清理全部已失效记录</button></form>
<small>最多保留 128 条记录，删除已过期或已撤销记录可释放名额；旧分享地址保持失效。</small>
<div id="shares"></div><small>分享地址只响应支持的代理客户端；其他访问和过期地址显示公开宣传页。已分享过的自用账号不会因此撤销。</small></section>
<section><h2>订阅格式与分流</h2>
<p>直接复制完整地址到客户端。自动识别地址按客户端选择格式，其余地址固定格式。以下均为自用订阅。</p>
<?php foreach ([''=>'自动识别客户端','c'=>'Clash / Mihomo','b'=>'Base64 / v2rayN','s'=>'sing-box JSON','n'=>'NekoBox JSON'] as $letter=>$label): $linkId='subscription-'.($letter ?: 'auto'); ?>
<label for="<?= h($linkId) ?>"><?= h($label) ?></label><input id="<?= h($linkId) ?>" readonly value="<?= h($subscriptionBase.($letter!==''?'/'.$letter:'')) ?>">
<button type="button" data-copy="<?= h($linkId) ?>">复制链接</button>
<?php endforeach ?>
<p>内置 ACL4SSR 官方公开规则集，可在本机合并自定义 INI。规则修改不重启核心，不改变节点证书验证。自定义模板仅影响 c 格式。</p>
<p id="rules-status" class="notice<?= ($rulesStatus['status'] ?? '')==='stale'?' warning':'' ?>" role="status" <?= $rulesStatus===null?'hidden':'' ?>><?= h(($rulesStatus['status'] ?? '')==='stale'?'默认模板更新失败，正在使用持久缓存。':'默认模板链接正常。') ?></p>
<form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="rules-save">
<label for="rules-mode">默认模板</label><select id="rules-mode" name="rules-mode">
<?php foreach (['default'=>'内置 ACL4SSR 预设','url'=>'使用 HTTPS 链接作为默认模板','paste'=>'粘贴自定义 INI'] as $mode=>$label): ?>
<option value="<?= h($mode) ?>" <?= $rulesMode===$mode ? 'selected' : '' ?>><?= h($label) ?></option>
<?php endforeach ?></select>
<div id="rules-url-fields"><label for="rules-url">默认模板 HTTPS 链接</label><input id="rules-url" name="rules-url" type="url" maxlength="2048" value="<?= h($rulesMode==='url' ? ($rules['url'] ?? '') : '') ?>" placeholder="https://…/template.ini">
<small>自用和分享订阅均生效。有人拉取订阅且缓存超过一小时时才更新；无人拉取不下载。失败后继续使用持久缓存，五分钟后允许下次请求重试。订阅同时增加 [NOTICE] 英文和 [提醒] 中文两个提醒节点，恢复后下次更新订阅自动消失；该节点仅作提醒。</small></div>
<div id="rules-ini-fields"><label for="rules-ini">自定义 INI 内容</label><textarea id="rules-ini" name="rules-ini" maxlength="262144" spellcheck="false"><?= h($rulesMode==='paste' ? ($rules['ini'] ?? '') : '') ?></textarea></div>
<button class="rules-action" <?= in_array($state, ['queued','running'], true) ? 'disabled' : '' ?>>保存默认模板</button></form>
<label for="rules-override-url">临时模板 HTTPS 链接（不保存为默认）</label><input id="rules-override-url" type="url" maxlength="2048" placeholder="https://…/template.ini">
<label for="rules-link">使用临时模板的完整订阅地址</label><input id="rules-link" readonly placeholder="填写上方临时模板链接后自动生成"><button type="button" data-copy="rules-link">复制链接</button>
<small>也可在订阅 URL 添加 ?f=c&amp;a=模板 HTTPS 地址的 Base64URL 编码，仅替换本次响应的模板，不改变以上默认设置。临时模板下载失败会报错。支持 ruleset、custom_proxy_group 及基本生成开关；不执行脚本或导入任意文件。</small>
</section>
<section><h2>备份清理</h2><p>仅管理本服务的自动操作备份。默认保留全部历史，清理后删除的备份无法恢复。</p>
<form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="backup-refresh">
<button class="backup-action" <?= in_array($state, ['queued','running'], true) ? 'disabled' : '' ?>>刷新备份清单</button></form>
<p id="backup-summary" class="muted"></p>
<form method="post" id="backup-prune-form"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="backup-prune">
<input type="hidden" id="backup-revision" name="revision">
<label for="backup-keep">保留最近几份自动备份</label><input id="backup-keep" name="keep" type="number" min="1" max="1000" value="3" required>
<small>至少保留一份；最近完整恢复点和当前恢复指针额外保护。手动迁移备份、首页备份及密码设置备份由你另行管理。</small>
<div class="backup-list"><table><thead><tr><th>时间（服务器）</th><th>占用</th><th>处理</th></tr></thead><tbody id="backup-rows"></tbody></table></div>
<p id="backup-plan" role="status"></p><button id="backup-prune" disabled>确认清理旧备份</button></form>
<small>清理仅删除预览中列出的旧备份，不重启服务。备份清单变化时会拒绝操作，刷新后重新确认。</small></section>
<script nonce="<?= h($nonce) ?>">
const statusURL = new URL(location.href); statusURL.searchParams.set('view', 'status');
const csrf = <?= json_encode($csrf) ?>;
const rulesRevision = <?= json_encode($rulesRevision) ?>;
let rulesDirty=false;
for (const id of ['rules-mode','rules-url','rules-ini','rules-override-url']) {
  document.getElementById(id).addEventListener('input',()=>rulesDirty=true);
}
for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const input=document.getElementById(button.dataset.copy); input.focus(); input.select();
    try { await navigator.clipboard.writeText(input.value); button.textContent='已复制'; }
    catch (_) { button.textContent='已选中，请复制'; }
    setTimeout(()=>button.textContent='复制链接',2000);
  });
}
function updateRulesFields() {
  const mode=document.getElementById('rules-mode').value;
  document.getElementById('rules-url-fields').hidden=mode!=='url';
  document.getElementById('rules-ini-fields').hidden=mode!=='paste';
  document.getElementById('rules-url').disabled=mode!=='url';
  document.getElementById('rules-url').required=mode==='url';
  document.getElementById('rules-ini').disabled=mode!=='paste';
  document.getElementById('rules-ini').required=mode==='paste';
}
document.getElementById('rules-mode').addEventListener('change',updateRulesFields);
updateRulesFields();
document.getElementById('rules-override-url').addEventListener('input', event => {
  const output=document.getElementById('rules-link'); output.value='';
  try {
    const value=event.target.value.trim(), url=new URL(value);
    if(url.protocol!=='https:' || url.username || url.password) return;
    const encoded=btoa(String.fromCharCode(...new TextEncoder().encode(value))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
    output.value=location.origin+<?= json_encode('/'.$token.'/c?a=') ?>+encoded;
  } catch (_) {}
});
let backupCatalog=null, backupBusy=false;
function renderRulesStatus(status) {
  const box=document.getElementById('rules-status');box.hidden=!status;
  if(!status) return;
  const date=value=>value?new Date(value*1000).toLocaleString():'未知';
  const stale=status.status==='stale';box.classList.toggle('warning',stale);
  box.textContent=stale ? '默认模板更新失败，正在使用持久缓存。失败时间：'+date(status.failed_at)+'；有效模板时间：'+date(status.updated_at)+'。'+status.error :
    '默认模板链接正常。有效模板时间：'+date(status.updated_at)+'。仅在订阅请求时按需更新。';
}
function sizeText(kib) { return kib<1024 ? kib+' KiB' : (kib/1024).toFixed(1)+' MiB'; }
function renderBackups(catalog, busy) {
  backupCatalog=catalog;backupBusy=busy;
  const rows=document.getElementById('backup-rows');rows.replaceChildren();
  const summary=document.getElementById('backup-summary'), plan=document.getElementById('backup-plan'), button=document.getElementById('backup-prune');
  const keep=Number(document.getElementById('backup-keep').value);
  document.getElementById('backup-revision').value=catalog?.revision || '';
  if (!catalog || !Array.isArray(catalog.items)) {summary.textContent='请先刷新备份清单。';plan.textContent='';button.disabled=true;return;}
  const valid=Number.isInteger(keep) && keep>=1 && keep<=1000;
  let count=0,kib=0;
  summary.textContent=catalog.items.length+' 份自动备份，共占用 '+sizeText(catalog.total_kib)+ '。';
  catalog.items.forEach((item,index)=>{
    const remove=valid && catalog.can_prune && index>=keep && !item.protected;
    if(remove){count++;kib+=item.kib;}
    const id=item.id, time=id.slice(0,4)+'-'+id.slice(4,6)+'-'+id.slice(6,8)+' '+id.slice(9,11)+':'+id.slice(11,13)+':'+id.slice(13,15);
    const row=document.createElement('tr');
    for(const value of [time,sizeText(item.kib),remove?'将删除':item.reason || '保留']){const cell=document.createElement('td');cell.textContent=value;row.append(cell);}
    rows.append(row);
  });
  plan.textContent=!catalog.can_prune ? '未找到完整恢复点，暂不能清理。' : !valid ? '请输入 1–1000 的保留数量。' : '将删除 '+count+' 份旧备份，预计释放 '+sizeText(kib)+'。';
  button.textContent='确认清理 '+count+' 份旧备份';button.disabled=busy || !valid || !catalog.can_prune || count===0;
}
document.getElementById('backup-keep').addEventListener('input',()=>renderBackups(backupCatalog,backupBusy));
function renderShares(shares, busy) {
  const box = document.getElementById('shares'); box.replaceChildren();
  const inactive=shares.filter(s=>s.revoked_at || s.expires_at*1000<=Date.now()).length;
  document.getElementById('share-count').textContent='已保留 '+shares.length+' / 128 条记录，其中 '+inactive+' 条已失效。';
  document.getElementById('prune-shares').disabled=busy || inactive===0;
  for (const share of shares) {
    const item=document.createElement('div'); item.className='notice';
    const expired=share.expires_at * 1000 <= Date.now();
    const label=document.createElement('p'); label.textContent=(share.label || '未命名分享') + ' · ' + (share.revoked_at ? '已撤销' : expired ? '已到期' : '有效');
    const time=document.createElement('small'); time.textContent='到期：'+new Date(share.expires_at*1000).toLocaleString();
    item.append(label,time);
    if (!share.revoked_at && !expired) {
      const input=document.createElement('input');input.readOnly=true;input.value=location.origin+'/'+share.token;input.setAttribute('aria-label','分享订阅地址');item.append(input);
    }
    const form=document.createElement('form');form.method='post';
    const action=share.revoked_at || expired ? 'share-delete' : 'share-revoke';
    for (const [name,value] of Object.entries({csrf,action,share_id:share.id})) {const field=document.createElement('input');field.type='hidden';field.name=name;field.value=value;form.append(field);}
    const button=document.createElement('button');button.className='share-action';button.disabled=busy;
    button.textContent=action==='share-delete' ? '删除记录' : '撤销分享';form.append(button);item.append(form);
    box.append(item);
  }
}
async function refreshStatus() {
  try {
    const response = await fetch(statusURL, {cache:'no-store', headers:{Accept:'text/html'}});
    if (response.status === 401) { location.reload(); return; }
    if (!response.ok) { throw new Error('status'); }
    const data = await response.json();
    if (!rulesDirty && data.rules_revision!==rulesRevision) { location.reload(); return; }
    document.getElementById('status').textContent = data.message;
    renderRulesStatus(data.rules_status);
    for (const protocol of ['vless','tuic','hysteria2']) {
      document.getElementById('port-' + protocol).textContent = data.ports[protocol] ?? '—';
    }
    for (const button of document.querySelectorAll('.port-action, .share-action, .backup-action, .rules-action')) {
      button.disabled = ['queued','running'].includes(data.status);
    }
    renderShares(data.shares, ['queued','running'].includes(data.status));
    renderBackups(data.backups, ['queued','running'].includes(data.status));
  } catch (_) { document.getElementById('status').textContent = '暂时无法获取状态，请刷新页面查看。'; }
}
setInterval(refreshStatus, 3000);
renderRulesStatus(<?= json_encode($rulesStatus,JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>);
renderShares(<?= json_encode($bundle['share_index'] ?? [], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>, <?= in_array($state, ['queued','running'], true) ? 'true' : 'false' ?>);
renderBackups(<?= json_encode(read_json($directory . '/backups.json'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>, <?= in_array($state, ['queued','running'], true) ? 'true' : 'false' ?>);
</script>
<?php endif ?>
</main></body></html>
