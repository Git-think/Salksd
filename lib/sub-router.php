<?php
declare(strict_types=1);

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
    $value = json_decode((string)@file_get_contents($path), true);
    return is_array($value) ? $value : null;
}
function write_json(string $path, array $value): void {
    $temp = tempnam(dirname($path), '.write-');
    if ($temp === false) { throw new RuntimeException('storage'); }
    try {
        $json = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
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
    if (preg_match('/nekobox|nekoray|sing-box|\bSFM\b|\bSFI\b|\bSFA\b|karing/i', $agent)) { return 'singbox-all.json'; }
    if (preg_match('/clash|mihomo/i', $agent)) { return 'mihomo-all.yaml'; }
    if (preg_match('/v2rayn|v2rayng|shadowrocket|hiddify|streisand|loon/i', $agent)) { return 'v2.log'; }
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
if (!preg_match('~^/(?:manage/)?([a-f0-9]{64}|[A-Za-z0-9_-]{8})$~D', $path, $match)) { cover(); }
if (!in_array(strtolower((string)($_SERVER['HTTPS'] ?? '')), ['on', '1'], true)) { cover(); }
$directory = __DIR__ . '/.salksd-data';
$bundle = read_json($directory . '/bundle.json');
if ($bundle === null) { cover(); }
$token = $match[1];
$format = str_starts_with($path, '/manage/') ? 'manage' : 'auto';
$strong = strlen($token) === 64 && hash_equals($bundle['token_hash'] ?? '', hash('sha256', $token));
$agent = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
$clientFormat = proxy_format($agent);
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
$panel = $strong && ($format === 'manage' || $method === 'POST' || ($browser && field($_GET, 'raw') !== '1'));
if (!$panel) {
    $name = $clientFormat ?? 'v2.log';
    if (!isset($content[$name])) { cover(); }
    header('Content-Type: ' . (str_ends_with($name, '.json') ? 'application/json' : 'text/plain') . '; charset=utf-8');
    if ($method !== 'HEAD') { echo $content[$name]; }
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
session_set_cookie_params(['lifetime'=>0, 'path'=>'/', 'secure'=>true, 'httponly'=>true, 'samesite'=>'Strict']);
if (!session_start()) { stop_request(503); }
if (!is_string($_SESSION['csrf'] ?? null)) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); }
$config = settings($directory);
$access = authorised($config, $strong);
$panelPath = $format === 'manage' ? '/manage/' . $token : '/' . rawurlencode($token);

if ($method === 'POST') {
    if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 8192) { stop_request(413); }
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
        if (!in_array($action, ['change-ports','share-create','share-revoke'], true)) { stop_request(400); }
        $task = ['id'=>bin2hex(random_bytes(16)), 'action'=>$action, 'created_at'=>time()];
        if ($action === 'change-ports') {
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
        } else {
            $id = field($_POST, 'share_id');
            if (!preg_match('/^[0-9a-f]{32}$/D', $id)) { stop_request(400); }
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
if (in_array($state, ['queued', 'running'], true) && time() - (int)($result['updated_at'] ?? 0) > 600) {
    $message = '等待超时，无法确认操作结果。请检查保活状态；系统不会自动重复执行。';
}
$ports = array_intersect_key($bundle['ports'] ?? [], array_flip(['vless', 'tuic', 'hysteria2']));
if (field($_GET, 'view') === 'status') {
    if (!$access) { stop_request(401); }
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['status'=>$state, 'message'=>$message, 'ports'=>$ports,'shares'=>$bundle['share_index'] ?? []], JSON_UNESCAPED_UNICODE);
    exit;
}
$notice = (string)($_SESSION['notice'] ?? '');
unset($_SESSION['notice']);
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
input,select{width:100%;padding:9px;background:#111827;color:#fff;border:1px solid #596579}
button{padding:10px 18px;margin-top:16px;border:0;background:#93c5fd;color:#102239;cursor:pointer}button:disabled{opacity:.5;cursor:wait}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #374151}
.notice{padding:12px;border-left:3px solid #93c5fd;background:#1f2937}small{display:block;margin-top:9px;color:#b7c2d2}
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
<section><h2>限时分享</h2><p>分享使用独立账号。到期或撤销后，已导入的分享节点也会失效。操作会重启核心，现有连接短暂中断。</p>
<form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="share-create">
<label for="share-label">分享名称</label><input id="share-label" name="label" maxlength="80" placeholder="例如：朋友的手机">
<label for="share-minutes">有效期（分钟）</label><input id="share-minutes" name="minutes" type="number" min="1" max="527040" value="1440" required>
<small>1440 分钟为一天，10080 分钟为七天。</small><button>生成分享订阅</button></form>
<div id="shares"></div><small>分享地址只响应支持的代理客户端；其他访问和过期地址显示公开宣传页。已分享过的自用账号不会因此撤销。</small></section>
<script nonce="<?= h($nonce) ?>">
const statusURL = new URL(location.href); statusURL.searchParams.set('view', 'status');
const csrf = <?= json_encode($csrf) ?>;
function renderShares(shares) {
  const box = document.getElementById('shares'); box.replaceChildren();
  for (const share of shares) {
    const item=document.createElement('div'); item.className='notice';
    const expired=share.expires_at * 1000 <= Date.now();
    const label=document.createElement('p'); label.textContent=(share.label || '未命名分享') + ' · ' + (share.revoked_at ? '已撤销' : expired ? '已到期' : '有效');
    const time=document.createElement('small'); time.textContent='到期：'+new Date(share.expires_at*1000).toLocaleString();
    item.append(label,time);
    if (!share.revoked_at && !expired) {
      const input=document.createElement('input');input.readOnly=true;input.value=location.origin+'/'+share.token;input.setAttribute('aria-label','分享订阅地址');item.append(input);
      const form=document.createElement('form');form.method='post';
      for (const [name,value] of Object.entries({csrf,action:'share-revoke',share_id:share.id})) {const field=document.createElement('input');field.type='hidden';field.name=name;field.value=value;form.append(field);}
      const button=document.createElement('button');button.textContent='撤销分享';form.append(button);item.append(form);
    }
    box.append(item);
  }
}
async function refreshStatus() {
  try {
    const response = await fetch(statusURL, {cache:'no-store', headers:{Accept:'text/html'}});
    if (response.status === 401) { location.reload(); return; }
    if (!response.ok) { throw new Error('status'); }
    const data = await response.json();
    document.getElementById('status').textContent = data.message;
    for (const protocol of ['vless','tuic','hysteria2']) {
      document.getElementById('port-' + protocol).textContent = data.ports[protocol] ?? '—';
    }
    for (const button of document.querySelectorAll('.port-action')) {
      button.disabled = ['queued','running'].includes(data.status);
    }
    renderShares(data.shares);
  } catch (_) { document.getElementById('status').textContent = '暂时无法获取状态，请刷新页面查看。'; }
}
setInterval(refreshStatus, 3000);
renderShares(<?= json_encode($bundle['share_index'] ?? [], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>);
</script>
<?php endif ?>
</main></body></html>
