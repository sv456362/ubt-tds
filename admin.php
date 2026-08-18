<?php
require __DIR__ . '/config.php';
require __DIR__ . '/includes/functions.php';
session_name(SESSION_NAME);
session_start();

/* --------- хелперы первого запуска (с защитой от повторного объявления) --------- */
if (!function_exists('is_default_auth')) {
    function is_default_auth(): bool { return ADMIN_PASSWORD_HASH === ''; }
}
if (!function_exists('check_admin_password')) {
    function check_admin_password(string $pass): bool {
        if (!is_default_auth()) return password_verify($pass, ADMIN_PASSWORD_HASH);
        return hash_equals('admin', $pass);
    }
}

$SELF = ADMIN_PANEL_FILE;
$actualFile = basename($_SERVER['SCRIPT_NAME']);
$filenameMismatch = ($actualFile !== $SELF);
if ($filenameMismatch) $SELF = $actualFile;

$action = $_GET['action'] ?? $_POST['action'] ?? 'list';
$error = '';
$notice = '';

/* ---------------- AUTH ---------------- */
function is_logged_in(): bool { return !empty($_SESSION['is_admin']); }

if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $ip = get_client_ip();
    if (!login_throttle_check($ip)) {
        $error = 'Слишком много неудачных попыток входа. Повторите через 15 минут.';
        $action = 'login_form';
    } else {
        $login = $_POST['login'] ?? '';
        $pass  = $_POST['password'] ?? '';
        if ($login === ADMIN_LOGIN && check_admin_password($pass)) {
            login_throttle_clear($ip);
            session_regenerate_id(true);
            $_SESSION['is_admin'] = true;
            header('Location: ' . $SELF);
            exit;
        }
        login_throttle_fail($ip);
        $error = 'Неверный логин или пароль';
        $action = 'login_form';
    }
}

if ($action === 'logout') {
    $_SESSION = [];
    session_destroy();
    header('Location: ' . $SELF);
    exit;
}

if (!is_logged_in()) $action = 'login_form';

/* ---------------- ACTIONS (require login) ---------------- */
if (is_logged_in() && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_check()) {
        $error = 'Сессия устарела, попробуйте ещё раз.';
    } else {
        if ($action === 'create_campaign') {
            $name = trim($_POST['name'] ?? '');
            $slug = trim($_POST['slug'] ?? '');
            $slug = $slug !== '' ? preg_replace('/[^a-zA-Z0-9_-]/', '', $slug) : generate_slug();
            $links = load_links();
            if ($slug === '' || isset($links[$slug])) {
                $error = 'Такой идентификатор уже занят, выберите другой.';
            } else {
                $links[$slug] = [
                    'name' => $name !== '' ? $name : $slug,
                    'active' => true,
                    'created' => date('Y-m-d H:i:s'),
                    'targets' => [],
                    'total_clicks' => 0,
                    'redirect_type' => DEFAULT_REDIRECT_TYPE,
                ];
                save_links($links);
                header('Location: ' . $SELF . '?action=edit&slug=' . urlencode($slug));
                exit;
            }
        }
        if ($action === 'delete_campaign') {
            $slug = $_POST['slug'] ?? '';
            $links = load_links();
            unset($links[$slug]);
            save_links($links);
            header('Location: ' . $SELF);
            exit;
        }
        if ($action === 'toggle_campaign') {
            $slug = $_POST['slug'] ?? '';
            $links = load_links();
            if (isset($links[$slug])) {
                $links[$slug]['active'] = empty($links[$slug]['active']);
                save_links($links);
            }
            header('Location: ' . $SELF);
            exit;
        }
        if ($action === 'update_campaign') {
            $slug = $_POST['slug'] ?? '';
            $links = load_links();
            if (isset($links[$slug])) {
                $links[$slug]['name'] = trim($_POST['name'] ?? $links[$slug]['name']);
                $rt = (int)($_POST['redirect_type'] ?? DEFAULT_REDIRECT_TYPE);
                $links[$slug]['redirect_type'] = in_array($rt, [301, 302, 307], true) ? $rt : DEFAULT_REDIRECT_TYPE;
                save_links($links);
            }
            $newSlug = trim($_POST['new_slug'] ?? '');
            $newSlug = preg_replace('/[^a-zA-Z0-9_-]/', '', $newSlug);
            if ($newSlug !== '' && $newSlug !== $slug) {
                if (rename_campaign_slug($slug, $newSlug)) {
                    header('Location: ' . $SELF . '?action=edit&slug=' . urlencode($newSlug));
                    exit;
                } else {
                    $error = 'Не удалось переименовать: такой идентификатор уже занят.';
                    header('Location: ' . $SELF . '?action=edit&slug=' . urlencode($slug));
                    exit;
                }
            }
            header('Location: ' . $SELF . '?action=edit&slug=' . urlencode($slug));
            exit;
        }
        if ($action === 'add_target') {
            $slug = $_POST['slug'] ?? '';
            $url = trim($_POST['url'] ?? '');
            $weight = max(0, (int)($_POST['weight'] ?? 1));
            $links = load_links();
            if (isset($links[$slug]) && $url !== '' && filter_var($url, FILTER_VALIDATE_URL)) {
                $links[$slug]['targets'][] = ['url' => $url, 'weight' => $weight, 'clicks' => 0];
                save_links($links);
            } else {
                $error = 'Некорректная ссылка.';
            }
            header('Location: ' . $SELF . '?action=edit&slug=' . urlencode($slug));
            exit;
        }
        if ($action === 'update_target') {
            $slug = $_POST['slug'] ?? '';
            $idx = (int)($_POST['idx'] ?? -1);
            $url = trim($_POST['url'] ?? '');
            $weight = max(0, (int)($_POST['weight'] ?? 1));
            $links = load_links();
            if (isset($links[$slug]['targets'][$idx]) && filter_var($url, FILTER_VALIDATE_URL)) {
                $links[$slug]['targets'][$idx]['url'] = $url;
                $links[$slug]['targets'][$idx]['weight'] = $weight;
                save_links($links);
            }
            header('Location: ' . $SELF . '?action=edit&slug=' . urlencode($slug));
            exit;
        }
        if ($action === 'delete_target') {
            $slug = $_POST['slug'] ?? '';
            $idx = (int)($_POST['idx'] ?? -1);
            $links = load_links();
            if (isset($links[$slug]['targets'][$idx])) {
                array_splice($links[$slug]['targets'], $idx, 1);
                save_links($links);
            }
            header('Location: ' . $SELF . '?action=edit&slug=' . urlencode($slug));
            exit;
        }
        if ($action === 'delete_make_hash') {
            $f = __DIR__ . '/tools/make_hash.php';
            if (is_file($f)) @unlink($f);
            header('Location: ' . $SELF);
            exit;
        }
        if ($action === 'fix_panel_filename') {
            $configFile = __DIR__ . '/config.php';
            $lines = file($configFile);
            if ($lines !== false) {
                foreach ($lines as &$line) {
                    $t = ltrim($line);
                    if (strpos($t, "define('ADMIN_PANEL_FILE'") === 0) {
                        $line = "define('ADMIN_PANEL_FILE', " . var_export($actualFile, true) . ");\n";
                    }
                }
                unset($line);
                if (file_put_contents($configFile, implode('', $lines), LOCK_EX) !== false) {
                    if (function_exists('opcache_invalidate')) opcache_invalidate($configFile, true);
                }
            }
            header('Location: ' . $SELF);
            exit;
        }
    }
}

/* ---------------- DATA FOR VIEWS ---------------- */
$links = is_logged_in() ? load_links(true) : [];
$todayHosts = is_logged_in() ? today_hosts_by_campaign() : [];
$editSlug = $_GET['slug'] ?? '';
$editCampaign = $links[$editSlug] ?? null;
$day = preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['day'] ?? '') ? $_GET['day'] : date('Y-m-d');
$chartDaily = ($editCampaign) ? get_chart_daily($editSlug, 30) : null;
$dayStats = ($editCampaign) ? analyze_campaign_day($editSlug, $day) : null;
$baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https://' : 'http://')
    . $_SERVER['HTTP_HOST'] . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
$campaignBaseUrl = $baseUrl;
$deviceLabels = ['desktop' => 'Десктоп', 'mobile' => 'Мобильные', 'unknown' => 'Неизвестно'];
?><!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TDS — управление ссылками</title>
<link rel="icon" href="<?= h($baseUrl) ?>/favicon.ico" type="image/x-icon">
<style>
:root{--bg:#0f1115;--panel:#171a21;--border:#262b36;--text:#e6e8eb;--muted:#8b909c;--accent:#4f7cff;--accent2:#3ecf8e;--danger:#e5484d;--ok:#3ecf8e;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
a{color:var(--accent);text-decoration:none;}
.wrap{max-width:1000px;margin:0 auto;padding:24px 16px 60px;}
h1{font-size:26px;margin:0 0 8px;text-align:center;}
h2{font-size:16px;margin:24px 0 10px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em;}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px;margin-bottom:16px;}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
.cols{display:flex;gap:16px;flex-wrap:wrap;}
.cols > .panel{flex:1;min-width:220px;}
input[type=text],input[type=password],input[type=number],input[type=url],select{background:#0f1115;border:1px solid var(--border);color:var(--text);padding:9px 10px;border-radius:7px;font-size:14px;}
input[type=number]{width:80px;}
button,.btn{background:var(--accent);color:#fff;border:none;padding:9px 14px;border-radius:7px;cursor:pointer;font-size:14px;display:inline-block;}
button.secondary{background:#2a2f3a;}
button.danger{background:var(--danger);}
button.small,.btn.small{padding:6px 10px;font-size:12px;}
table{width:100%;border-collapse:collapse;font-size:14px;}
th,td{padding:8px 6px;border-bottom:1px solid var(--border);text-align:left;}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;}
.muted{color:var(--muted);}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:12px;}
.badge.on{background:rgba(62,207,142,.15);color:var(--ok);}
.badge.off{background:rgba(229,72,77,.15);color:var(--danger);}
.error{background:rgba(229,72,77,.12);color:#ff9a9d;padding:10px 14px;border-radius:8px;margin-bottom:16px;}
.notice{background:rgba(62,207,142,.12);color:var(--ok);padding:10px 14px;border-radius:8px;margin-bottom:16px;}
.warn-box{background:rgba(229,72,77,.12);color:#ff9a9d;padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px;}
.link-url{font-family:monospace;font-size:13px;color:var(--muted);word-break:break-all;}
.topbar-sub{text-align:center;margin-bottom:18px;}
.topbar-sub p{margin:0 0 12px;}
form.inline{display:inline;}
.stat-num{font-size:26px;font-weight:700;}
.stat-num.hits{color:var(--accent);}
.stat-num.hosts{color:var(--danger);}
.legend{display:flex;gap:16px;font-size:12px;color:var(--muted);margin-bottom:8px;flex-wrap:wrap;}
.legend span{display:inline-flex;align-items:center;gap:6px;}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block;}
.bar-row{display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:13px;}
.bar-track{flex:1;background:#0f1115;border-radius:4px;height:8px;overflow:hidden;}
.bar-fill{height:100%;background:var(--accent);}
.link-row{display:inline-flex;align-items:center;gap:8px;flex-wrap:wrap;vertical-align:middle;}
.copy-btn{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;font-size:12px;line-height:1.2;color:#cfd6e4;background:#262c3a;border:1px solid #3d4658;border-radius:6px;cursor:pointer;white-space:nowrap;transition:background .15s,border-color .15s,color .15s;}
.copy-btn:hover{background:#313a4e;border-color:#4a5670;}
.copy-btn:active{transform:translateY(1px);}
.copy-btn.copied{color:#7ee2a8;border-color:#2f7d55;background:rgba(46,125,85,.12);}
.scroll-table th{position:sticky;top:0;background:var(--panel);z-index:1;}
</style>
</head>
<body>
<div class="wrap">
<?php if ($action === 'login_form'): ?>
<h1>Вход в панель управления</h1>
<?php if ($error): ?><div class="error"><?= h($error) ?></div><?php endif; ?>
<div class="panel" style="max-width:340px;">
<form method="post" action="<?= h($SELF) ?>?action=login">
<div class="row" style="flex-direction:column;align-items:stretch;">
<input type="text" name="login" value="<?= h(is_default_auth() ? 'admin' : '') ?>" placeholder="Логин" required>
<input type="password" name="password" value="<?= h(is_default_auth() ? 'admin' : '') ?>" placeholder="Пароль" required>
<button type="submit">Войти</button>
</div>
</form>
</div>
<?php else: ?>
<h1>TDS — управление ссылками</h1>
<div class="topbar-sub">
<p>Сделано для ТГ канала <a href="https://t.me/dating_UBT">@Dating_UBT</a></p>
<a class="btn secondary small" href="<?= h($SELF) ?>?action=logout">Выйти</a>
</div>

<?php if (is_default_auth()): ?>
<div class="warn-box" style="font-weight:700;font-size:14px;">
⚠ Вы работаете под стандартным логином и паролем admin:admin —
запустите мастер первой настройки прямо сейчас:
<a href="<?= h($baseUrl) ?>/tools/make_hash.php" target="_blank" rel="noopener" style="text-decoration:underline;color:inherit;">открыть мастер настройки</a>
</div>
<?php elseif (file_exists(__DIR__ . '/tools/make_hash.php')): ?>
<div class="warn-box" style="font-weight:700;">
Мастер настройки <code>tools/make_hash.php</code> всё ещё на сервере —
удалите файл, чтобы никто кроме вас не смог им воспользоваться.
<form method="post" action="<?= h($SELF) ?>?action=delete_make_hash" style="display:inline;margin-left:10px;">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<button type="submit" class="small danger">Удалить tools/make_hash.php</button>
</form>
</div>
<?php endif; ?>

<?php if ($filenameMismatch): ?>
<div class="warn-box" style="font-weight:700;">
🔒 Фича безопасности: панель переименована в <code><?= h($actualFile) ?></code>,
но в config.php остался старый <code><?= h(ADMIN_PANEL_FILE) ?></code>.
<form method="post" action="<?= h($SELF) ?>?action=fix_panel_filename" style="display:inline;margin-left:10px;">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<button type="submit" class="small">Записать <?= h($actualFile) ?> в config.php</button>
</form>
</div>
<?php endif; ?>
<?php if ($error): ?><div class="error"><?= h($error) ?></div><?php endif; ?>
<?php if ($notice): ?><div class="notice"><?= h($notice) ?></div><?php endif; ?>

<?php if ($action === 'edit' && $editCampaign): ?>
<p><a href="<?= h($SELF) ?>">&larr; ко всем кампаниям</a></p>
<div class="panel">
<form method="post" action="<?= h($SELF) ?>?action=update_campaign">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<input type="hidden" name="slug" value="<?= h($editSlug) ?>">
<div class="row">
<label class="muted">Название:</label>
<input type="text" name="name" value="<?= h($editCampaign['name']) ?>">
<label class="muted">Тип редиректа:</label>
<select name="redirect_type">
<?php foreach ([302 => '302 — временный', 301 => '301 — постоянный', 307 => '307 — временный (строгий)'] as $code => $label): ?>
<option value="<?= $code ?>" <?= ((int)($editCampaign['redirect_type'] ?? DEFAULT_REDIRECT_TYPE) === $code) ? 'selected' : '' ?>><?= h($label) ?></option>
<?php endforeach; ?>
</select>
</div>
<div class="row" style="margin-top:10px;">
<label class="muted">Короткая ссылка (slug):</label>
<input type="text" name="new_slug" value="<?= h($editSlug) ?>">
<button type="submit" class="small">Сохранить</button>
</div>
</form>
<p class="muted" style="margin-top:12px;">
Ссылка для трафика:<br>
<span class="link-row">
<span class="link-url"><?= h($campaignBaseUrl) ?>/<?= h($editSlug) ?></span>
<button type="button" class="copy-btn" title="Скопировать в буфер обмена">
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
<span class="copy-label">Копировать</span>
</button>
</span>
<br><span style="font-size:12px;">(короткий формат работает при включённом mod_rewrite; иначе используйте
<span class="link-row">
<span class="link-url"><?= h($campaignBaseUrl) ?>/index.php?c=<?= h($editSlug) ?></span>
<button type="button" class="copy-btn" title="Скопировать в буфер обмена">
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
<span class="copy-label">Копировать</span>
</button>
</span>)</span>
</p>
</div>

<h2>Офферы / цели ротации</h2>
<div class="panel">
<?php if (empty($editCampaign['targets'])): ?>
<p class="muted">Офферов пока нет — добавьте первый ниже.</p>
<?php else: ?>
<div style="display:flex;gap:8px;padding:4px 6px;color:var(--muted);font-size:12px;text-transform:uppercase;">
<div style="flex:1;">URL</div><div style="width:80px;">Вес</div><div style="width:60px;">Клики</div><div style="width:170px;"></div>
</div>
<?php foreach ($editCampaign['targets'] as $i => $t): ?>
<div style="display:flex;gap:8px;align-items:center;padding:8px 6px;border-bottom:1px solid var(--border);flex-wrap:wrap;">
<form method="post" action="<?= h($SELF) ?>?action=update_target" style="display:flex;gap:8px;align-items:center;flex:1;flex-wrap:wrap;">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<input type="hidden" name="slug" value="<?= h($editSlug) ?>">
<input type="hidden" name="idx" value="<?= (int)$i ?>">
<input type="url" name="url" value="<?= h($t['url']) ?>" style="flex:1;min-width:180px;">
<input type="number" name="weight" value="<?= (int)($t['weight'] ?? 1) ?>" min="0" style="width:80px;">
<span class="muted" style="width:60px;"><?= (int)($t['clicks'] ?? 0) ?></span>
<button type="submit" class="small">Сохранить</button>
</form>
<form method="post" action="<?= h($SELF) ?>?action=delete_target" onsubmit="return confirm('Удалить оффер?');">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<input type="hidden" name="slug" value="<?= h($editSlug) ?>">
<input type="hidden" name="idx" value="<?= (int)$i ?>">
<button type="submit" class="small danger">Удалить</button>
</form>
</div>
<?php endforeach; ?>
<?php endif; ?>
<form method="post" action="<?= h($SELF) ?>?action=add_target" style="margin-top:14px;">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<input type="hidden" name="slug" value="<?= h($editSlug) ?>">
<div class="row">
<input type="url" name="url" placeholder="https://пп.ру/offer?sub=1" required style="flex:1;min-width:220px;">
<input type="number" name="weight" placeholder="Вес" value="1" min="0">
<button type="submit">Добавить оффер</button>
</div>
</form>
<p class="muted" style="font-size:12px;margin-top:10px;">
Вес определяет долю трафика: например, у оффера А вес 70, у оффера Б вес 30 — трафик пойдёт примерно 70/30.
</p>
</div>

<h2>Статистика на <?= h(date('d-m-Y', strtotime($day))) ?><?= $day === date('Y-m-d') ? ' (сегодня)' : '' ?></h2>
<div class="panel">
<div class="legend" style="margin-bottom:12px;gap:24px;flex-wrap:wrap;">
<span><span style="color:#4f7cff;font-size:20px;font-weight:700;"><?= (int)$dayStats['hits'] ?></span> Хиты (переходы)</span>
<span><span style="color:#e5484d;font-size:20px;font-weight:700;"><?= (int)$dayStats['hosts'] ?></span> Хосты (уникальные посетители)</span>
<span><span style="color:#f5a623;font-size:20px;font-weight:700;"><?= (int)$dayStats['bots'] ?></span> Боты (подозрительные клики)</span>
</div>
<?= render_dual_line_chart($chartDaily, $SELF . '?action=edit&slug=' . urlencode($editSlug), $day) ?>
<p class="muted" style="font-size:12px;margin-top:8px;">
Цифры под столбиками — дни. Светлые кликабельны (за день есть данные),
синяя жирная — выбранный день; его разбивка и лог показаны ниже.
</p>
</div>

<div class="cols">
<div class="panel">
<h2 style="margin-top:0;">Рефереры</h2>
<?php if (empty($dayStats['referrers'])): ?>
<p class="muted">Нет данных.</p>
<?php else: ?>
<?php $maxRef = max($dayStats['referrers']); ?>
<?php foreach ($dayStats['referrers'] as $ref => $count): ?>
<div class="bar-row">
<div style="width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="<?= h($ref) ?>"><?= h($ref) ?></div>
<div class="bar-track"><div class="bar-fill" style="width:<?= (int)($count / $maxRef * 100) ?>%;"></div></div>
<div style="width:30px;text-align:right;"><?= (int)$count ?></div>
</div>
<?php endforeach; ?>
<?php endif; ?>
</div>
<div class="panel">
<h2 style="margin-top:0;">Языки браузера</h2>
<?php if (empty($dayStats['languages'])): ?>
<p class="muted">Нет данных.</p>
<?php else: ?>
<?php $maxLang = max($dayStats['languages']); ?>
<?php foreach ($dayStats['languages'] as $lang => $count): ?>
<div class="bar-row">
<div style="width:80px;text-transform:uppercase;"><?= h($lang) ?></div>
<div class="bar-track"><div class="bar-fill" style="width:<?= (int)($count / $maxLang * 100) ?>%;background:#3ecf8e;"></div></div>
<div style="width:30px;text-align:right;"><?= (int)$count ?></div>
</div>
<?php endforeach; ?>
<?php endif; ?>
</div>
<div class="panel">
<h2 style="margin-top:0;">Устройства</h2>
<?php $totalDev = max(1, array_sum($dayStats['devices'])); ?>
<?php foreach ($dayStats['devices'] as $dev => $count): if ($count === 0) continue; ?>
<div class="bar-row">
<div style="width:90px;"><?= h($deviceLabels[$dev] ?? $dev) ?></div>
<div class="bar-track"><div class="bar-fill" style="width:<?= (int)($count / $totalDev * 100) ?>%;background:#f5a623;"></div></div>
<div style="width:30px;text-align:right;"><?= (int)$count ?></div>
</div>
<?php endforeach; ?>
</div>
</div>

<h2>Клики за <?= h(date('d-m-Y', strtotime($day))) ?></h2>
<div class="panel">
<?php $rows = array_slice($dayStats['records'], 0, 1000); ?>
<?php if (empty($rows)): ?>
<p class="muted">Пока пусто.</p>
<?php else: ?>
<div class="legend" style="margin-bottom:10px;">
<span><span class="dot" style="background:#4f7cff;"></span> Первый хит дня</span>
<span><span class="dot" style="background:#e5484d;"></span> Повтор в течение дня</span>
<span><span class="dot" style="background:#f5a623;"></span> Бот</span>
</div>
<?php
$repeatHosts = bot_repeat_hosts($rows);
$botSig = 0; $botRepeat = 0;
foreach ($rows as $r) {
    if ((int)($r['bs'] ?? 0) >= 3) $botSig++;
    elseif (!empty($r['nc']) && ($r['h'] ?? '') !== '' && isset($repeatHosts[$r['h']])) $botRepeat++;
}
if ($botSig + $botRepeat > 0): ?>
<p class="muted" style="font-size:12px;margin-bottom:10px;">
Диагностика: ботов за день — <?= $botSig + $botRepeat ?>;
из них явные подписи (bs≥3): <span style="color:#e5484d;font-weight:700;"><?= $botSig ?></span>,
«рецидивисты без куки»: <span style="color:#f5a623;font-weight:700;"><?= $botRepeat ?></span>.
</p>
<?php endif; ?>
<div style="max-height:740px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;">
<table class="scroll-table">
<tr><th>Время</th><th>Оффер</th><th>Устройство</th><th>Язык</th><th>Реферер</th><th>Бот-балл</th></tr>
<?php foreach ($rows as $rec): ?>
<?php
$cls = $rec['cls'] ?? 'new';
$rowBg  = ['new' => 'rgba(79,124,255,.08)', 'ret' => 'rgba(229,72,77,.08)', 'bot' => 'rgba(245,166,35,.10)'][$cls];
$rowDot = ['new' => '#4f7cff', 'ret' => '#e5484d', 'bot' => '#f5a623'][$cls];
$bs = (int)($rec['bs'] ?? 0);
?>
<tr style="background:<?= $rowBg ?>;">
<td><span class="dot" style="background:<?= $rowDot ?>;margin-right:6px;"></span><?= h($rec['t'] ?? '') ?></td>
<td><?= (int)($rec['i'] ?? 0) + 1 ?></td>
<td><?= h($deviceLabels[$rec['d'] ?? 'unknown'] ?? ($rec['d'] ?? '-')) ?></td>
<td><?= h(strtoupper($rec['l'] ?? '-')) ?></td>
<td class="muted" title="<?= h($rec['r'] ?? '') ?>"><?= h(referrer_domain($rec['r'] ?? '')) ?></td>
<td>
<span style="font-weight:700;color:<?= $bs >= 3 ? '#e5484d' : ($bs > 0 ? '#f5a623' : '#3ecf8e') ?>;"><?= $bs ?></span>
<?php if (!empty($rec['nc'])): ?> <span class="muted" style="font-size:11px;" title="Клиент не вернул cookie">нет куки</span><?php endif; ?>
<?php if (!empty($rec['bb'])): ?><div class="muted" style="font-size:10px;"><?= h($rec['bb']) ?></div><?php endif; ?>
</td>
</tr>
<?php endforeach; ?>
</table>
</div>
<?php endif; ?>
</div>

<?php else: ?>
<h2>Новая кампания</h2>
<div class="panel">
<form method="post" action="<?= h($SELF) ?>?action=create_campaign">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<div class="row">
<input type="text" name="name" placeholder="Название (например, Casino RU)">
<input type="text" name="slug" placeholder="Идентификатор (необязательно, сгенерируется сам)">
<button type="submit">Создать</button>
</div>
</form>
</div>
<h2>Кампании</h2>
<?php if (empty($links)): ?>
<p class="muted">Пока нет ни одной кампании.</p>
<?php else: ?>
<div class="panel">
<table>
<tr><th>Название</th><th>Ссылка</th><th>Офферов</th><th>Хосты</th><th>Статус</th><th></th></tr>
<?php foreach ($links as $slug => $c): ?>
<tr>
<td><a href="<?= h($SELF) ?>?action=edit&slug=<?= urlencode($slug) ?>"><?= h($c['name'] ?? $slug) ?></a></td>
<td class="link-url"><?= h($campaignBaseUrl) ?>/<?= h($slug) ?></td>
<td><?= count($c['targets'] ?? []) ?></td>
<td><?= (int)($todayHosts[$slug] ?? 0) ?></td>
<td>
<?php if (!empty($c['active'])): ?>
<span class="badge on">включена</span>
<?php else: ?>
<span class="badge off">выключена</span>
<?php endif; ?>
</td>
<td class="row" style="gap:6px;">
<form class="inline" method="post" action="<?= h($SELF) ?>?action=toggle_campaign">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<input type="hidden" name="slug" value="<?= h($slug) ?>">
<button type="submit" class="small secondary"><?= !empty($c['active']) ? 'Выключить' : 'Включить' ?></button>
</form>
<form class="inline" method="post" action="<?= h($SELF) ?>?action=delete_campaign" onsubmit="return confirm('Удалить кампанию целиком?');">
<input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
<input type="hidden" name="slug" value="<?= h($slug) ?>">
<button type="submit" class="small danger">Удалить</button>
</form>
</td>
</tr>
<?php endforeach; ?>
</table>
</div>
<?php endif; ?>
<?php endif; ?>
<?php endif; ?>
</div>

<script>
(function () {
  function fallbackCopy(text) {
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.top = '-1000px';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      ta.setSelectionRange(0, text.length);
      try {
        var ok = document.execCommand('copy');
        document.body.removeChild(ta);
        ok ? resolve() : reject(new Error('copy failed'));
      } catch (err) {
        document.body.removeChild(ta);
        reject(err);
      }
    });
  }
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).catch(function () { return fallbackCopy(text); });
    }
    return fallbackCopy(text);
  }
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.copy-btn');
    if (!btn) return;
    var row = btn.closest('.link-row');
    var urlEl = row ? row.querySelector('.link-url') : null;
    if (!urlEl) return;
    copyText(urlEl.textContent.trim()).then(function () {
      var label = btn.querySelector('.copy-label');
      if (!label) return;
      if (btn.dataset.timer) clearTimeout(+btn.dataset.timer);
      var original = label.dataset.original || label.textContent;
      label.dataset.original = original;
      label.textContent = 'Скопировано ✓';
      btn.classList.add('copied');
      btn.dataset.timer = setTimeout(function () {
        label.textContent = original;
        btn.classList.remove('copied');
      }, 1600);
    });
  });
})();
</script>
</body>
</html>