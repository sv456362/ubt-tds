<?php
/**
 * tools/make_hash.php — мастер первой настройки.
 * Генерирует логин/пароль/имя панели автоматически, пользователь может
 * отредактировать поля вручную. Доступен ТОЛЬКО залогиненным в админке.
 * ВАЖНО: после использования удалите файл (админка покажет кнопку).
 */
require dirname(__DIR__) . '/config.php';
require dirname(__DIR__) . '/includes/functions.php';
session_name(SESSION_NAME);
session_start();

if (empty($_SESSION['is_admin'])) {
    http_response_code(403);
    exit('Доступ запрещён: сначала войдите в панель управления.');
}

// Генерируем случайные значения один раз за сессию
if (empty($_SESSION['tds_setup'])) {
    $loginChars = 'abcdefghijkmnopqrstuvwxyz23456789';
    $passChars  = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $nameChars  = 'abcdefghijklmnopqrstuvwxyz23456789';

    $login = 'user_';
    for ($i = 0; $i < 6; $i++) $login .= $loginChars[random_int(0, strlen($loginChars) - 1)];

    $pass = '';
    for ($i = 0; $i < 16; $i++) $pass .= $passChars[random_int(0, strlen($passChars) - 1)];

    $panel = '';
    for ($i = 0; $i < 15; $i++) $panel .= $nameChars[random_int(0, strlen($nameChars) - 1)];
    $panel .= '.php';

    $_SESSION['tds_setup'] = [
        'login' => $login,
        'pass'  => $pass,
        'panel' => $panel,
    ];
}

// Базовый URL сайта (поднимаемся на уровень выше /tools)
$scheme  = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host    = $_SERVER['HTTP_HOST'] ?? 'localhost';
$dir     = dirname(dirname($_SERVER['SCRIPT_NAME'] ?? ''));
$baseUrl = $scheme . '://' . $host . (($dir === '/' || $dir === '\\') ? '' : $dir);

$configFile = dirname(__DIR__) . '/config.php';
$error = '';
$showDone = false;
$savedLogin = '';
$savedPass = '';
$savedPanel = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $newLogin = trim($_POST['login'] ?? '');
    $newPass  = $_POST['password'] ?? '';
    $newPanel = trim($_POST['panel_name'] ?? '');

    if ($newLogin === '' || $newPass === '' || $newPanel === '') {
        $error = 'Все поля должны быть заполнены.';
    } elseif (!preg_match('/^[a-zA-Z0-9_.-]{3,32}$/', $newLogin)) {
        $error = 'Логин: 3–32 символа, только латиница, цифры и символы _ . -';
    } elseif (strlen($newPass) < 8) {
        $error = 'Пароль должен быть не короче 8 символов.';
    } elseif (!preg_match('/^[a-zA-Z0-9_.-]{3,40}\.php$/', $newPanel)) {
        $error = 'Имя панели: 3–40 символов + .php, только латиница, цифры и _ . -';
    } else {
        $hash = password_hash($newPass, PASSWORD_DEFAULT);
        $newSecret = bin2hex(random_bytes(32));
        $lines = file($configFile);
        if ($lines === false) {
            $error = 'Не удалось прочитать config.php.';
        } else {
            foreach ($lines as &$line) {
                $t = ltrim($line);
                if (strpos($t, "define('ADMIN_LOGIN'") === 0) {
                    $line = "define('ADMIN_LOGIN', " . var_export($newLogin, true) . ");\n";
                } elseif (strpos($t, "define('ADMIN_PASSWORD_HASH'") === 0) {
                    $line = "define('ADMIN_PASSWORD_HASH', " . var_export($hash, true) . ");\n";
                } elseif (strpos($t, "define('ADMIN_PANEL_FILE'") === 0) {
                    $line = "define('ADMIN_PANEL_FILE', " . var_export($newPanel, true) . ");\n";
                } elseif (strpos($t, "define('APP_SECRET'") === 0) {
                    $line = "define('APP_SECRET', " . var_export($newSecret, true) . ");\n";
                }
            }
            unset($line);

            if (file_put_contents($configFile, implode('', $lines), LOCK_EX) === false) {
                $error = 'Не удалось записать config.php (права на файл?).';
            } else {
                if (function_exists('opcache_invalidate')) opcache_invalidate($configFile, true);

                // Переименовываем файл панели, если имя изменилось
                $oldFile = dirname(__DIR__) . '/' . ADMIN_PANEL_FILE;
                $newFile = dirname(__DIR__) . '/' . $newPanel;
                if ($newPanel !== ADMIN_PANEL_FILE && file_exists($oldFile) && !file_exists($newFile)) {
                    @rename($oldFile, $newFile);
                }

                $savedLogin = $newLogin;
                $savedPass  = $newPass;
                $savedPanel = $newPanel;
                $showDone = true;

                unset($_SESSION['tds_setup']);
            }
        }
    }

    if ($error) {
        $_SESSION['tds_setup']['login'] = $newLogin;
        $_SESSION['tds_setup']['pass']  = $newPass;
        $_SESSION['tds_setup']['panel'] = $newPanel;
    }
}

$prefill = $_SESSION['tds_setup'];
?><!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Мастер настройки TDS</title>
<link rel="icon" href="<?= h($baseUrl) ?>/favicon.ico" type="image/x-icon">
<style>
body{background:#0f1115;color:#e6e8eb;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;}
.wrap{max-width:620px;margin:40px auto;padding:0 16px;}
.panel{background:#171a21;border:1px solid #262b36;border-radius:10px;padding:22px;margin-bottom:16px;}
h3{margin-top:0;color:#4f7cff;font-size:22px;}
input[type=text],input[type=password]{
width:100%;box-sizing:border-box;background:#0f1115;border:1px solid #262b36;
color:#e6e8eb;padding:13px 14px;border-radius:7px;font-size:15px;margin-bottom:14px;font-family:monospace;
}
input[type=text]:focus,input[type=password]:focus{outline:none;border-color:#4f7cff;}
button{background:#4f7cff;color:#fff;border:none;padding:12px 16px;border-radius:7px;cursor:pointer;font-size:15px;width:100%;}
button.big{background:#3ecf8e;color:#000;font-size:20px;font-weight:700;padding:20px;border-radius:10px;margin-top:14px;display:none;}
button.big.visible{display:block;}
.error{background:rgba(229,72,77,.12);color:#ff9a9d;padding:10px 14px;border-radius:8px;margin-bottom:14px;}
.ok{background:rgba(62,207,142,.12);color:#3ecf8e;padding:12px 16px;border-radius:8px;margin-bottom:14px;font-size:16px;font-weight:600;}
.warn{background:rgba(245,166,35,.15);color:#f5a623;padding:14px 16px;border-radius:8px;margin-bottom:14px;border:2px solid #f5a623;font-size:15px;}
.muted{color:#8b909c;font-size:12px;}
label{display:block;margin-bottom:6px;font-size:13px;color:#cfd6e4;text-transform:uppercase;letter-spacing:.04em;font-weight:600;}
.credentials{background:#0f1115;border:2px solid #4f7cff;border-radius:8px;padding:18px;margin:16px 0;font-family:monospace;font-size:15px;line-height:1.9;}
.credentials .row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px;}
.credentials strong{color:#4f7cff;min-width:110px;display:inline-block;}
.credentials .val{color:#e6e8eb;word-break:break-all;flex:1;}
.copy-btn{background:#2a2f3a;color:#e6e8eb;border:1px solid #3d4658;padding:5px 10px;border-radius:5px;cursor:pointer;font-size:12px;white-space:nowrap;}
.copy-btn:hover{background:#313a4e;}
.copy-btn.ok{background:#3ecf8e;color:#000;border-color:#2f7d55;}
.check-row{display:flex;align-items:center;gap:10px;padding:14px 16px;background:#0f1115;border-radius:8px;margin-top:16px;cursor:pointer;border:1px solid #262b36;}
.check-row:hover{border-color:#4f7cff;}
.check-row input{width:22px;height:22px;margin:0;cursor:pointer;}
.check-row label{margin:0;text-transform:none;font-size:15px;letter-spacing:0;color:#e6e8eb;cursor:pointer;font-weight:normal;}
</style>
</head>
<body>
<div class="wrap">

<?php if ($showDone): ?>
<div class="panel">
<h3>✅ Настройка завершена!</h3>
<div class="ok">Все данные успешно записаны, секретный ключ обновлён.</div>

<div class="warn">
⚠️ <strong>Сохрани эти данные прямо сейчас!</strong><br>
После закрытия страницы их восстановить будет невозможно.
</div>

<div class="credentials">
<div class="row">
<strong>Логин:</strong>
<span class="val" id="loginVal"><?= htmlspecialchars($savedLogin, ENT_QUOTES, 'UTF-8') ?></span>
<button class="copy-btn" onclick="copyField('loginVal', this)">Копировать</button>
</div>
<div class="row">
<strong>Пароль:</strong>
<span class="val" id="passVal"><?= htmlspecialchars($savedPass, ENT_QUOTES, 'UTF-8') ?></span>
<button class="copy-btn" onclick="copyField('passVal', this)">Копировать</button>
</div>
<div class="row">
<strong>Ссылка входа:</strong>
<span class="val" id="urlVal"><?= htmlspecialchars($baseUrl . '/' . $savedPanel, ENT_QUOTES, 'UTF-8') ?></span>
<button class="copy-btn" onclick="copyField('urlVal', this)">Копировать</button>
</div>
<div style="margin-top:12px;text-align:center;">
<button class="copy-btn" onclick="copyAll(this)" style="background:#4f7cff;color:#fff;padding:10px 18px;font-size:14px;">📋 Скопировать всё разом</button>
</div>
</div>

<div class="check-row" onclick="document.getElementById('confirmCheck').click()">
<input type="checkbox" id="confirmCheck" onclick="event.stopPropagation(); toggleGoBtn()">
<label for="confirmCheck">Я сохранил свои данные</label>
</div>

<button class="big" id="goBtn"
onclick="window.location.href='<?= htmlspecialchars($baseUrl . '/' . $savedPanel, ENT_QUOTES, 'UTF-8') ?>'">
🚀 Перейти в админку
</button>

<div class="muted" style="margin-top:14px;text-align:center;">
После перехода войдите с новыми данными и нажмите<br>
«Удалить tools/make_hash.php» — это уберёт мастер с сервера.
</div>
</div>

<?php else: ?>
<div class="panel">
<h3>🔧 Мастер первой настройки</h3>
<p class="muted" style="margin-bottom:18px;">
Все поля уже заполнены случайными значениями. Можешь отредактировать их
или оставить как есть — нажми «Сохранить данные».
</p>

<?php if ($error): ?><div class="error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>

<form method="post">
<label>Логин</label>
<input type="text" name="login" value="<?= htmlspecialchars($prefill['login'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>

<label>Пароль</label>
<input type="text" name="password" value="<?= htmlspecialchars($prefill['pass'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>

<label>Имя файла панели</label>
<input type="text" name="panel_name" value="<?= htmlspecialchars($prefill['panel'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>

<button type="submit">💾 Сохранить данные</button>
</form>
</div>
<?php endif; ?>

</div>

<script>
function copyField(id, btn) {
    var text = document.getElementById(id).textContent;
    copyText(text, btn);
}

function copyAll(btn) {
    var login = document.getElementById('loginVal').textContent;
    var pass  = document.getElementById('passVal').textContent;
    var url   = document.getElementById('urlVal').textContent;
    var text  = 'Логин: ' + login + '\nПароль: ' + pass + '\nСсылка входа: ' + url;
    copyText(text, btn);
}

function copyText(text, btn) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function() { flash(btn); });
    } else {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.top = '-1000px';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); flash(btn); } catch(e) {}
        document.body.removeChild(ta);
    }
}

function flash(btn) {
    var orig = btn.textContent;
    btn.textContent = '✓ Скопировано';
    btn.classList.add('ok');
    setTimeout(function() {
        btn.textContent = orig;
        btn.classList.remove('ok');
    }, 1500);
}

function toggleGoBtn() {
    var cb = document.getElementById('confirmCheck');
    var btn = document.getElementById('goBtn');
    if (cb.checked) btn.classList.add('visible');
    else btn.classList.remove('visible');
}
</script>
</body>
</html>