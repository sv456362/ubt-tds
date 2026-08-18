<?php
/**
 * index.php — публичный редиректор.
 * Основной способ использования (через .htaccess): https://вашдомен/SLUG
 * Также работает напрямую: https://вашдомен/index.php?c=SLUG
 * Метка источника: https://вашдомен/SLUG?googlr — любой GET-параметр,
 * кроме «c», считается тегом реферера и подставляется в отчёт, когда
 * настоящий реферер не определён (пустой или «сам себя»).
 */
require __DIR__ . '/config.php';
require __DIR__ . '/includes/functions.php';

function fallback(): void {
    if (FALLBACK_REDIRECT_URL !== '') {
        header('Location: ' . FALLBACK_REDIRECT_URL, true, 302);
        exit;
    }
    http_response_code(404);
    exit('Not found');
}

$campaign = isset($_GET['c']) ? preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['c']) : '';
if ($campaign === '') {
    fallback();
}

$links = load_links();
if (!isset($links[$campaign]) || empty($links[$campaign]['targets'])) {
    fallback();
}

$camp = $links[$campaign];
if (isset($camp['active']) && !$camp['active']) {
    fallback();
}

$targetIndex = pick_weighted_target($camp['targets']);
$target = $camp['targets'][$targetIndex];
if (empty($target['url'])) {
    fallback();
}

// Метка источника из строки запроса: /SLUG?googlr или /index.php?c=SLUG&src=fb
// (любой GET-параметр кроме «c»; в «голом» виде меткой является имя параметра).
// ВАЖНО: для короткого формата правило в .htaccess должно иметь флаг QSA,
// иначе всё, что стоит после «?», теряется при перезаписи на index.php.
$refTag = '';
foreach ($_GET as $k => $v) {
    if ($k === 'c') continue;
    $refTag = ($v === '' || $v === null) ? (string)$k : $k . '=' . $v;
    break;
}

log_click($campaign, $targetIndex, $refTag);

$redirectType = (int)($camp['redirect_type'] ?? DEFAULT_REDIRECT_TYPE);
if (!in_array($redirectType, [301, 302, 307, 308], true)) {
    $redirectType = 302;
}
header('Location: ' . $target['url'], true, $redirectType);
exit;