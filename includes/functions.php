<?php
/**
 * Вспомогательные функции. Архитектура «файл = день»:
 * - каждый клик аппендится в data/logs/YYYY-MM-DD.php (с PHP-заглушкой);
 * - статистика за день читает ОДИН маленький файл;
 * - ротация = удаление файлов старше 30 дней по имени, без сканирования;
 * - график строится из кэша data/chart_<slug>.dat.php + живого текущего дня;
 * - уники: cookie-ID, при отсутствии — хэш IP;
 * - боты: явные подписи (bs>=3) или «рецидивисты без куки» (2+ хита без куки);
 * - реферер: внешний как есть, пустой/«сам себя» заменяется меткой из ссылки.
 */

const STORAGE_GUARD = "<?php exit; ?>\n";
if (!defined('LOGS_DIR')) define('LOGS_DIR', DATA_DIR . '/logs');
if (!defined('ROTATION_FILE')) define('ROTATION_FILE', DATA_DIR . '/.last_rotation');
if (!defined('HOST_COOKIE')) define('HOST_COOKIE', 'ubt_uid');
if (!defined('HOST_COOKIE_DAYS')) define('HOST_COOKIE_DAYS', 365);
if (!defined('LOGIN_THROTTLE_FILE')) define('LOGIN_THROTTLE_FILE', DATA_DIR . '/.login_throttle.json');
if (!defined('LOGIN_MAX_FAILS')) define('LOGIN_MAX_FAILS', 5);
if (!defined('LOGIN_WINDOW')) define('LOGIN_WINDOW', 900);

function ensure_data_files(): void {
    static $done = false;
    if ($done) return;
    if (!is_dir(DATA_DIR)) mkdir(DATA_DIR, 0775, true);
    if (!is_dir(LOGS_DIR)) mkdir(LOGS_DIR, 0775, true);
    if (!file_exists(LINKS_FILE)) {
        file_put_contents(LINKS_FILE, STORAGE_GUARD . json_encode([], JSON_PRETTY_PRINT));
    }
    $done = true;
}

/**
 * Читает кампании. Счётчики кликов уже хранятся в самом файле
 * (инкремент на каждый клик), $withClicks — для совместимости вызовов.
 */
function load_links(bool $withClicks = false): array {
    ensure_data_files();
    $content = @file_get_contents(LINKS_FILE);
    if ($content === false) return [];
    if (strncmp($content, '<?php', 5) === 0) {
        $pos = strpos($content, "\n");
        if ($pos !== false) $content = substr($content, $pos + 1);
    }
    $data = json_decode($content, true);
    return is_array($data) ? $data : [];
}

/**
 * Атомарное сохранение: временный файл → rename().
 * Вызывается только из админки и при инкременте счётчиков.
 */
function save_links(array $data): bool {
    ensure_data_files();
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $tmp = LINKS_FILE . '.tmp';
    if (file_put_contents($tmp, STORAGE_GUARD . $json, LOCK_EX) === false) return false;
    return rename($tmp, LINKS_FILE);
}

function rename_campaign_slug(string $oldSlug, string $newSlug): bool {
    $links = load_links();
    if (!isset($links[$oldSlug]) || isset($links[$newSlug]) || $newSlug === '') return false;
    $links[$newSlug] = $links[$oldSlug];
    unset($links[$oldSlug]);
    return save_links($links);
}

function pick_weighted_target(array $targets): int {
    $total = 0;
    foreach ($targets as $t) $total += max(0, (int)($t['weight'] ?? 1));
    if ($total <= 0) return 0;
    $rand = mt_rand(1, $total);
    $acc = 0;
    foreach ($targets as $i => $t) {
        $acc += max(0, (int)($t['weight'] ?? 1));
        if ($rand <= $acc) return $i;
    }
    return array_key_first($targets);
}

/* ---------------- сбор данных о посетителе ---------------- */
function get_client_ip(): string {
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR'] as $key) {
        if (!empty($_SERVER[$key])) {
            $val = trim(explode(',', $_SERVER[$key])[0]);
            if (filter_var($val, FILTER_VALIDATE_IP)) return $val;
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function client_host_hash(): string {
    return substr(hash('sha256', get_client_ip() . APP_SECRET), 0, 12);
}

/**
 * Возвращает [hostId, hadCookie]: cookie есть → ID из неё (стабилен при смене IP),
 * нет → ID = хэш IP и тут же ставим cookie для будущих визитов.
 */
function get_host_id(): array {
    $ipHash = client_host_hash();
    $cookie = $_COOKIE[HOST_COOKIE] ?? '';
    if (preg_match('/^[a-f0-9]{12}$/', $cookie)) return [$cookie, true];
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    setcookie(HOST_COOKIE, $ipHash, time() + HOST_COOKIE_DAYS * 86400, '/', '', $secure, true);
    return [$ipHash, false];
}

/**
 * «Ботность» по аномалиям HTTP-запроса. Возвращает [балл, маска]:
 * маска перечисляет сработавшие чеки — видно, какой заголовок «провалился».
 * (Чек Accept-Encoding убран: прокси хостинга вырезает его у всех запросов.)
 */
function bot_score(): array {
    $score = 0;
    $mask = [];
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if ($ua === '') {
        $score += 3;
        $mask[] = 'пустой-UA';
    } elseif (preg_match('/bot|crawl|spider|curl|wget|python|scrapy|httpclient|libwww|lwp-|okhttp|java\/|go-http|headless|phantom|selenium|puppeteer|parser|monitor|fetch|probe/i', $ua)) {
        $score += 5;
        $mask[] = 'бот-UA';
    }
    if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) { $score += 1; $mask[] = 'нет-языка'; }
    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
    if ($accept !== '' && strpos($accept, 'text/html') === false && strpos($accept, '*/*') === false) { $score += 1; $mask[] = 'нет-html'; }
    if (empty($_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS'])
        && empty($_SERVER['HTTP_SEC_FETCH_MODE'])
        && empty($_SERVER['HTTP_SEC_CH_UA'])) { $score += 1; $mask[] = 'нет-sec-заголовков'; }
    return [$score, implode(', ', $mask)];
}

/**
 * Бот ли запись СРАЗУ: только явные подписи (балл >= 3).
 * Аномалии заголовков (1–2 балла) сами по себе не криминал.
 */
function rec_is_bot(array $rec): bool {
    return ((int)($rec['bs'] ?? 0)) >= 3;
}

/**
 * Хосты-«рецидивисты»: били 2+ раза и каждый раз без куки.
 * Браузер вернул бы куку со второго хита — значит, это скрипт.
 */
function bot_repeat_hosts(array $records): array {
    $nc = [];
    foreach ($records as $r) {
        if (!empty($r['nc']) && ($r['h'] ?? '') !== '') {
            $nc[$r['h']] = ($nc[$r['h']] ?? 0) + 1;
        }
    }
    $out = [];
    foreach ($nc as $h => $cnt) {
        if ($cnt >= 2) $out[$h] = true;
    }
    return $out;
}

/**
 * Итоговый вердикт: явная подпись ИЛИ «рецидивист без куки».
 */
function rec_is_bot_full(array $rec, array $repeatHosts): bool {
    if (rec_is_bot($rec)) return true;
    $h = $rec['h'] ?? '';
    return !empty($rec['nc']) && $h !== '' && isset($repeatHosts[$h]);
}

function detect_device(string $ua): string {
    return preg_match('/Mobi|Android|iPhone|iPad|iPod|Windows Phone|BlackBerry/i', $ua) ? 'mobile' : 'desktop';
}

function parse_primary_language(?string $header): string {
    if (!$header) return 'unknown';
    $first = trim(explode(',', $header)[0]);
    $lang = trim(explode(';', $first)[0]);
    $lang = explode('-', $lang)[0];
    $lang = strtolower(trim($lang));
    return $lang !== '' ? $lang : 'unknown';
}

function referrer_domain(?string $ref): string {
    if (!$ref) return 'Прямой переход';
    $host = parse_url($ref, PHP_URL_HOST);
    if (!$host) return $ref; // метка источника (?googlr)
    return preg_replace('/^www\./', '', strtolower($host));
}

function self_host(): string {
    $host = strtolower($_SERVER['HTTP_HOST'] ?? '');
    $host = preg_replace('/:\d+$/', '', $host);
    return preg_replace('/^www\./', '', $host);
}

/* ---------------- дневные файлы лога ---------------- */
function log_file_for(string $date): string {
    return LOGS_DIR . '/' . $date . '.php';
}

// Список дат (Y-m-d), по которым есть лог-файлы; хронологически по возрастанию
function list_log_days(): array {
    ensure_data_files();
    $out = [];
    foreach (glob(LOGS_DIR . '/*.php') as $f) {
        $d = basename($f, '.php');
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $d)) $out[] = $d;
    }
    sort($out);
    return $out;
}

// Читает один дневной файл сверху вниз, пропуская заглушку
function each_click_record_in_file(string $file, callable $callback): void {
    $fp = @fopen($file, 'r');
    if (!$fp) return;
    fgets($fp); // заглушка
    while (($line = fgets($fp)) !== false) {
        $line = trim($line);
        if ($line === '') continue;
        $rec = json_decode($line, true);
        if (is_array($rec)) $callback($rec);
    }
    fclose($fp);
}

// Читает СТАРЫЙ единый лог data/stats.dat.php (нужен только для миграции)
function each_click_record(callable $callback): void {
    if (!is_file(STATS_FILE)) return;
    $fp = fopen(STATS_FILE, 'r');
    if (!$fp) return;
    fgets($fp);
    while (($line = fgets($fp)) !== false) {
        $line = trim($line);
        if ($line === '') continue;
        $rec = json_decode($line, true);
        if (!is_array($rec)) {
            $parts = explode("\t", $line);
            if (count($parts) < 3) continue;
            $rec = ['t' => $parts[0], 'c' => $parts[1], 'i' => (int)$parts[2], 'r' => $parts[3] ?? '', 'h' => null, 'l' => 'unknown', 'd' => 'unknown'];
        }
        $callback($rec);
    }
    fclose($fp);
}

/* ---------------- ротация: удаление старых файлов, без сканирования ---------------- */
function should_rotate_log(): bool {
    if (!file_exists(ROTATION_FILE)) return true;
    $last = (int)@file_get_contents(ROTATION_FILE);
    return (time() - $last) > 3600;
}

function rotate_log(): void {
    $cutoff = date('Y-m-d', strtotime('-30 days'));
    foreach (glob(LOGS_DIR . '/*.php') as $f) {
        $d = basename($f, '.php');
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $d) && $d < $cutoff) @unlink($f);
    }
    @file_put_contents(ROTATION_FILE, (string)time(), LOCK_EX);
}

/* ---------------- логирование кликов ---------------- */
// Записывает клик в файл дня; 'bs' — балл ботности, 'bb' — маска чеков.
function log_click(string $campaign, int $targetIndex): void {
    ensure_data_files();
    [$hostId, $hadCookie] = get_host_id();

    // Метка источника: /SLUG?googlr или /index.php?c=SLUG&src=fb
    $refTag = '';
    foreach ($_GET as $k => $v) {
        if ($k === 'c') continue;
        $refTag = ($v === '' || $v === null) ? (string)$k : $k . '=' . $v;
        break;
    }
    $refTag = rtrim($refTag, '/');

    // Реферер: внешний как есть; пустой/«сам себя» → метка
    $ref = $_SERVER['HTTP_REFERER'] ?? '';
    $rd = referrer_domain($ref);
    $self = self_host();
    $refStore = ($rd !== 'Прямой переход' && ($self === '' || $rd !== $self)) ? $ref : $refTag;

    [$bsScore, $bsMask] = bot_score();

    $record = [
        't' => date('Y-m-d H:i:s'),
        'c' => $campaign,
        'i' => $targetIndex,
        'r' => substr($refStore, 0, 300),
        'h' => $hostId,
        'nc' => $hadCookie ? 0 : 1,
        'bs' => $bsScore,
        'bb' => $bsMask,
        'l' => parse_primary_language($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null),
        'd' => detect_device($_SERVER['HTTP_USER_AGENT'] ?? ''),
    ];

    $file = log_file_for(date('Y-m-d'));
    $fp = fopen($file, 'a');
    if ($fp) {
        flock($fp, LOCK_EX);
        if (ftell($fp) === 0) fwrite($fp, STORAGE_GUARD);
        fwrite($fp, json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
        flock($fp, LOCK_UN);
        fclose($fp);
    }

    // счётчики кампании (для списка в админке)
    $links = load_links();
    if (isset($links[$campaign]['targets'][$targetIndex])) {
        $links[$campaign]['targets'][$targetIndex]['clicks'] =
            ($links[$campaign]['targets'][$targetIndex]['clicks'] ?? 0) + 1;
        $links[$campaign]['total_clicks'] = ($links[$campaign]['total_clicks'] ?? 0) + 1;
        save_links($links);
    }

    if (should_rotate_log()) rotate_log();
}

/* ---------------- аналитика за день ---------------- */
/**
 * Лёгкая аналитика за ОДИН день: читает только один файл дня.
 * 'cls' у записей: bot / new (первый хит дня) / ret (повтор в течение дня).
 */
function analyze_campaign_day(string $slug, string $date): array {
    $hits = 0; $hostsSet = []; $bots = 0;
    $referrers = []; $languages = [];
    $devices = ['desktop' => 0, 'mobile' => 0, 'unknown' => 0];
    $records = [];
    $file = log_file_for($date);
    if (is_file($file)) {
        each_click_record_in_file($file, function ($rec) use (
            $slug, &$hits, &$hostsSet, &$referrers, &$languages, &$devices, &$records
        ) {
            if (($rec['c'] ?? '') !== $slug) return;
            $hits++;
            $h = $rec['h'] ?? null;
            if ($h) $hostsSet[$h] = true;
            $ref = referrer_domain($rec['r'] ?? '');
            $referrers[$ref] = ($referrers[$ref] ?? 0) + 1;
            $lang = $rec['l'] ?? 'unknown';
            $languages[$lang] = ($languages[$lang] ?? 0) + 1;
            $dev = $rec['d'] ?? 'unknown';
            if (!isset($devices[$dev])) $devices[$dev] = 0;
            $devices[$dev]++;
            $records[] = $rec;
        });
    }
    $repeat = bot_repeat_hosts($records);
    foreach ($records as $r) {
        if (rec_is_bot_full($r, $repeat)) $bots++;
    }
    // класс строки: бот / первый хит дня / повтор в течение дня
    $seen = [];
    foreach ($records as &$r) {
        $h = $r['h'] ?? '';
        if (rec_is_bot_full($r, $repeat)) {
            $r['cls'] = 'bot';
        } elseif ($h !== '' && isset($seen[$h])) {
            $r['cls'] = 'ret';
        } else {
            if ($h !== '') $seen[$h] = true;
            $r['cls'] = 'new';
        }
    }
    unset($r);
    $records = array_reverse($records); // новые сверху для таблицы
    arsort($referrers);
    arsort($languages);
    return [
        'hits' => $hits,
        'hosts' => count($hostsSet),
        'bots' => $bots,
        'referrers' => $referrers,
        'languages' => $languages,
        'devices' => $devices,
        'records' => $records,
    ];
}

/* ---------------- кэш сумм за день для графика ---------------- */
function chart_cache_file(string $slug): string {
    return DATA_DIR . '/chart_' . preg_replace('/[^a-zA-Z0-9_-]/', '', $slug) . '.dat.php';
}

function chart_cache_read(string $file): array {
    $out = [];
    if (!is_file($file)) return $out;
    $fp = @fopen($file, 'r');
    if (!$fp) return $out;
    fgets($fp); // заглушка
    while (($line = fgets($fp)) !== false) {
        $p = explode("\t", trim($line));
        if (count($p) >= 4) {
            $out[$p[0]] = ['hits' => (int)$p[1], 'hosts' => (int)$p[2], 'bots' => (int)$p[3]];
        }
    }
    fclose($fp);
    return $out;
}

function chart_cache_write(string $file, array $data): void {
    ksort($data);
    $lines = STORAGE_GUARD;
    foreach ($data as $d => $v) {
        $lines .= $d . "\t" . $v['hits'] . "\t" . $v['hosts'] . "\t" . $v['bots'] . "\n";
    }
    $tmp = $file . '.tmp';
    if (file_put_contents($tmp, $lines, LOCK_EX) !== false) rename($tmp, $file);
}

// Суммы за один день из его лог-файла (боты — по новым правилам).
// $slug !== null — считать только указанную кампанию.
function summarize_day_file(string $date, string $slug = null): array {
    $records = [];
    $file = log_file_for($date);
    if (is_file($file)) {
        each_click_record_in_file($file, function ($rec) use (&$records, $slug) {
            if ($slug !== null && ($rec['c'] ?? '') !== $slug) return;
            $records[] = $rec;
        });
    }
    $repeat = bot_repeat_hosts($records);
    $hits = 0; $hosts = []; $bots = 0;
    foreach ($records as $rec) {
        $hits++;
        $h = $rec['h'] ?? null;
        if ($h) $hosts[$h] = true;
        if (rec_is_bot_full($rec, $repeat)) $bots++;
    }
    return ['hits' => $hits, 'hosts' => count($hosts), 'bots' => $bots];
}

/**
 * Готовый массив для графика за $days дней (date => hits/hosts/bots)
 * ПО КОНКРЕТНОЙ КАМПАНИИ. Дёшево: кэш из ~30 строк + живой текущий день;
 * вчерашний досчитывается один раз после смены суток.
 */
function get_chart_daily(string $slug, int $days = 30): array {
    $today = date('Y-m-d');
    $windowStart = date('Y-m-d', strtotime('-' . ($days - 1) . ' days'));
    $file = chart_cache_file($slug);
    $cache = chart_cache_read($file);

    // Досчитываем отсутствующее от вчера назад (в штатном режиме — только вчера)
    $d = date('Y-m-d', strtotime('-1 day'));
    $changed = false;
    while ($d >= $windowStart) {
        if (isset($cache[$d])) break;
        $cache[$d] = summarize_day_file($d, $slug);
        $changed = true;
        $d = date('Y-m-d', strtotime($d . ' -1 day'));
    }
    // Удаляем строки старше окна
    foreach ($cache as $date => $v) {
        if ($date < $windowStart) { unset($cache[$date]); $changed = true; }
    }
    if ($changed) chart_cache_write($file, $cache);

    $daily = [];
    for ($i = $days - 1; $i >= 0; $i--) {
        $date = date('Y-m-d', strtotime("-$i days"));
        $daily[$date] = ($date === $today)
            ? summarize_day_file($date, $slug)                      // живой текущий день
            : ($cache[$date] ?? ['hits' => 0, 'hosts' => 0, 'bots' => 0]);
    }
    return $daily;
}

/* ---------------- SVG-график: 3 цвета + кликабельная ось дней ---------------- */
function render_dual_line_chart(array $daily, string $linkBase = '', string $selectedDay = ''): string {
    $dates = array_keys($daily);
    $hits  = array_values(array_map(function ($v) { return (int)$v['hits']; }, $daily));
    $hosts = array_values(array_map(function ($v) { return (int)$v['hosts']; }, $daily));
    $bots  = array_values(array_map(function ($v) { return (int)($v['bots'] ?? 0); }, $daily));
    $n = count($dates);
    if ($n < 2) return '<p class="muted">Недостаточно данных для графика.</p>';

    $width = 700; $height = 236;
    $padL = 34; $padR = 14; $padT = 18; $padB = 44;
    $plotW = $width - $padL - $padR;
    $plotH = $height - $padT - $padB;
    $max  = max(1, max($hits), max($hosts), max($bots));
    $slot = $plotW / $n;
    $barW = max(3, round($slot * 0.62, 1));

    $monthNames = ['01'=>'янв','02'=>'фев','03'=>'мар','04'=>'апр','05'=>'май','06'=>'июн',
                   '07'=>'июл','08'=>'авг','09'=>'сен','10'=>'окт','11'=>'ноя','12'=>'дек'];

    $svg = '<svg viewBox="0 0 ' . $width . ' ' . $height . '" width="100%" style="max-width:100%;height:auto;">';

    foreach ([0, 0.5, 1] as $frac) {
        $y = round($padT + $plotH - $frac * $plotH, 1);
        $val = (int)round($max * $frac);
        $svg .= '<line x1="' . $padL . '" y1="' . $y . '" x2="' . ($width - $padR) . '" y2="' . $y . '" stroke="#262b36" stroke-width="1"/>';
        $svg .= '<text x="4" y="' . ($y + 4) . '" font-size="10" fill="#8b909c">' . $val . '</text>';
    }

    $prevMonth = '';
    for ($i = 0; $i < $n; $i++) {
        $xC   = $padL + $i * $slot + $slot / 2;
        $xBar = round($xC - $barW / 2, 1);

        $svg .= '<rect x="' . $xBar . '" y="' . ($padT + $plotH - 1) . '" width="' . $barW . '" height="1" fill="#262b36"/>';

        // цифра дня: кликабельна, если есть данные; выбранный день — синий жирный
        $dayNum = (int)substr($dates[$i], 8, 2);
        if ($linkBase !== '' && $hits[$i] > 0) {
            $isSel = ($dates[$i] === $selectedDay);
            $fill = $isSel ? '#4f7cff' : '#cfd6e4';
            $fw = $isSel ? ' font-weight="700"' : '';
            $svg .= '<a href="' . h($linkBase . '&day=' . $dates[$i]) . '" style="cursor:pointer;">'
                 .  '<text x="' . round($xC, 1) . '" y="' . ($padT + $plotH + 13) . '" font-size="9" fill="' . $fill . '"' . $fw . ' text-anchor="middle">' . $dayNum . '</text></a>';
        } else {
            $svg .= '<text x="' . round($xC, 1) . '" y="' . ($padT + $plotH + 13) . '" font-size="9" fill="#8b909c" text-anchor="middle">' . $dayNum . '</text>';
        }

        $m = substr($dates[$i], 5, 2);
        if ($i === 0 || $m !== $prevMonth) {
            $svg .= '<text x="' . round($xC, 1) . '" y="' . ($height - 6) . '" font-size="10" fill="#cfd6e4" text-anchor="middle">' . ($monthNames[$m] ?? $m) . '</text>';
        }
        $prevMonth = $m;

        if ($hits[$i] <= 0) continue;

        $hHits = round(($hits[$i] / $max) * $plotH, 1);
        $yHits = round($padT + $plotH - $hHits, 1);

        $svg .= '<g><title>' . h($dates[$i]) . ' — хиты: ' . $hits[$i] . ', хосты: ' . $hosts[$i] . ', боты: ' . $bots[$i] . '</title>';
        $svg .= '<rect x="' . $xBar . '" y="' . $yHits . '" width="' . $barW . '" height="' . $hHits . '" rx="2" fill="#4f7cff"/>';
        if ($hosts[$i] > 0) {
            $hG = round(($hosts[$i] / $max) * $plotH, 1);
            $svg .= '<rect x="' . $xBar . '" y="' . round($padT + $plotH - $hG, 1) . '" width="' . $barW . '" height="' . $hG . '" fill="#e5484d"/>';
        }
        if ($bots[$i] > 0) {
            $hB = round(($bots[$i] / $max) * $plotH, 1);
            $svg .= '<rect x="' . $xBar . '" y="' . round($padT + $plotH - $hB, 1) . '" width="' . $barW . '" height="' . $hB . '" fill="#f5a623"/>';
        }
        $svg .= '<rect x="' . $xBar . '" y="' . $yHits . '" width="' . $barW . '" height="' . $hHits . '" rx="2" fill="none" stroke="#000" stroke-width="1"/>';
        $svg .= '</g>';
    }

    $svg .= '</svg>';
    return $svg;
}

/* ---------------- первый запуск / пароль ---------------- */
function is_default_auth(): bool {
    return ADMIN_PASSWORD_HASH === '';
}

function check_admin_password(string $pass): bool {
    if (!is_default_auth()) return password_verify($pass, ADMIN_PASSWORD_HASH);
    return hash_equals('admin', $pass);
}

/* ---------------- троттлинг входа ---------------- */
function login_throttle_check(string $ip): bool {
    $data = json_decode((string)@file_get_contents(LOGIN_THROTTLE_FILE), true);
    if (!is_array($data)) return true;
    $rec = $data[$ip] ?? null;
    if ($rec && ($rec['lock'] ?? 0) > time()) return false;
    return true;
}

function login_throttle_fail(string $ip): void {
    $data = json_decode((string)@file_get_contents(LOGIN_THROTTLE_FILE), true);
    if (!is_array($data)) $data = [];
    $now = time();
    $rec = $data[$ip] ?? ['fails' => [], 'lock' => 0];
    $fresh = [];
    foreach ($rec['fails'] as $t) {
        if ($t > $now - LOGIN_WINDOW) $fresh[] = $t;
    }
    $fresh[] = $now;
    $rec['fails'] = $fresh;
    if (count($fresh) >= LOGIN_MAX_FAILS) {
        $rec['lock'] = $now + LOGIN_WINDOW;
        $rec['fails'] = [];
    }
    $data[$ip] = $rec;
    if (count($data) > 200) {
        foreach ($data as $k => $r) {
            if (($r['lock'] ?? 0) < $now && empty($r['fails'])) unset($data[$k]);
        }
    }
    @file_put_contents(LOGIN_THROTTLE_FILE, json_encode($data), LOCK_EX);
}

function login_throttle_clear(string $ip): void {
    $data = json_decode((string)@file_get_contents(LOGIN_THROTTLE_FILE), true);
    if (!is_array($data) || !isset($data[$ip])) return;
    unset($data[$ip]);
    @file_put_contents(LOGIN_THROTTLE_FILE, json_encode($data), LOCK_EX);
}

/* ---------------- разное ---------------- */
function generate_slug(int $len = 6): string {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $slug = '';
    for ($i = 0; $i < $len; $i++) {
        $slug .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $slug;
}

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
    return $_SESSION['csrf'];
}

function csrf_check(): bool {
    return isset($_POST['csrf'], $_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $_POST['csrf']);
}

function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

/* ---------------- хосты за сегодня для списка кампаний ---------------- */
// Уники (хосты) за сегодня по каждой кампании — для главной таблицы.
function today_hosts_by_campaign(): array {
    $sets = [];
    $file = log_file_for(date('Y-m-d'));
    if (is_file($file)) {
        each_click_record_in_file($file, function ($rec) use (&$sets) {
            $c = $rec['c'] ?? '';
            if ($c === '') return;
            $h = $rec['h'] ?? null;
            if ($h) $sets[$c][$h] = true;
        });
    }
    $out = [];
    foreach ($sets as $c => $set) $out[$c] = count($set);
    return $out;
}