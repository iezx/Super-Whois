<?php
// index.php — Super Whois v2.1.0
define('RATE_LIMIT', 30);
define('RATE_WINDOW', 3600);
define('RATE_STORE', __DIR__ . '/rate_store');
define('TRUST_PROXY_HEADERS', true);

ini_set('pcre.backtrack_limit', '100000');

if (empty($_SERVER['QUERY_STRING']) && empty($_POST)) {
    $default_lang = isset($_COOKIE['lang']) ? $_COOKIE['lang'] : 'en';
    header('Location: index.php?lang=' . $default_lang);
    exit();
}

if (!function_exists('idn_to_ascii')) {
    die("Error: The 'intl' PHP extension is missing.");
}

require_once __DIR__ . '/languages.php';

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: no-referrer-when-downgrade');
header('Permissions-Policy: clipboard-write=(self)');

$supported_langs = ['en', 'zh'];
$lang = 'en';

if (isset($_GET['lang'])) {
    $gl = strtolower(trim($_GET['lang']));
    if (in_array($gl, $supported_langs, true)) {
        $lang = $gl;
        $isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        setcookie('lang', $lang, [
            'expires'  => time() + 86400 * 30,
            'path'     => '/',
            'secure'   => $isSecure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }
} elseif (isset($_COOKIE['lang']) && in_array($_COOKIE['lang'], $supported_langs, true)) {
    $lang = $_COOKIE['lang'];
}
$T = get_language_strings($lang);

function getClientIP(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (TRUST_PROXY_HEADERS) {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
        }
    }
    $validated = filter_var($ip, FILTER_VALIDATE_IP);
    return $validated ?: 'unknown';
}

function enforceRateLimit(): void {
    $dir = RATE_STORE;
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $ip   = getClientIP();
    $key  = preg_replace('/[^a-z0-9.:]/i', '_', strtolower($ip));
    $file = $dir . '/' . $key . '.json';
    $now  = time();
    $fp = fopen($file, 'c+');
    if (!$fp) die('Rate limit storage unavailable.');
    flock($fp, LOCK_EX);
    $size = filesize($file);
    $raw  = $size > 0 ? fread($fp, $size) : '';
    $data = json_decode($raw, true) ?: ['count' => 0, 'reset' => $now + RATE_WINDOW];
    if ($now > $data['reset'] || !isset($data['count'])) {
        $data = ['count' => 0, 'reset' => $now + RATE_WINDOW];
    }
    $data['count']++;
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if ($data['count'] > RATE_LIMIT) {
        http_response_code(429);
        die('Rate limit exceeded.');
    }
}

enforceRateLimit();

function sanitizeQuery(string $input): string {
    $q = trim($input);
    $q = preg_replace('/^https?:\/\//i', '', $q);
    $q = explode('/', $q, 2)[0];
    $q = preg_replace('/:\d+$/', '', $q);
    $q = preg_replace('/\s+/', '', $q);
    return substr($q, 0, 253);
}

function getSafeWhoisIP(string $host): ?string {
    $host = strtolower(trim($host));
    if ($host === '') return null;
    $resolvedIP = null;
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $resolvedIP = $host;
    } else {
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        if ($records === false || empty($records)) return null;
        foreach ($records as $record) {
            if (isset($record['ip'])) { $resolvedIP = $record['ip']; break; }
            if (isset($record['ipv6'])) { $resolvedIP = $record['ipv6']; break; }
        }
    }
    if (!$resolvedIP) return null;
    if (filter_var($resolvedIP, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return filter_var($resolvedIP, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "[$resolvedIP]" : $resolvedIP;
    }
    return null;
}

function getDomainExtension(string $domain): string {
    $a = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($a === false) return '';
    return strtolower(end(explode('.', $a)));
}

function resolveWhoisServer(string $domainAscii, array $whoisServers): ?string {
    $labels = explode('.', strtolower($domainAscii));
    $n      = count($labels);
    if ($n >= 2) {
        $sld = $labels[$n - 2] . '.' . $labels[$n - 1];
        if (isset($whoisServers[$sld])) return $whoisServers[$sld];
    }
    return $whoisServers[$labels[$n - 1]] ?? null;
}

function queryWhoisServer(string $serverDomain, string $query): array {
    $safeIP = getSafeWhoisIP($serverDomain);
    if (!$safeIP) return [];
    $sock = @fsockopen($safeIP, 43, $errno, $errstr, 5);
    if (!$sock) return [];
    stream_set_timeout($sock, 5);
    fwrite($sock, $query . "\r\n");
    $raw = '';
    while (!feof($sock)) {
        $chunk = fgets($sock, 4096);
        if ($chunk === false) break;
        $raw .= $chunk;
        if (strlen($raw) > 524288) break;
    }
    fclose($sock);
    return explode("\n", $raw);
}

function resolveFullWhois(string $server, string $query): array {
    $lines = queryWhoisServer($server, $query);
    if (empty($lines)) return [$lines, $server];
    $referral = null;
    foreach ($lines as $line) {
        if (preg_match('/^Registrar WHOIS Server\s*:\s*(.+)$/i', trim($line), $m)) {
            $c = strtolower(trim($m[1]));
            if ($c !== '' && strtolower($c) !== strtolower($server)) {
                $referral = $c;
                break;
            }
        }
    }
    if ($referral !== null) {
        $full = queryWhoisServer($referral, $query);
        if (count($full) > 5) return [$full, $referral];
    }
    return [$lines, $server];
}

function censorIPsInArray(array $lines): array {
    $pat = '/(\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9:.]+\b)/i';
    return array_map(fn($l) => preg_replace($pat, '[REDACTED]', $l), $lines);
}

function getRIRServer(string $ip): string {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'whois.arin.net';
    $l = ip2long($ip);
    $r = fn($a, $b) => $l >= ip2long($a) && $l <= ip2long($b);
    if ($r('1.0.0.0','1.255.255.255')||$r('14.0.0.0','14.255.255.255')||
        $r('27.0.0.0','27.255.255.255')||$r('49.0.0.0','49.255.255.255')||
        $r('58.0.0.0','60.255.255.255')||$r('101.0.0.0','103.255.255.255')||
        $r('110.0.0.0','126.255.255.255')||$r('175.0.0.0','180.255.255.255')||
        $r('182.0.0.0','183.255.255.255')||$r('202.0.0.0','203.255.255.255')||
        $r('210.0.0.0','211.255.255.255')||$r('218.0.0.0','223.255.255.255'))
        return 'whois.apnic.net';
    if ($r('2.0.0.0','2.255.255.255')||$r('5.0.0.0','5.255.255.255')||
        $r('31.0.0.0','31.255.255.255')||$r('37.0.0.0','37.255.255.255')||
        $r('46.0.0.0','46.255.255.255')||$r('77.0.0.0','95.255.255.255')||
        $r('176.0.0.0','178.255.255.255')||$r('185.0.0.0','185.255.255.255')||
        $r('188.0.0.0','195.255.255.255')||$r('212.0.0.0','213.255.255.255')||
        $r('217.0.0.0','217.255.255.255'))
        return 'whois.ripe.net';
    if ($r('177.0.0.0','177.255.255.255')||$r('179.0.0.0','179.255.255.255')||
        $r('181.0.0.0','181.255.255.255')||$r('186.0.0.0','191.255.255.255')||
        $r('200.0.0.0','201.255.255.255'))
        return 'whois.lacnic.net';
    if ($r('41.0.0.0','41.255.255.255')||$r('102.0.0.0','102.255.255.255')||
        $r('105.0.0.0','105.255.255.255')||$r('154.0.0.0','154.255.255.255')||
        $r('196.0.0.0','197.255.255.255'))
        return 'whois.afrinic.net';
    return 'whois.arin.net';
}

function detectApexDomain(string $query): ?string {
    $ascii = idn_to_ascii($query, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($ascii === false) return null;
    $labels = explode('.', strtolower($ascii));
    $n      = count($labels);
    if ($n < 3) return null;
    $known2 = [
        'co.uk','org.uk','me.uk','net.uk','ltd.uk','plc.uk','sch.uk',
        'ac.uk','gov.uk','nhs.uk','police.uk','mod.uk',
        'com.au','net.au','org.au','edu.au','gov.au','asn.au','id.au',
        'com.cn','net.cn','org.cn','gov.cn','edu.cn','ac.cn',
        'co.jp','ne.jp','ac.jp','go.jp','or.jp','gr.jp','ed.jp',
        'co.nz','net.nz','org.nz','govt.nz','ac.nz','school.nz',
        'co.in','net.in','org.in','gov.in','ac.in','edu.in',
        'co.za','net.za','org.za','gov.za','ac.za','edu.za',
        'com.br','net.br','org.br','gov.br','edu.br',
        'com.mx','net.mx','org.mx','gob.mx','edu.mx',
        'com.ar','net.ar','org.ar','gov.ar','edu.ar',
        'com.sg','net.sg','org.sg','gov.sg','edu.sg',
        'com.hk','net.hk','org.hk','gov.hk','edu.hk',
        'com.tw','net.tw','org.tw','gov.tw','edu.tw',
        'co.kr','or.kr','ne.kr','go.kr','ac.kr','re.kr',
        'com.tr','net.tr','org.tr','gov.tr','edu.tr',
        'com.my','net.my','org.my','gov.my','edu.my',
        'com.ph','net.ph','org.ph','gov.ph','edu.ph',
        'com.pk','net.pk','org.pk','gov.pk','edu.pk',
        'com.ng','net.ng','org.ng','gov.ng','edu.ng',
        'com.gh','gov.gh','org.gh','edu.gh',
    ];
    $last2 = $labels[$n - 2] . '.' . $labels[$n - 1];
    if (in_array($last2, $known2, true)) {
        if ($n < 4) return null;
        return $labels[$n - 3] . '.' . $last2;
    }
    return $labels[$n - 2] . '.' . $labels[$n - 1];
}

function parseWhoisData(array $rawResult, array $T): array {
    $info = [
        $T['group_dates']             => [],
        $T['group_registrar_contact'] => [],
        $T['group_nameservers']       => [],
        $T['group_status']            => [],
        $T['group_dnssec']            => [],
    ];
    $patterns = [
        '/^Registry Expiry Date\s*:/i' => [$T['group_dates'], 'Expiration Date'],
        '/^Registrar Registration Expiration Date\s*:/i' => [$T['group_dates'], 'Expiration Date'],
        '/^(?:Expir(?:y|ation|es)\s*Date|paid-till|renewal[- ]?date|expire[sd]?)\s*:/i' => [$T['group_dates'], 'Expiration Date'],
        '/^(?:Registry Creation Date|Creation Date|Created(?: Date)?|Registration Time|Registered (?:on|date)|Domain Registration Date|created)\s*:/i' => [$T['group_dates'], 'Creation Date'],
        '/^(?:Updated Date|Last[- ]Modified|Last[- ]Updated?|changed|Modified)\s*:/i' => [$T['group_dates'], 'Updated Date'],
        '/^Registrar WHOIS Server\s*:/i' => [$T['group_registrar_contact'], 'Registrar WHOIS Server'],
        '/^(?:Registrar|Sponsoring Registrar|Registered by)\s*:/i' => [$T['group_registrar_contact'], 'Registrar'],
        '/^Registrar IANA ID\s*:/i' => [$T['group_registrar_contact'], 'Registrar IANA ID'],
        '/^Registrar Abuse Contact Email\s*:/i' => [$T['group_registrar_contact'], 'Abuse Email'],
        '/^Registrar Abuse Contact Phone\s*:/i' => [$T['group_registrar_contact'], 'Abuse Phone'],
        '/^Registrant Name\s*:/i' => [$T['group_registrar_contact'], 'Registrant Name'],
        '/^(?:Registrant Organization|Registrant Organisation)\s*:/i' => [$T['group_registrar_contact'], 'Registrant Org'],
        '/^Registrant Country\s*:/i' => [$T['group_registrar_contact'], 'Registrant Country'],
        '/^Registrant Email\s*:/i' => [$T['group_registrar_contact'], 'Registrant Email'],
        '/^(?:netname|OrgName|org-name|owner)\s*:/i' => [$T['group_registrar_contact'], 'Network Name'],
        '/^descr\s*:/i' => [$T['group_registrar_contact'], 'Description'],
        '/^country\s*:/i' => [$T['group_registrar_contact'], 'Country'],
        '/^(?:Admin Email|Tech Email)\s*:/i' => [$T['group_registrar_contact'], 'Contact Email'],
        '/^(?:Name Server|nserver|nameserver)\s*:/i' => [$T['group_nameservers'], null],
        '/^(?:Domain Status|Status|state)\s*:/i' => [$T['group_status'], null],
        '/^DNSSEC\s*:/i' => [$T['group_dnssec'], null],
    ];
    $seen = [];
    foreach ($rawResult as $rawLine) {
        $line = rtrim($rawLine);
        if ($line === '' || $line[0] === '%' || $line[0] === '#') continue;
        if (preg_match('/^(?:remarks?|source|nic-hdl|mnt-by|role|abuse-c|rt)\s*:/i', $line)) continue;
        if (stripos($line, '>>>') !== false || stripos($line, '<<<') !== false) continue;
        foreach ($patterns as $pattern => [$group, $label]) {
            if (!preg_match($pattern, $line)) continue;
            $value = trim(ltrim(trim(preg_replace($pattern, '', $line, 1)), ': '));
            if ($value === '' || $value === '-' || strtoupper($value) === 'REDACTED FOR PRIVACY') continue;
            if ($label === null) {
                if ($group === $T['group_nameservers']) {
                    $value = strtolower(rtrim($value, '.'));
                    $value = preg_replace('/\s+\[.*\]$/', '', $value);
                }
                if (!in_array(strtolower($value), array_map('strtolower', $info[$group]), true))
                    $info[$group][] = $value;
            } else {
                $ck = $group . '|' . $label;
                if (!isset($seen[$ck])) {
                    if ($group === $T['group_dates']) $value = normaliseDate($value);
                    $info[$group][$label] = $value;
                    $seen[$ck] = true;
                }
            }
            continue 2;
        }
    }
    if (!empty($info[$T['group_nameservers']])) sort($info[$T['group_nameservers']]);
    return $info;
}

function normaliseDate(string $raw): string {
    $raw   = trim($raw);
    $clean = preg_replace('/\s+[A-Z]{2,5}$/', '', $raw);
    $ts    = strtotime($clean);
    if ($ts !== false && $ts > 0) return gmdate('Y-m-d H:i:s', $ts) . ' UTC';
    return $raw;
}

function buildRawDataHtml(array $lines, array $T): string {
    return '<div class="raw-data-container">'
        . '<button class="details-toggle" onclick="toggleDetails(this)">' . $T['show_raw_data'] . '</button>'
        . '<div class="details-content"><pre>'
        . htmlspecialchars(implode("\n", $lines), ENT_QUOTES, 'UTF-8')
        . '</pre></div></div>';
}

function buildCopyButtonHtml(string $domain, string $lang, array $T): string {
    $url = 'index.php?lang=' . $lang . '&query=' . urlencode($domain);
    $escapedArgs = htmlspecialchars(json_encode($url), ENT_QUOTES, 'UTF-8');
    return '<div class="copy-row">'
        . '<button class="copy-link-btn" onclick="copyToClipboard(' . $escapedArgs . ', this)">'
        . '<i class="fa-solid fa-link"></i> ' . $T['copy_link_button'] . '</button>'
        . '</div>';
}

function buildSubdomainSuggestion(string $apex, string $lang, array $T): string {
    $url = htmlspecialchars('index.php?lang=' . $lang . '&query=' . urlencode($apex), ENT_QUOTES, 'UTF-8');
    return '<div class="subdomain-hint">'
        . '<i class="fa-solid fa-circle-info"></i> '
        . htmlspecialchars($T['subdomain_hint'], ENT_QUOTES, 'UTF-8') . ' '
        . '<a href="' . $url . '" class="subdomain-apex">' . htmlspecialchars($apex, ENT_QUOTES, 'UTF-8') . '</a>'
        . htmlspecialchars($T['subdomain_hint_suffix'], ENT_QUOTES, 'UTF-8')
        . ' <a href="' . $url . '" class="subdomain-search-btn">'
        . htmlspecialchars($T['subdomain_search_btn'], ENT_QUOTES, 'UTF-8')
        . '</a>'
        . '</div>';
}

function displayWhoisInfo(string $domain, string $server, array $parsedInfo, array $rawResult, array $T): void {
    global $lang;
    $copyBtn = buildCopyButtonHtml($domain, $lang, $T);
    echo '<div class="result-card">';
    echo '<div class="result-title">';
    echo '<h2><i class="fa-solid fa-circle-check" style="color:var(--clr-success)"></i> '
        . htmlspecialchars($domain, ENT_QUOTES, 'UTF-8') . ' ' . $T['domain_registered'] . '</h2>';
    echo '</div>';
    echo $copyBtn;
    echo '<p class="searched-from">' . $T['searched_from'] . ': '
        . htmlspecialchars($server, ENT_QUOTES, 'UTF-8') . '</p>';
    foreach ($parsedInfo as $groupName => $details) {
        if ($groupName === $T['group_dnssec']) {
            if (empty($details)) continue;
            $text = str_contains(strtolower(implode(' ', $details)), 'unsigned') ? 'No' : 'Yes';
            echo '<div class="info-group"><h3>' . htmlspecialchars($groupName, ENT_QUOTES, 'UTF-8')
                . '</h3><ul><li>' . $text . '</li></ul></div>';
            continue;
        }
        if (empty($details)) continue;
        echo '<div class="info-group"><h3>' . htmlspecialchars($groupName, ENT_QUOTES, 'UTF-8') . '</h3><ul>';
        if (array_is_list($details)) {
            foreach ($details as $item)
                echo '<li>' . htmlspecialchars($item, ENT_QUOTES, 'UTF-8') . '</li>';
        } else {
            foreach ($details as $k => $v)
                echo '<li><strong>' . htmlspecialchars($k, ENT_QUOTES, 'UTF-8') . ':</strong> '
                    . htmlspecialchars($v, ENT_QUOTES, 'UTF-8') . '</li>';
        }
        echo '</ul></div>';
    }
    echo buildRawDataHtml($rawResult, $T);
    echo '</div>';
}

function performWhoisQuery(string $domain, array $T): void {
    require_once __DIR__ . '/whois_servers.php';
    global $lang;
    $domainAscii = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($domainAscii === false) {
        echo '<div class="result-card"><p class="error-msg">' . $T['invalid_query'] . '</p></div>'; return;
    }
    $apexSuggestion = detectApexDomain($domain);
    $server = resolveWhoisServer($domainAscii, $whoisServers);
    if ($server === null) {
        if ($apexSuggestion !== null) {
            echo buildSubdomainSuggestion($apexSuggestion, $lang, $T);
        }
        echo '<div class="result-card"><p class="error-msg">' . $T['unsupported_tld'] . '</p></div>'; return;
    }
    $tld         = getDomainExtension($domain);
    $queryToSend = $domainAscii;
    if ($tld === 'de') $queryToSend = '-T dn,ace ' . $domainAscii;
    if ($tld === 'jp') $queryToSend = $domainAscii . '/e';
    [$rawResult, $usedServer] = resolveFullWhois($server, $queryToSend);
    if (empty($rawResult)) {
        if ($apexSuggestion !== null) echo buildSubdomainSuggestion($apexSuggestion, $lang, $T);
        echo '<div class="result-card"><p class="error-msg">' . $T['no_info_found'] . '</p></div>'; return;
    }
    $rawString     = strtolower(implode("\n", $rawResult));
    $censoredLines = censorIPsInArray($rawResult);
    $rawHtml       = buildRawDataHtml($censoredLines, $T);
    $copyBtn       = buildCopyButtonHtml($domain, $lang, $T);
    $freeKws = [
        'not found','no match','no data found','no entries found',
        'domain not found','is not registered','not exist',
        'object does not exist','no object found','status: free',
        'available for registration','this domain is not registered',
        'no information available',
    ];
    foreach ($freeKws as $kw) {
        if (str_contains($rawString, $kw)) {
            if ($apexSuggestion !== null) echo buildSubdomainSuggestion($apexSuggestion, $lang, $T);
            echo '<div class="result-card status-available">';
            echo '<div class="result-title"><h2>' . htmlspecialchars($domain, ENT_QUOTES, 'UTF-8') . '</h2></div>';
            echo $copyBtn;
            echo '<p class="status-text">' . $T['domain_available'] . '</p>';
            echo $rawHtml; echo '</div>'; return;
        }
    }
    $held = false;
    foreach ($rawResult as $line) {
        $t = strtolower(trim($line));
        if (preg_match('/^(?:domain\s+)?status\s*:/i', $t) &&
            (str_contains($t,'serverhold')||str_contains($t,'clienthold')||
             str_contains($t,'registry lock')||str_contains($t,'pendingdelete'))) {
            $held = true; break;
        }
    }
    if ($held) {
        echo '<div class="result-card status-reserved">';
        echo '<div class="result-title"><h2>' . htmlspecialchars($domain, ENT_QUOTES, 'UTF-8') . '</h2></div>';
        echo $copyBtn;
        echo '<p class="status-text">' . $T['domain_reserved'] . '</p>';
        echo $rawHtml; echo '</div>'; return;
    }
    if ($apexSuggestion !== null) echo buildSubdomainSuggestion($apexSuggestion, $lang, $T);
    $parsedInfo = parseWhoisData($censoredLines, $T);
    displayWhoisInfo($domain, $usedServer, $parsedInfo, $censoredLines, $T);
}

function performIPWhoisQuery(string $ip, array $T): void {
    $server   = getRIRServer($ip);
    $censored = censorIPsInArray(queryWhoisServer($server, $ip));
    echo '<div class="result-card">';
    if (!empty($censored) && count($censored) > 3) {
        echo '<div class="result-title"><h2>'
            . htmlspecialchars($ip, ENT_QUOTES, 'UTF-8') . ' ' . $T['whois_information'] . '</h2></div>';
        echo '<p class="searched-from">' . $T['searched_from'] . ': '
            . htmlspecialchars($server, ENT_QUOTES, 'UTF-8') . '</p>';
        echo '<div class="raw-data-wrapper"><pre>'
            . htmlspecialchars(implode("\n", $censored), ENT_QUOTES, 'UTF-8') . '</pre></div>';
    } else {
        echo '<p class="error-msg">' . $T['no_info_found'] . '</p>';
    }
    echo '</div>';
}

function performASNWhoisQuery(string $asn, array $T): void {
    $server   = 'whois.arin.net';
    $censored = censorIPsInArray(queryWhoisServer($server, $asn));
    echo '<div class="result-card">';
    if (!empty($censored) && count($censored) > 3) {
        echo '<div class="result-title"><h2>'
            . htmlspecialchars(strtoupper($asn), ENT_QUOTES, 'UTF-8') . ' ' . $T['whois_information'] . '</h2></div>';
        echo '<p class="searched-from">' . $T['searched_from'] . ': '
            . htmlspecialchars($server, ENT_QUOTES, 'UTF-8') . '</p>';
        echo '<div class="raw-data-wrapper"><pre>'
            . htmlspecialchars(implode("\n", $censored), ENT_QUOTES, 'UTF-8') . '</pre></div>';
    } else {
        echo '<p class="error-msg">' . $T['no_info_found'] . '</p>';
    }
    echo '</div>';
}

$current_query = '';
if (!empty($_POST['query']))    $current_query = sanitizeQuery($_POST['query']);
elseif (!empty($_GET['query'])) $current_query = sanitizeQuery($_GET['query']);
?>
<!DOCTYPE html>
<html lang="<?php echo $lang; ?>">
<head>
    <meta charset="UTF-8">
    <title><?php echo htmlspecialchars($T['page_title'], ENT_QUOTES, 'UTF-8'); ?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="<?php echo htmlspecialchars($T['meta_description'], ENT_QUOTES, 'UTF-8'); ?>">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <link rel="stylesheet" href="./style.css">
    <link rel="shortcut icon" href="https://cdn.807070.xyz/img/new/2023/01/14/63c2a68d3bb10.png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
</head>
<body>

<header>
    <div class="header-content">
        <h2><i class="fa-solid fa-globe"></i> <?php echo htmlspecialchars($T['header_title'], ENT_QUOTES, 'UTF-8'); ?></h2>
        <div class="header-actions">
            <button id="theme-toggle" class="icon-btn" aria-label="Toggle dark mode">
                <i class="fa-solid fa-moon" id="theme-icon"></i>
            </button>
            <div class="language-switcher">
                <?php $suffix = !empty($current_query) ? '&query=' . urlencode($current_query) : ''; ?>
                <a href="<?php echo htmlspecialchars('?lang=en' . $suffix, ENT_QUOTES, 'UTF-8'); ?>"
                   <?php if ($lang === 'en') echo 'class="active"'; ?>>EN</a>
                <a href="<?php echo htmlspecialchars('?lang=zh' . $suffix, ENT_QUOTES, 'UTF-8'); ?>"
                   <?php if ($lang === 'zh') echo 'class="active"'; ?>>中文</a>
            </div>
            <a href="api.php?lang=<?php echo $lang; ?>" class="api-badge" target="_blank" rel="noopener">
                <i class="fa-solid fa-code"></i> API
            </a>
        </div>
    </div>
</header>

<main>
    <div class="search-card">
        <form method="post" action="?lang=<?php echo $lang; ?>">
            <div class="input-wrapper">
                <i class="fa-solid fa-magnifying-glass"></i>
                <input type="text" name="query"
                       placeholder="<?php echo htmlspecialchars($T['placeholder'], ENT_QUOTES, 'UTF-8'); ?>"
                       required autocomplete="off" spellcheck="false" maxlength="253"
                       value="<?php echo htmlspecialchars($current_query, ENT_QUOTES, 'UTF-8'); ?>">
            </div>
            <button type="submit" class="submit-button">
                <i class="fa-solid fa-magnifying-glass"></i>
                <?php echo $T['search_button']; ?>
            </button>
        </form>
    </div>

    <?php
    if ($current_query !== '') {
        $asciiQ = idn_to_ascii($current_query, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        $isIPv4 = filter_var($current_query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $isIPv6 = filter_var($current_query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        $isASN  = (bool) preg_match('/^AS\d{1,10}$/i', $current_query);
        if ($isIPv4 || $isIPv6) {
            performIPWhoisQuery($current_query, $T);
        } elseif ($isASN) {
            performASNWhoisQuery($current_query, $T);
        } elseif ($asciiQ !== false
                  && filter_var($asciiQ, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
                  && substr_count($asciiQ, '.') >= 1) {
            performWhoisQuery($current_query, $T);
        } else {
            echo '<div class="result-card"><p class="error-msg">' . $T['invalid_query'] . '</p></div>';
        }
    }
    ?>

    <div class="actions-container">
        <button id="toggle-guides-btn" class="secondary-button"></button>
    </div>

    <div id="guides-container">
        <div class="illustrate-card">
            <div class="card-header">
                <h3><?php echo htmlspecialchars($T['guide_title'], ENT_QUOTES, 'UTF-8'); ?></h3>
            </div>
            <ol>
                <li><?php echo $T['guide_step1']; ?></li>
                <li><?php echo $T['guide_step2']; ?></li>
                <li><?php echo $T['guide_step3']; ?></li>
                <li><?php echo $T['guide_step4']; ?></li>
                <li><?php echo $T['guide_step5']; ?></li>
                <li><?php echo $T['guide_step6']; ?></li>
            </ol>
        </div>
    </div>

    <div class="history-card">
        <div class="history-header">
            <h3><?php echo htmlspecialchars($T['history_records_title'], ENT_QUOTES, 'UTF-8'); ?></h3>
            <button class="clear-button" onclick="clearHistory()">
                <?php echo htmlspecialchars($T['clear_history_button'], ENT_QUOTES, 'UTF-8'); ?>
            </button>
        </div>
        <p class="history-info"><?php echo htmlspecialchars($T['history_info'], ENT_QUOTES, 'UTF-8'); ?></p>
        <ul id="history-list"></ul>
    </div>
</main>

<footer>
    <p><?php echo $T['footer_text']; ?>
        | <a href="api.php?lang=<?php echo $lang; ?>"><?php echo $T['footer_api_link']; ?></a>
        | <a href="https://github.com/iezx/Super-Whois" target="_blank" rel="noopener noreferrer"><?php echo $T['footer_github']; ?></a>
    </p>
</footer>

<script>
document.addEventListener('DOMContentLoaded', () => {
    const ThemeKey  = 'superWhoisTheme';
    const themeBtn  = document.getElementById('theme-toggle');
    const themeIcon = document.getElementById('theme-icon');
    function applyTheme(dark) {
        document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
        themeIcon.className = dark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
        try { localStorage.setItem(ThemeKey, dark ? 'dark' : 'light'); } catch(e) {}
    }
    (() => {
        let s = null; try { s = localStorage.getItem(ThemeKey); } catch(e) {}
        applyTheme(s ? s === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches);
    })();
    themeBtn.addEventListener('click', () =>
        applyTheme(document.documentElement.getAttribute('data-theme') !== 'dark'));

    const App = {
        guidesContainer: document.getElementById('guides-container'),
        toggleBtn:       document.getElementById('toggle-guides-btn'),
        historyList:     document.getElementById('history-list'),
        queryInput:      document.querySelector('input[name="query"]'),
        form:            document.querySelector('form'),
        guidesVisible:   true,
        historyKey:      'superWhoisHistory_v2',
        text: {
            showGuides: <?php echo json_encode($T['toggle_guides_button']); ?>,
            hideGuides: <?php echo json_encode($T['hide_guides_button']); ?>,
            showRaw:    <?php echo json_encode($T['show_raw_data']); ?>,
            hideRaw:    <?php echo json_encode($T['hide_raw_data']); ?>,
            noHistory:  <?php echo json_encode($T['no_history']); ?>,
            clickHint:  <?php echo json_encode($T['history_click_hint']); ?>,
            copied:     <?php echo json_encode($T['copied_feedback']); ?>,
            copyFailed: <?php echo json_encode($T['copy_failed']); ?>,
        },
        init() { this.bindEvents(); this.updateUIVisibility(); this.loadHistory(); },
        bindEvents() {
            this.toggleBtn.addEventListener('click', () => {
                this.guidesVisible = !this.guidesVisible;
                this.updateUIVisibility();
            });
            this.form.addEventListener('submit', () => {
                const q = this.queryInput.value.trim();
                if (q) this.saveHistory(q);
            });
        },
        updateUIVisibility() {
            this.guidesContainer.classList.toggle('is-hidden', !this.guidesVisible);
            this.toggleBtn.textContent = this.guidesVisible ? this.text.hideGuides : this.text.showGuides;
        },
        loadHistory() {
            let h = [];
            try { h = JSON.parse(localStorage.getItem(this.historyKey) || '[]'); } catch(e) {}
            if (!Array.isArray(h)) h = [];
            this.historyList.innerHTML = '';
            if (h.length === 0) {
                this.historyList.innerHTML = `<li class="no-history">${this.text.noHistory}</li>`;
                return;
            }
            h.slice(-10).reverse().forEach(item => {
                const li = document.createElement('li');
                li.className   = 'history-item';
                li.textContent = item;
                li.title       = this.text.clickHint;
                li.onclick     = () => {
                    this.queryInput.value = item;
                    this.saveHistory(item);
                    this.form.submit();
                };
                this.historyList.appendChild(li);
            });
        },
        saveHistory(q) {
            q = q.trim().toLowerCase();
            if (!q) return;
            let h = [];
            try { h = JSON.parse(localStorage.getItem(this.historyKey) || '[]'); } catch(e) {}
            if (!Array.isArray(h)) h = [];
            h = h.filter(i => i !== q);
            h.push(q);
            if (h.length > 20) h.splice(0, h.length - 20);
            try { localStorage.setItem(this.historyKey, JSON.stringify(h)); } catch(e) {}
        },
    };

    window.copyToClipboard = (path, btn) => {
        const url  = new URL(path, window.location.href).href;
        const orig = btn.innerHTML;

        const succeed = () => {
            btn.textContent = App.text.copied;
            btn.disabled    = true;
            setTimeout(() => { btn.innerHTML = orig; btn.disabled = false; }, 2000);
        };

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(url).then(succeed).catch(() => fallback(url, succeed));
        } else {
            fallback(url, succeed);
        }
    };

    function fallback(text, onSuccess) {
        const ta = document.createElement('textarea');
        ta.value     = text;
        ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        try {
            if (document.execCommand('copy')) { onSuccess(); }
            else { alert(App.text.copyFailed + '\n' + text); }
        } catch(e) {
            alert(App.text.copyFailed + '\n' + text);
        }
        document.body.removeChild(ta);
    }

    window.toggleDetails = btn => {
        const c = btn.nextElementSibling;
        const v = c.style.display === 'block';
        c.style.display = v ? 'none' : 'block';
        btn.textContent = v ? App.text.showRaw : App.text.hideRaw;
    };

    window.clearHistory = () => {
        try { localStorage.removeItem(App.historyKey); } catch(e) {}
        App.loadHistory();
    };

    App.init();
});
</script>
</body>
</html>