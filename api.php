<?php
define('API_RATE_LIMIT',            30);
define('API_RATE_WINDOW',           3600);
define('API_RATE_STORE',            __DIR__ . '/api_rate_store');
define('API_KEYS_FILE',             __DIR__ . '/api_keys.php');
define('API_ALLOW_UNAUTHENTICATED', true);
define('API_MAX_QUERY_LENGTH',      253);
define('API_VERSION',               'V1.0');


define('API_TRUST_PROXY_HEADERS',   true); 


ini_set('pcre.backtrack_limit', '100000');

if (!function_exists('idn_to_ascii')) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Server error: intl extension missing.', 'code' => 500]);
    exit();
}

require_once __DIR__ . '/languages.php';

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

if (!isset($_GET['q']) || trim($_GET['q']) === '') {
    header('Content-Type: text/html; charset=UTF-8');
    renderApiDocs($T, $lang);
    exit();
}

header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex');

$providedKey     = isset($_GET['key']) ? trim($_GET['key']) : '';
$isAuthenticated = false;
if ($providedKey !== '' && file_exists(API_KEYS_FILE)) {
    $apiKeys = [];
    require API_KEYS_FILE;
    if (in_array($providedKey, $apiKeys, true)) $isAuthenticated = true;
}

if (!$isAuthenticated && !API_ALLOW_UNAUTHENTICATED) {
    apiError(401, 'Unauthorized. A valid API key is required.');
}

if (!$isAuthenticated) enforceRateLimit();

$query = sanitizeApiQuery(trim($_GET['q']));
if ($query === '') apiError(400, 'Invalid or empty query.');

$T_en   = get_language_strings('en');  
$result = dispatchQuery($query, $T_en);
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
exit();




function getClientIP(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    

    if (API_TRUST_PROXY_HEADERS) {
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
    $dir = API_RATE_STORE;
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    
    $ip   = getClientIP();
    $key  = preg_replace('/[^a-z0-9.:]/i', '_', strtolower($ip));
    $file = $dir . '/' . $key . '.json';
    $now  = time();
    

    $fp = fopen($file, 'c+');
    if (!$fp) {
        apiError(500, 'Internal Server Error: Rate limit storage unavaiable.');
    }
    
    flock($fp, LOCK_EX); 
    
    $size = filesize($file);
    $raw  = $size > 0 ? fread($fp, $size) : '';
    $data = json_decode($raw, true) ?: ['count' => 0, 'reset' => $now + API_RATE_WINDOW];
    
    if ($now > $data['reset'] || !isset($data['count'])) {
        $data = ['count' => 0, 'reset' => $now + API_RATE_WINDOW];
    }
    
    $data['count']++;
    

    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    
    header('X-RateLimit-Limit: '     . API_RATE_LIMIT);
    header('X-RateLimit-Remaining: ' . max(0, API_RATE_LIMIT - $data['count']));
    header('X-RateLimit-Reset: '     . $data['reset']);
    
    if ($data['count'] > API_RATE_LIMIT) {
        apiError(429, 'Rate limit exceeded. Max ' . API_RATE_LIMIT
            . ' requests/hour. Retry after ' . date('Y-m-d H:i:s', $data['reset']) . ' UTC.');
    }
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

function qWS(string $serverDomain, string $query): array {

    $safeIP = getSafeWhoisIP($serverDomain);
    if (!$safeIP) return [];


    $sock = @fsockopen($safeIP, 43, $e, $es, 5); 
    if (!$sock) return [];
    
    stream_set_timeout($sock, 5);
    fwrite($sock, $query . "\r\n");
    
    $raw = '';
    while (!feof($sock)) {
        $c = fgets($sock, 4096);
        if ($c === false) break;
        $raw .= $c;
        if (strlen($raw) > 524288) break; 
    }
    fclose($sock);
    return explode("\n", $raw);
}

function sanitizeApiQuery(string $input): string {
    $q = trim($input);
    $q = preg_replace('/^https?:\/\//i', '', $q);
    $q = explode('/', $q, 2)[0];
    $q = preg_replace('/:\d+$/', '', $q);
    $q = preg_replace('/\s+/', '', $q);
    return substr($q, 0, API_MAX_QUERY_LENGTH);
}

function apiError(int $code, string $message): void {
    http_response_code($code);
    echo json_encode(['error' => $message, 'code' => $code]);
    exit();
}

function resolveFullWS(string $server, string $query): array {
    $lines = qWS($server, $query);
    if (empty($lines)) return [$lines, $server];
    foreach ($lines as $line) {
        if (preg_match('/^Registrar WHOIS Server\s*:\s*(.+)$/i', trim($line), $m)) {
            $c = strtolower(trim($m[1]));
            if ($c !== '' && strtolower($c) !== strtolower($server)) {
                $full = qWS($c, $query);
                if (count($full) > 5) return [$full, $c];
                break;
            }
        }
    }
    return [$lines, $server];
}

function resolveWS(string $domainAscii, array $whoisServers): ?string {
    $labels = explode('.', strtolower($domainAscii));
    $n      = count($labels);
    if ($n >= 2) {
        $sld = $labels[$n-2] . '.' . $labels[$n-1];
        if (isset($whoisServers[$sld])) return $whoisServers[$sld];
    }
    return $whoisServers[$labels[$n-1]] ?? null;
}

function getRIR(string $ip): string {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'whois.arin.net';
    $l = ip2long($ip);
    $r = fn($a,$b) => $l >= ip2long($a) && $l <= ip2long($b);
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

function censorAPI(array $lines): array {
    $p = '/(\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9:.]+\b)/i';
    return array_map(fn($l) => preg_replace($p, '[REDACTED]', $l), $lines);
}

function parseForAPI(array $rawResult): array {
    $info = [
        'creation_date'     => null, 'expiration_date'   => null,
        'updated_date'      => null, 'registrar'         => null,
        'registrar_iana_id' => null, 'registrar_whois'   => null,
        'abuse_email'       => null, 'abuse_phone'       => null,
        'registrant_name'   => null, 'registrant_org'    => null,
        'registrant_country'=> null, 'registrant_email'  => null,
        'nameservers'       => [],   'status'            => [],
        'dnssec'            => null,
    ];
    $patterns = [
        '/^Registry Expiry Date\s*:/i'                                                 => ['expiration_date', true],
        '/^Registrar Registration Expiration Date\s*:/i'                               => ['expiration_date', true],
        '/^(?:Expir(?:y|ation|es)\s*Date|paid-till|expire[sd]?|renewal[- ]?date)\s*:/i' => ['expiration_date', true],
        '/^(?:Registry Creation Date|Creation Date|Created(?: Date)?|Registration Time|Registered (?:on|date)|created)\s*:/i' => ['creation_date', true],
        '/^(?:Updated Date|Last[- ]Modified|Last[- ]Updated?|changed|Modified)\s*:/i' => ['updated_date', true],
        '/^Registrar WHOIS Server\s*:/i'          => ['registrar_whois',    true],
        '/^(?:Registrar|Sponsoring Registrar)\s*:/i' => ['registrar',        true],
        '/^Registrar IANA ID\s*:/i'               => ['registrar_iana_id',  true],
        '/^Registrar Abuse Contact Email\s*:/i'   => ['abuse_email',        true],
        '/^Registrar Abuse Contact Phone\s*:/i'   => ['abuse_phone',        true],
        '/^Registrant Name\s*:/i'                 => ['registrant_name',    true],
        '/^(?:Registrant Organization|Registrant Organisation)\s*:/i' => ['registrant_org', true],
        '/^Registrant Country\s*:/i'              => ['registrant_country', true],
        '/^Registrant Email\s*:/i'                => ['registrant_email',   true],
        '/^(?:OrgName|netname|org-name|owner)\s*:/i' => ['registrant_org',  true],
        '/^country\s*:/i'                         => ['registrant_country', true],
        '/^(?:Name Server|nserver|nameserver)\s*:/i' => ['nameservers',     false],
        '/^(?:Domain Status|Status|state)\s*:/i'  => ['status',             false],
        '/^DNSSEC\s*:/i'                          => ['dnssec',             true],
    ];
    $seen = [];
    foreach ($rawResult as $rawLine) {
        $line = rtrim($rawLine);
        if ($line === '' || $line[0] === '%' || $line[0] === '#') continue;
        if (preg_match('/^(?:remarks?|source|nic-hdl|mnt-by|role|abuse-c|rt)\s*:/i', $line)) continue;
        if (stripos($line, '>>>') !== false) continue;
        foreach ($patterns as $pattern => [$field, $single]) {
            if (!preg_match($pattern, $line)) continue;
            $value = trim(ltrim(trim(preg_replace($pattern, '', $line, 1)), ': '));
            if ($value === '' || $value === '-' || strtoupper($value) === 'REDACTED FOR PRIVACY') continue;
            if (!$single) {
                if ($field === 'nameservers') $value = strtolower(rtrim($value, '.'));
                if (!in_array(strtolower($value), array_map('strtolower', $info[$field]), true))
                    $info[$field][] = $value;
            } else {
                if (!isset($seen[$field])) {
                    if (in_array($field, ['creation_date','expiration_date','updated_date'])) {
                        $clean = preg_replace('/\s+[A-Z]{2,5}$/', '', $value);
                        $ts    = strtotime($clean);
                        if ($ts !== false && $ts > 0) $value = gmdate('Y-m-d\TH:i:s\Z', $ts);
                    }
                    $info[$field] = $value;
                    $seen[$field] = true;
                }
            }
            continue 2;
        }
    }
    if (!empty($info['nameservers'])) sort($info['nameservers']);
    if ($info['dnssec'] !== null)
        $info['dnssec'] = str_contains(strtolower($info['dnssec']), 'unsigned') ? 'unsigned' : 'signed';
    return array_filter($info, fn($v) => $v !== null && $v !== []);
}

function dispatchQuery(string $query, array $T): array {
    $base = [
        'query'        => $query,
        'query_type'   => '',
        'whois_server' => '',
        'status'       => '',
        'timestamp'    => gmdate('Y-m-d\TH:i:s\Z'),
        'api_version'  => API_VERSION,
    ];
    $isIPv4 = filter_var($query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    $isIPv6 = filter_var($query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    $isASN  = (bool) preg_match('/^AS\d{1,10}$/i', $query);
    $asciiQ = idn_to_ascii($query, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);

    if ($isIPv4 || $isIPv6) {
        $base['query_type']   = $isIPv6 ? 'ipv6' : 'ipv4';
        $server               = getRIR($query);
        $raw                  = qWS($server, $query);
        if (count($raw) < 3) { $base['status'] = 'error'; $base['error'] = 'No data returned.'; return $base; }
        $base['status']       = 'found';
        $base['whois_server'] = $server;
        $base['raw']          = implode("\n", censorAPI($raw));
        return $base;

    } elseif ($isASN) {
        $base['query_type']   = 'asn';
        $server               = 'whois.arin.net';
        $raw                  = qWS($server, strtoupper($query));
        if (count($raw) < 3) { $base['status'] = 'error'; $base['error'] = 'No data returned.'; return $base; }
        $base['status']       = 'found';
        $base['whois_server'] = $server;
        $base['raw']          = implode("\n", censorAPI($raw));
        return $base;

    } elseif ($asciiQ !== false
              && filter_var($asciiQ, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
              && substr_count($asciiQ, '.') >= 1) {

        $base['query_type'] = 'domain';

        $apexLabels = explode('.', strtolower($asciiQ));
        $an         = count($apexLabels);
        $known2Api  = ['co.uk','org.uk','com.au','net.au','org.au','com.cn','net.cn','org.cn',
                       'co.jp','com.br','net.br','com.mx','com.ar','com.sg','com.hk','com.tw',
                       'co.kr','com.tr','com.my','co.nz','co.in','co.za'];
        $last2Api   = $an >= 2 ? ($apexLabels[$an-2] . '.' . $apexLabels[$an-1]) : '';
        if (in_array($last2Api, $known2Api, true) && $an >= 4) {
            $base['subdomain_suggestion'] = $apexLabels[$an-3] . '.' . $last2Api;
        } elseif (!in_array($last2Api, $known2Api, true) && $an >= 3) {
            $base['subdomain_suggestion'] = $apexLabels[$an-2] . '.' . $apexLabels[$an-1];
        }

        require_once __DIR__ . '/whois_servers.php';
        $server = resolveWS($asciiQ, $whoisServers);
        if ($server === null) {
            $base['status'] = 'unsupported_tld';
            $base['error']  = 'No WHOIS server known for this TLD.';
            return $base;
        }
        $tld = strtolower(end(explode('.', $asciiQ)));
        $q2  = $asciiQ;
        if ($tld === 'de') $q2 = '-T dn,ace ' . $asciiQ;
        if ($tld === 'jp') $q2 = $asciiQ . '/e';

        [$rawLines, $usedServer] = resolveFullWS($server, $q2);
        $base['whois_server']    = $usedServer;
        if (empty($rawLines)) {
            $base['status'] = 'error'; $base['error'] = 'Could not reach WHOIS server.'; return $base;
        }
        $rawString = strtolower(implode("\n", $rawLines));
        $freeKws = ['not found','no match','no data found','no entries found',
                    'domain not found','is not registered','not exist',
                    'object does not exist','status: free',
                    'available for registration','this domain is not registered'];
        foreach ($freeKws as $kw) {
            if (str_contains($rawString, $kw)) { $base['status'] = 'available'; return $base; }
        }
        $censored       = censorAPI($rawLines);
        $base['status'] = 'registered';
        $base['data']   = parseForAPI($censored);
        $base['raw']    = implode("\n", $censored);
        return $base;

    } else {
        apiError(400, 'Invalid query. Please supply a valid domain, IP, or ASN (e.g. AS15169).');
    }
}

function renderApiDocs(array $T, string $lang): void {
    $authNote = API_ALLOW_UNAUTHENTICATED ? $T['api_auth_public'] : $T['api_auth_protected'];
    $rateNote = sprintf($T['api_rate_note'], API_RATE_LIMIT);
    $h = fn(string $s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');

    $scheme   = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host     = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $host     = preg_replace('/:(80|443)$/', '', $host);
    if (!preg_match('/^[a-zA-Z0-9\[\]:\.\-]+$/', $host)) $host = 'your-domain.com';
    $basePath = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/\\');
    $baseUrl  = $scheme . '://' . $host . ($basePath !== '' && $basePath !== '/' ? $basePath : '') . '/api.php';
?>
<!DOCTYPE html>
<html lang="<?php echo $lang; ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $h($T['api_page_title']); ?></title>
    <link rel="stylesheet" href="./style.css">
    <link rel="shortcut icon" href="https://cdn.807070.xyz/img/new/2023/01/14/63c2a68d3bb10.png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        .api-hero{text-align:center;padding:36px 0 16px}
        .api-hero h1{font-size:30px;font-weight:800;color:var(--clr-primary);letter-spacing:-.03em}
        .api-hero p{color:var(--clr-text-secondary);margin-top:8px}
        .api-badge-large{display:inline-flex;align-items:center;gap:8px;background:var(--clr-primary);
            color:#fff;padding:6px 16px;border-radius:99px;font-size:13px;font-weight:700;
            letter-spacing:.04em;margin-top:12px;text-decoration:none}
        .doc-section{margin-top:4px}
        .doc-section > .card-header h2{font-size:15px;font-weight:700;color:var(--clr-text);
            border-bottom:2px solid var(--clr-border);padding-bottom:8px;margin-bottom:14px;
            letter-spacing:.01em}
        .endpoint-box{background:var(--clr-code-bg);border:1px solid var(--clr-border);
            border-radius:var(--radius-md);padding:14px 18px;font-family:var(--font-mono);
            font-size:13px;margin-bottom:10px;overflow-x:auto}
        .endpoint-box .method{color:var(--clr-primary);font-weight:700;margin-right:10px}
        .param-table{width:100%;border-collapse:collapse;font-size:14px}
        .param-table th{text-align:left;padding:8px 12px;font-size:11px;font-weight:700;
            letter-spacing:.06em;text-transform:uppercase;color:var(--clr-text-muted);
            background:var(--clr-code-bg);border-bottom:1px solid var(--clr-border)}
        .param-table td{padding:9px 12px;border-bottom:1px solid var(--clr-border-light);vertical-align:top}
        .param-table tr:last-child td{border-bottom:none}
        .badge-req{background:#fee2e2;color:#b91c1c;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}
        .badge-opt{background:#e0f2fe;color:#0369a1;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}
        .json-block{background:var(--clr-code-bg);border:1px solid var(--clr-border);
            border-radius:var(--radius-md);padding:14px 18px;font-family:var(--font-mono);
            font-size:12.5px;line-height:1.75;overflow-x:auto;white-space:pre;
            color:var(--clr-text-secondary);max-height:420px;overflow-y:auto}
        .try-box{display:flex;gap:10px;flex-wrap:wrap}
        .try-input{flex:1;min-width:180px;height:40px;padding:0 14px;
            border:1.5px solid var(--clr-border);border-radius:var(--radius-sm);
            font-size:14px;background:var(--clr-surface);color:var(--clr-text);
            font-family:var(--font-mono)}
        .try-input:focus{border-color:var(--clr-primary);outline:none}
        .try-btn{height:40px;padding:0 18px;background:var(--clr-primary);color:#fff;
            border:none;border-radius:var(--radius-sm);font-weight:700;cursor:pointer;font-size:14px}
        .try-btn:hover{background:var(--clr-primary-dark)}
        #try-result{margin-top:10px;display:none}
        .response-status{font-size:12px;font-weight:700;margin-bottom:6px}
        .status-ok{color:var(--clr-success)}.status-err{color:var(--clr-danger)}
        .back-link{display:inline-flex;align-items:center;gap:6px;color:var(--clr-text-secondary);
            text-decoration:none;font-size:13px;font-weight:500;margin-bottom:14px}
        .back-link:hover{color:var(--clr-primary)}
        .sub-heading{font-size:14px;font-weight:700;margin:14px 0 6px;color:var(--clr-text)}
    </style>
</head>
<body>

<header>
    <div class="header-content">
        <h2><i class="fa-solid fa-globe"></i> <?php echo $h($T['header_title']); ?></h2>
        <div class="header-actions">
            <button id="theme-toggle" class="icon-btn" aria-label="Toggle dark mode">
                <i class="fa-solid fa-moon" id="theme-icon"></i>
            </button>
            <div class="language-switcher">
                <a href="?lang=en" <?php if ($lang === 'en') echo 'class="active"'; ?>>EN</a>
                <a href="?lang=zh" <?php if ($lang === 'zh') echo 'class="active"'; ?>>中文</a>
            </div>
        </div>
    </div>
</header>

<main>
    <a href="index.php?lang=<?php echo $lang; ?>" class="back-link">
        <i class="fa-solid fa-arrow-left"></i> <?php echo $h($T['api_back_link']); ?>
    </a>

    <div class="api-hero">
        <h1><?php echo $h($T['api_hero_title']); ?></h1>
        <p><?php echo $h($T['api_hero_subtitle']); ?></p>
        <span class="api-badge-large"><i class="fa-solid fa-code"></i> v<?php echo API_VERSION; ?></span>
    </div>

    <div class="illustrate-card doc-section">
        <div class="card-header"><h2><?php echo $h($T['api_section_base_url']); ?></h2></div>
        <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?></div>
    </div>

    <div class="illustrate-card doc-section">
        <div class="card-header"><h2><?php echo $h($T['api_section_auth']); ?></h2></div>
        <p style="font-size:14px;margin-bottom:12px"><?php echo $authNote; ?></p>
        <div class="endpoint-box"><span class="method">GET</span>api.php?q=google.com&amp;key=YOUR_API_KEY</div>
        <p style="font-size:13px;color:var(--clr-text-muted);margin-bottom:6px"><?php echo $T['api_auth_keys_note']; ?></p>
        <div class="json-block">&lt;?php
$apiKeys = [
    'sk_live_your_secret_key_here',
    'sk_live_another_key',
];</div>
    </div>

    <div class="illustrate-card doc-section">
        <div class="card-header"><h2><?php echo $h($T['api_section_rate']); ?></h2></div>
        <p style="font-size:14px;margin-bottom:12px"><?php echo $rateNote; ?></p>
        <table class="param-table">
            <tr>
                <th><?php echo $h($T['api_rate_header_name']); ?></th>
                <th><?php echo $h($T['api_rate_header_desc']); ?></th>
            </tr>
            <tr><td><code>X-RateLimit-Limit</code></td><td><?php echo $h($T['api_rate_limit_label']); ?></td></tr>
            <tr><td><code>X-RateLimit-Remaining</code></td><td><?php echo $h($T['api_rate_remaining_label']); ?></td></tr>
            <tr><td><code>X-RateLimit-Reset</code></td><td><?php echo $h($T['api_rate_reset_label']); ?></td></tr>
        </table>
    </div>

    <div class="illustrate-card doc-section">
        <div class="card-header"><h2><?php echo $h($T['api_section_params']); ?></h2></div>
        <table class="param-table">
            <tr>
                <th><?php echo $h($T['api_param_name']); ?></th>
                <th><?php echo $h($T['api_param_required']); ?></th>
                <th><?php echo $h($T['api_param_desc']); ?></th>
            </tr>
            <tr>
                <td><code>q</code></td>
                <td><span class="badge-req"><?php echo $h($T['api_param_required']); ?></span></td>
                <td><?php echo $T['api_param_q_desc']; ?></td>
            </tr>
            <tr>
                <td><code>key</code></td>
                <td><span class="badge-opt"><?php echo $lang === 'zh' ? '可选' : 'Optional'; ?></span></td>
                <td><?php echo $T['api_param_key_desc']; ?></td>
            </tr>
            <tr>
                <td><code>lang</code></td>
                <td><span class="badge-opt"><?php echo $lang === 'zh' ? '可选' : 'Optional'; ?></span></td>
                <td><?php echo $lang === 'zh' ? '文档语言：<code>en</code>（默认）或 <code>zh</code>' : 'Docs language: <code>en</code> (default) or <code>zh</code>'; ?></td>
            </tr>
        </table>
    </div>

    <div class="illustrate-card doc-section">
        <div class="card-header"><h2><?php echo $h($T['api_section_endpoints']); ?></h2></div>
        <p class="sub-heading"><?php echo $h($T['api_endpoint_domain']); ?></p>
        <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?>?q=google.com</div>
        <p class="sub-heading"><?php echo $h($T['api_endpoint_ip']); ?></p>
        <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?>?q=8.8.8.8</div>
        <p class="sub-heading"><?php echo $h($T['api_endpoint_asn']); ?></p>
        <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?>?q=AS15169</div>
    </div>

    <div class="illustrate-card doc-section">
        <div class="card-header"><h2><?php echo $h($T['api_section_response']); ?></h2></div>
        <table class="param-table">
            <tr><th><?php echo $lang === 'zh' ? '字段' : 'Field'; ?></th><th><?php echo $lang === 'zh' ? '类型' : 'Type'; ?></th><th><?php echo $lang === 'zh' ? '说明' : 'Description'; ?></th></tr>
            <tr><td><code>query</code></td><td>string</td><td><?php echo $h($T['api_field_query']); ?></td></tr>
            <tr><td><code>query_type</code></td><td>string</td><td><?php echo $T['api_field_query_type']; ?></td></tr>
            <tr><td><code>status</code></td><td>string</td><td><?php echo $T['api_field_status']; ?></td></tr>
            <tr><td><code>whois_server</code></td><td>string</td><td><?php echo $T['api_field_whois_server']; ?></td></tr>
            <tr><td><code>timestamp</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_timestamp']); ?></td></tr>
            <tr><td><code>data</code></td><td>object</td><td><?php echo $T['api_field_data']; ?></td></tr>
            <tr><td><code>data.creation_date</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_creation']); ?></td></tr>
            <tr><td><code>data.expiration_date</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_expiration']); ?></td></tr>
            <tr><td><code>data.updated_date</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_updated']); ?></td></tr>
            <tr><td><code>data.registrar</code></td><td>string</td><td><?php echo $h($T['api_field_registrar']); ?></td></tr>
            <tr><td><code>data.nameservers</code></td><td>array</td><td><?php echo $h($T['api_field_nameservers']); ?></td></tr>
            <tr><td><code>data.status</code></td><td>array</td><td><?php echo $h($T['api_field_statuses']); ?></td></tr>
            <tr><td><code>data.dnssec</code></td><td>string</td><td><?php echo $h($T['api_field_dnssec']); ?></td></tr>
            <tr><td><code>raw</code></td><td>string</td><td><?php echo $h($T['api_field_raw']); ?></td></tr>
            <tr><td><code>subdomain_suggestion</code></td><td>string</td><td><?php echo $lang === 'zh' ? '若查询的是子域名，此字段返回建议查询的顶级域名（如查询 blog.example.com 时返回 example.com）' : 'If the query appears to be a subdomain, contains the suggested apex domain to look up instead (e.g. querying blog.example.com returns example.com)'; ?></td></tr>
        </table>
    </div>

    <div class="illustrate-card doc-section">
        <div class="card-header"><h2><?php echo $h($T['api_section_sample']); ?> — <code>api.php?q=google.com</code></h2></div>
        <div class="json-block">{
  "query": "google.com",
  "query_type": "domain",
  "whois_server": "whois.markmonitor.com",
  "status": "registered",
  "timestamp": "2024-11-15T10:23:45Z",
  "api_version": "1.0",
  "data": {
    "creation_date": "1997-09-15T04:00:00Z",
    "expiration_date": "2028-09-14T04:00:00Z",
    "updated_date": "2019-09-09T15:39:04Z",
    "registrar": "MarkMonitor Inc.",
    "registrar_iana_id": "292",
    "registrar_whois": "whois.markmonitor.com",
    "nameservers": ["ns1.google.com","ns2.google.com","ns3.google.com","ns4.google.com"],
    "status": ["clientDeleteProhibited ...","clientTransferProhibited ..."],
    "dnssec": "unsigned"
  },
  "raw": "Domain Name: GOOGLE.COM\r\n..."
}</div>
    </div>

    <div class="illustrate-card doc-section">
        <div class="card-header"><h2><?php echo $h($T['api_section_errors']); ?></h2></div>
        <table class="param-table">
            <tr><th>HTTP</th><th><?php echo $h($T['api_error_meaning']); ?></th></tr>
            <tr><td><code>400</code></td><td><?php echo $T['api_error_400']; ?></td></tr>
            <tr><td><code>401</code></td><td><?php echo $T['api_error_401']; ?></td></tr>
            <tr><td><code>429</code></td><td><?php echo $T['api_error_429']; ?></td></tr>
            <tr><td><code>500</code></td><td><?php echo $T['api_error_500']; ?></td></tr>
        </table>
    </div>

    <div class="illustrate-card doc-section">
        <div class="card-header"><h2><?php echo $h($T['api_section_try']); ?></h2></div>
        <div class="try-box">
            <input type="text" class="try-input" id="try-input"
                   placeholder="google.com, 8.8.8.8, AS15169" value="google.com">
            <button class="try-btn" onclick="runTry()">
                <i class="fa-solid fa-play"></i> <?php echo $h($T['api_try_send']); ?>
            </button>
        </div>
        <div id="try-result">
            <p class="response-status" id="try-status"></p>
            <div class="json-block" id="try-output"></div>
        </div>
    </div>

    <div class="illustrate-card doc-section">
        <div class="card-header"><h2><?php echo $h($T['api_section_examples']); ?></h2></div>

        <p class="sub-heading"><?php echo $h($T['api_example_js']); ?></p>
        <div class="json-block">fetch(<?php echo json_encode($baseUrl . '?q=google.com'); ?>)
  .then(r => r.json())
  .then(data => {
    console.log(data.status);               
    console.log(data.data.registrar);       
    console.log(data.data.expiration_date); 
  });</div>

        <p class="sub-heading" style="margin-top:16px"><?php echo $h($T['api_example_python']); ?></p>
        <div class="json-block">import requests

resp = requests.get(<?php echo json_encode($baseUrl); ?>, params={'q': 'google.com'})
data = resp.json()
print(data['status'])
print(data['data']['registrar'])</div>

        <p class="sub-heading" style="margin-top:16px"><?php echo $h($T['api_example_curl']); ?></p>
        <div class="json-block">curl "<?php echo $h($baseUrl); ?>?q=google.com" | python3 -m json.tool</div>
    </div>

</main>

<footer>
    <p><?php echo $T['footer_text']; ?>
        | <a href="index.php?lang=<?php echo $lang; ?>"><?php echo $lang === 'zh' ? '查询工具' : 'Lookup Tool'; ?></a>
        | <a href="https://github.com/iezx/Super-Whois" target="_blank" rel="noopener noreferrer"><?php echo $h($T['footer_github']); ?></a>
    </p>
</footer>

<script>
const ThemeKey = 'superWhoisTheme';
const btn = document.getElementById('theme-toggle');
const ico = document.getElementById('theme-icon');
function applyTheme(dark) {
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    ico.className = dark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
    try { localStorage.setItem(ThemeKey, dark ? 'dark' : 'light'); } catch(e) {}
}
(() => {
    let s = null; try { s = localStorage.getItem(ThemeKey); } catch(e) {}
    applyTheme(s ? s === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches);
})();
btn.addEventListener('click', () =>
    applyTheme(document.documentElement.getAttribute('data-theme') !== 'dark'));

const loadingText  = <?php echo json_encode($T['api_try_loading']); ?>;
const networkError = <?php echo json_encode($T['api_try_network_error']); ?>;
function runTry() {
    const q = document.getElementById('try-input').value.trim();
    if (!q) return;
    const statusEl = document.getElementById('try-status');
    const outputEl = document.getElementById('try-output');
    const resultEl = document.getElementById('try-result');
    resultEl.style.display = 'block';
    statusEl.textContent   = loadingText;
    statusEl.className     = 'response-status';
    outputEl.textContent   = '';
    fetch('api.php?q=' + encodeURIComponent(q))
        .then(r => { const sc = r.status; const ok = r.ok; return r.json().then(d => ({ok,sc,d})); })
        .then(({ok,sc,d}) => {
            statusEl.textContent = 'HTTP ' + sc + (ok ? ' OK' : ' Error');
            statusEl.className   = 'response-status ' + (ok ? 'status-ok' : 'status-err');
            outputEl.textContent = JSON.stringify(d, null, 2);
        })
        .catch(e => {
            statusEl.textContent = networkError;
            statusEl.className   = 'response-status status-err';
            outputEl.textContent = String(e);
        });
}
document.getElementById('try-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') runTry();
});
</script>
</body>
</html>
<?php
}
?>