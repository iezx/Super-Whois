<?php
/**
 * api.php — Super Whois API v2.2.2
 * Uses whois_core.php for all shared logic.
 */
require_once __DIR__ . '/config.php';
if (!defined('API_VERSION')) define('API_VERSION', SUPER_WHOIS_API_VERSION);
$apiRequestId = bin2hex(random_bytes(8));

ini_set('pcre.backtrack_limit', '100000');
ini_set('display_errors', '0');

if (!function_exists('idn_to_ascii')) {
    http_response_code(500);
    header('Content-Type: application/json; charset=UTF-8');
    header('X-Request-ID: ' . $apiRequestId);
    header('X-Super-Whois-Version: ' . API_VERSION);
    echo json_encode([
        'error' => 'Server error: intl extension missing.',
        'error_code' => 'intl_extension_missing',
        'code' => 500,
        'request_id' => $apiRequestId,
        'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
        'api_version' => API_VERSION,
    ], JSON_UNESCAPED_SLASHES);
    exit();
}

require_once __DIR__ . '/whois_core.php';
require_once __DIR__ . '/languages.php';
require_once __DIR__ . '/whois_servers.php';

set_exception_handler(static function (Throwable $error) use ($apiRequestId): void {
    appendLog('api_unhandled_error', ['request_id' => $apiRequestId, 'type' => get_class($error)]);
    if (!headers_sent()) {
        applyApiCorsHeaders();
        header('Content-Type: application/json; charset=UTF-8');
        header('X-Request-ID: ' . $apiRequestId);
        header('X-Super-Whois-Version: ' . API_VERSION);
    }
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error.', 'error_code' => 'internal_error', 'code' => 500,
        'request_id' => $apiRequestId, 'timestamp' => gmdate('Y-m-d\TH:i:s\Z')], JSON_UNESCAPED_SLASHES);
});

// ── Language ───────────────────────────────────────────────────────────────
$supported_langs = ['en', 'zh-cn', 'zh-tw'];
$lang = 'en';
if (isset($_GET['lang']) && is_string($_GET['lang'])) {
    $gl = strtolower(trim($_GET['lang']));
    if ($gl === 'zh') $gl = 'zh-cn';
    if (in_array($gl, $supported_langs, true)) {
        $lang = $gl;
        setcookie('lang', $lang, ['expires'=>time()+86400*30,'path'=>'/','httponly'=>true,'samesite'=>'Lax',
            'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off']);
    }
} elseif (isset($_COOKIE['lang']) && in_array($_COOKIE['lang'], $supported_langs, true)) {
    $lang = $_COOKIE['lang'];
} elseif (isset($_COOKIE['lang']) && $_COOKIE['lang'] === 'zh') {
    $lang = 'zh-cn';
}
$T = get_language_strings($lang);

// ── Request parsing and protocol handling ─────────────────────────────────
$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
if ($method === 'OPTIONS') {
    applyApiCorsHeaders();
    header('Allow: GET, HEAD, POST, OPTIONS');
    http_response_code(204);
    exit();
}
if (!in_array($method, ['GET', 'HEAD', 'POST'], true)) {
    header('Allow: GET, HEAD, POST, OPTIONS');
    apiError(405, 'Method not allowed.', 'method_not_allowed');
}

$requestPayload = [];
$requestQueries = null;
if ($method === 'POST') {
    $contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($contentLength > API_MAX_BODY_BYTES) apiError(413, 'Request body is too large.', 'body_too_large');
    $contentType = strtolower(trim(explode(';', (string)($_SERVER['CONTENT_TYPE'] ?? ''), 2)[0]));
    if ($contentType === 'application/json') {
        $rawBody = file_get_contents('php://input', false, null, 0, API_MAX_BODY_BYTES + 1);
        if (!is_string($rawBody) || strlen($rawBody) > API_MAX_BODY_BYTES) apiError(413, 'Request body is too large.', 'body_too_large');
        try {
            $decoded = json_decode($rawBody, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            apiError(400, 'Malformed JSON body.', 'invalid_json');
        }
        if (!is_array($decoded)) apiError(400, 'JSON body must be an object.', 'invalid_json');
        $requestPayload = $decoded;
    } else {
        $requestPayload = $_POST;
    }
    $requestQueries = $requestPayload['queries'] ?? $requestPayload['q'] ?? null;
} elseif (array_key_exists('q', $_GET)) {
    if (!is_string($_GET['q'])) apiError(400, 'q must be a string.', 'invalid_query_type');
    $requestQueries = $_GET['q'];
}

// A queryless GET remains the human-readable documentation route.
if ($requestQueries === null || $requestQueries === '') {
    if ($method === 'POST') apiError(400, 'Missing query. Provide q or queries.', 'missing_query');
    header('Content-Type: text/html; charset=UTF-8');
    if ($method !== 'HEAD') renderApiDocs($T, $lang);
    exit();
}
if (!is_string($requestQueries) && !is_array($requestQueries)) {
    apiError(400, 'q must be a string and queries must be an array of strings.', 'invalid_query_type');
}

applyApiCorsHeaders();
header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex');
header('Cache-Control: no-store');
header('X-Request-ID: ' . $apiRequestId);
header('X-Super-Whois-Version: ' . API_VERSION);

$credential = getProvidedApiKey();
if ($credential['source'] === 'invalid') apiError(400, 'key must be a string.', 'invalid_query_type');
$providedKey = $credential['key'];
$isAuthenticated = validateApiKey($providedKey);
if ($providedKey !== '' && !$isAuthenticated) apiError(401, 'Invalid API key.', 'invalid_api_key');
if (!$isAuthenticated && !API_ALLOW_UNAUTHENTICATED) {
    apiError(401, 'Unauthorized. A valid API key is required.', 'authentication_required');
}
if ($credential['source'] === 'query') {
    header('Warning: 299 SuperWhois "Query-string API keys are deprecated; use Authorization: Bearer or X-API-Key."');
}

if (is_string($requestQueries)) {
    $queries = preg_split('/[,\r\n]+/', $requestQueries) ?: [];
} else {
    $queries = $requestQueries;
}
foreach ($queries as $query) {
    if (!is_string($query)) apiError(400, 'Every query must be a string.', 'invalid_query_type');
}
$queries = array_values(array_filter(array_map('trim', $queries), static fn($query) => $query !== ''));
if ($queries === []) apiError(400, 'Invalid or empty query.', 'invalid_query');

$batchLimit = $isAuthenticated ? API_AUTH_MAX_BATCH : API_MAX_BATCH;
if (count($queries) > $batchLimit) {
    apiError(422, "Batch limit exceeded. Maximum: $batchLimit queries.", 'batch_limit_exceeded', ['max_queries' => $batchLimit]);
}

$dnsValue = $requestPayload['dns'] ?? ($_GET['dns'] ?? false);
$dnsFlag = $dnsValue === true || (is_string($dnsValue) && in_array(strtolower($dnsValue), ['1', 'true'], true));
$rawDefault = count($queries) === 1;
$rawValue = $requestPayload['raw'] ?? ($_GET['raw'] ?? $rawDefault);
$includeRaw = !($rawValue === false || (is_string($rawValue) && in_array(strtolower($rawValue), ['0', 'false'], true)));
$prettyValue = $requestPayload['pretty'] ?? ($_GET['pretty'] ?? false);
$pretty = $prettyValue === true || (is_string($prettyValue) && in_array(strtolower($prettyValue), ['1', 'true'], true));

// Normalize once and execute each unique query once while preserving output order.
$normalizedQueries = [];
$uniqueWork = [];
foreach ($queries as $position => $query) {
    $normalized = sanitizeQuery($query);
    $normalizedQueries[$position] = $normalized;
    if ($normalized !== '' && !isset($uniqueWork[strtolower($normalized)])) {
        $uniqueWork[strtolower($normalized)] = $normalized;
    }
}
$workCost = count($uniqueWork);
if ($dnsFlag) {
    foreach ($uniqueWork as $query) if (classifyQuery($query) === 'domain') $workCost++;
}
$rateIdentifier = $isAuthenticated ? apiKeyRateIdentifier($providedKey) : null;
$rateLimit = $isAuthenticated ? API_AUTH_RATE_LIMIT : API_RATE_LIMIT;
$rateHeaders = enforceRateLimit('api', max(1, $workCost), $rateIdentifier, $rateLimit);
foreach ($rateHeaders as $name => $value) header("$name: $value");

$startedAt = microtime(true);
$batchDeadlineAt = count($queries) > 1 ? $startedAt + (API_BATCH_DEADLINE_MS / 1000) : null;
$workResults = [];
foreach ($uniqueWork as $key => $query) {
    if ($batchDeadlineAt !== null && microtime(true) >= $batchDeadlineAt) {
        $result = deadlineApiQueryResult($query);
    } else {
        $result = dispatchApiQuery($query, $whoisServers, $includeRaw);
    }
    if ($dnsFlag && ($result['query_type'] ?? '') === 'domain' && ($result['status'] ?? '') !== 'error') {
        $result['dns_records'] = lookupDNSRecords((string)$result['query']);
    }
    $workResults[$key] = finalizeApiResult($result, $includeRaw, $apiRequestId);
}

if (count($queries) === 1) {
    $query = $normalizedQueries[0] ?? '';
    if ($query === '' || classifyQuery($query) === 'invalid') {
        apiError(400, 'Invalid query. Supply a domain, IP address, or ASN.', 'invalid_query');
    }
    $result = $workResults[strtolower($query)];
    header('Server-Timing: lookup;dur=' . (int)round((microtime(true) - $startedAt) * 1000));
    apiJsonResponse($result, 200, $pretty);
}

$results = [];
foreach ($normalizedQueries as $position => $query) {
    if ($query === '' || classifyQuery($query) === 'invalid') {
        $results[] = invalidApiQueryResult($queries[$position] ?? '', $apiRequestId);
    } else {
        $positionResult = $workResults[strtolower($query)];
        $positionResult['query'] = $query;
        $results[] = $positionResult;
    }
}
$elapsed = (int)round((microtime(true) - $startedAt) * 1000);
$failed = count(array_filter($results, static fn($result) => ($result['status'] ?? '') === 'error'));
header('Server-Timing: batch;dur=' . $elapsed);
apiJsonResponse([
    'batch' => true,
    'count' => count($results),
    'succeeded' => count($results) - $failed,
    'failed' => $failed,
    'duration_ms' => $elapsed,
    'api_version' => API_VERSION,
    'request_id' => $apiRequestId,
    'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
    'results' => $results,
], 200, $pretty);

// ── Helpers ───────────────────────────────────────────────────────────────

function applyApiCorsHeaders(): void {
    $origin = is_string($_SERVER['HTTP_ORIGIN'] ?? null) ? trim($_SERVER['HTTP_ORIGIN']) : '';
    $configured = array_values(array_filter(array_map('trim', explode(',', API_CORS_ORIGINS))));
    if (in_array('*', $configured, true)) {
        header('Access-Control-Allow-Origin: *');
    } elseif ($origin !== '' && in_array($origin, $configured, true)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Vary: Origin');
    }
    header('Access-Control-Allow-Methods: GET, HEAD, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Authorization, X-API-Key, Content-Type');
    header('Access-Control-Max-Age: 600');
}

function apiJsonResponse(array $payload, int $status = 200, bool $pretty = false): void {
    if (!headers_sent() && defined('API_VERSION')) header('X-Super-Whois-Version: ' . API_VERSION);
    http_response_code($status);
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR;
    if ($pretty) $flags |= JSON_PRETTY_PRINT;
    try {
        $json = json_encode($payload, $flags);
    } catch (JsonException) {
        http_response_code(500);
        $json = '{"error":"JSON encoding failed.","error_code":"json_encoding_failed","code":500}';
    }
    if (strlen($json) > API_MAX_RESPONSE_BYTES) {
        global $apiRequestId;
        http_response_code(413);
        $json = json_encode([
            'error' => 'Response exceeds the configured size limit. Retry with raw=false or a smaller batch.',
            'error_code' => 'response_too_large',
            'code' => 413,
            'request_id' => $apiRequestId ?? null,
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
        ], JSON_UNESCAPED_SLASHES) ?: '{"error":"Response too large.","error_code":"response_too_large","code":413}';
    }
    if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'HEAD') echo $json;
    exit();
}

function apiError(int $code, string $message, string $errorCode = 'request_error', array $extra = []): void {
    global $apiRequestId;
    if (!headers_sent()) {
        applyApiCorsHeaders();
        header('Content-Type: application/json; charset=UTF-8');
        header('X-Content-Type-Options: nosniff');
        if (is_string($apiRequestId ?? null) && $apiRequestId !== '') header('X-Request-ID: ' . $apiRequestId);
    }
    apiJsonResponse(array_merge([
        'error' => $message,
        'error_code' => $errorCode,
        'code' => $code,
        'request_id' => $apiRequestId ?? null,
        'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
    ], $extra), $code);
}

function invalidApiQueryResult(string $query, string $requestId): array {
    return [
        'query' => $query,
        'query_type' => 'invalid',
        'query_method' => 'none',
        'whois_server' => null,
        'status' => 'error',
        'error' => 'Invalid query.',
        'error_code' => 'invalid_query',
        'request_id' => $requestId,
        'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
        'api_version' => API_VERSION,
    ];
}

function finalizeApiResult(array $result, bool $includeRaw, string $requestId): array {
    if (!$includeRaw) {
        unset($result['raw']);
    } elseif (isset($result['raw']) && is_string($result['raw']) && strlen($result['raw']) > API_RAW_MAX_BYTES) {
        $result['raw'] = substr($result['raw'], 0, API_RAW_MAX_BYTES);
        $result['raw_truncated'] = true;
    }
    $result['request_id'] = $requestId;
    return $result;
}

function deadlineApiQueryResult(string $query): array {
    return [
        'query' => $query,
        'query_type' => classifyQuery($query),
        'query_method' => 'none',
        'whois_server' => null,
        'status' => 'error',
        'error' => 'Batch execution deadline exceeded before this item started.',
        'error_code' => 'batch_deadline_exceeded',
        'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
        'api_version' => API_VERSION,
        'cached' => false,
        'cache_age_s' => 0,
    ];
}

function dispatchApiQuery(string $query, array $whoisServers, bool $includeRaw = true): array {
    $base = [
        'query'        => $query,
        'query_type'   => '',
        'query_method' => '',
        'whois_server' => null,
        'status'       => '',
        'timestamp'    => gmdate('Y-m-d\TH:i:s\Z'),
        'api_version'  => API_VERSION,
        'cached'       => false,
        'cache_age_s'  => 0,
    ];
    $type = classifyQuery($query);
    $t0   = microtime(true);

    if ($type === 'ipv4' || $type === 'ipv6') {
        $base['query_type'] = $type;
        $server             = getRIRServer($query);
        $raw                = queryWhoisServer($server, $query);
        $elapsed            = round((microtime(true) - $t0) * 1000);
        appendLog('api_ip_lookup', ['query' => $query, 'server' => $server, 'ms' => $elapsed]);
        if (count($raw) < 3) {
            $base['status'] = 'error'; $base['error'] = 'No data returned.'; $base['error_code'] = 'upstream_no_data';
            $base['query_method'] = 'whois'; $base['whois_server'] = $server; $base['query_ms'] = $elapsed; $base['duration_ms'] = $elapsed;
            return $base;
        }
        $base['status']       = 'found';
        $base['query_method'] = 'whois';
        $base['whois_server'] = $server;
        $base['query_ms']     = $elapsed;
        $base['duration_ms']  = $elapsed;
        if ($includeRaw) $base['raw'] = implode("\n", censorIPs($raw));
        return $base;

    } elseif ($type === 'asn') {
        $base['query_type'] = 'asn';
        $server             = 'whois.arin.net';
        $raw                = queryWhoisServer($server, strtoupper($query));
        $elapsed            = round((microtime(true) - $t0) * 1000);
        appendLog('api_asn_lookup', ['query' => $query, 'server' => $server, 'ms' => $elapsed]);
        if (count($raw) < 3) {
            $base['status'] = 'error'; $base['error'] = 'No data returned.'; $base['error_code'] = 'upstream_no_data';
            $base['query_method'] = 'whois'; $base['whois_server'] = $server; $base['query_ms'] = $elapsed; $base['duration_ms'] = $elapsed;
            return $base;
        }
        $base['status']       = 'found';
        $base['query_method'] = 'whois';
        $base['whois_server'] = $server;
        $base['query_ms']     = $elapsed;
        $base['duration_ms']  = $elapsed;
        if ($includeRaw) $base['raw'] = implode("\n", censorIPs($raw));
        return $base;

    } elseif ($type === 'domain') {
        $base['query_type'] = 'domain';
        $asciiQ = idn_to_ascii($query, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($asciiQ === false) return invalidApiQueryResult($query, '');

        $result = lookupDomain($asciiQ, $whoisServers);
        $elapsed = round((microtime(true) - $t0) * 1000);

        appendLog('api_domain_lookup', [
            'query'  => $query,
            'server' => $result['server'] ?? '',
            'method' => $result['method'] ?? '',
            'status' => $result['status'] ?? '',
            'ms'     => $elapsed,
        ]);

        $base['whois_server'] = $result['server'] ?? '';
        $base['query_method'] = $result['method'] ?? '';
        $base['query_ms']     = $elapsed;
        $base['duration_ms']  = $elapsed;
        $base['status']       = $result['status'] ?? 'error';
        $unicodeQ = idnToUnicodeDomain($asciiQ);
        if ($unicodeQ !== null) $base['unicode_domain'] = $unicodeQ;
        $base['lookup_domain'] = array_key_exists('lookup_domain', $result) ? $result['lookup_domain'] : strtolower($asciiQ);
        if (!empty($result['is_subdomain'])) {
            $base['is_subdomain'] = true;
            $base['subdomain_suggestion'] = $base['lookup_domain'];
        }
        $cacheMeta = is_array($result['_cache'] ?? null) ? $result['_cache'] : [];
        $base['cached'] = !empty($cacheMeta['hit']);
        $base['cache_age_s'] = (int)($cacheMeta['age'] ?? 0);
        if (!empty($cacheMeta['stale'])) $base['stale'] = true;
        if (isset($result['availability'])) $base['availability'] = $result['availability'];
        if (isset($result['upstream_status'])) $base['upstream_status'] = $result['upstream_status'];
        if (!empty($result['raw_truncated'])) $base['raw_truncated'] = true;

        if (!empty($result['route_provider'])) {
            $base['route_provider'] = $result['route_provider'];
            $base['route_suffix']   = $result['route_suffix'];
        }
        if (!empty($result['web_url'])) {
            $base['web_lookup_url'] = $result['web_url'];
        }

        if ($result['status'] === 'registered') {
            $parsed = $result['parsed'];
            $apiData = [];
            foreach (['creation_date','expiration_date','updated_date'] as $df) {
                if (!empty($parsed[$df])) {
                    $ts = strtotime($parsed[$df]);
                    $apiData[$df] = ($ts > 0) ? gmdate('Y-m-d\TH:i:s\Z', $ts) : $parsed[$df];
                }
            }
            foreach (['registrar','registrar_iana_id','registrar_whois','abuse_email','abuse_phone',
                      'registrant_name','registrant_org','registrant_country',
                      'registrant_address','registrant_city','registrant_region','registrant_postal_code',
                      'registrant_email','registrant_phone','admin_email','tech_email',
                      'nameservers','status','dnssec'] as $f) {
                if (!empty($parsed[$f])) $apiData[$f] = $parsed[$f];
            }
            $base['data'] = $apiData;
        }

        if ($result['status'] === 'error') {
            $base['error'] = ($result['raw'][0] ?? 'Unknown error');
            $base['error_code'] = $result['error_code'] ?? 'upstream_error';
            if (!empty($result['attempted_servers']) && is_array($result['attempted_servers'])) {
                $base['attempted_servers'] = array_values(array_filter(array_map('strval', $result['attempted_servers'])));
            }
        }
        if ($result['status'] === 'restricted') {
            $base['error'] = 'Registry lookup access is restricted.';
            $base['error_code'] = $result['error_code'] ?? 'registry_access_restricted';
            if (!empty($result['attempted_servers']) && is_array($result['attempted_servers'])) {
                $base['attempted_servers'] = array_values(array_filter(array_map('strval', $result['attempted_servers'])));
            }
            $webUrl = $result['web_url'] ?? whoisGetWebLookupUrl(explode('.', $asciiQ)[count(explode('.', $asciiQ))-1] ?? '');
            if ($webUrl !== null) $base['web_lookup_url'] = $webUrl;
        }

        if ($includeRaw) $base['raw'] = implode("\n", censorIPs($result['raw'] ?? []));
        return $base;

    } else {
        return invalidApiQueryResult($query, '');
    }
}

// ── API Documentation Page ─────────────────────────────────────────────────

function renderApiDocs(array $T, string $lang): void {
    if (!headers_sent()) header('X-Super-Whois-Version: ' . API_VERSION);
    $h        = fn(string $s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    $authNote = API_ALLOW_UNAUTHENTICATED ? $T['api_auth_public'] : $T['api_auth_protected'];
    $rateNote = sprintf($T['api_rate_note'], API_RATE_LIMIT);
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
<meta name="application-version" content="<?php echo SUPER_WHOIS_VERSION; ?>">
<title><?php echo $h($T['api_page_title']); ?></title>
<link rel="stylesheet" href="./style.css">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
<style>
.api-hero{text-align:center;padding:40px 0 20px}
.api-hero h1{font-size:32px;font-weight:800;color:var(--clr-primary);letter-spacing:-.03em}
.api-hero p{color:var(--clr-text-secondary);margin-top:8px;font-size:15px}
.api-version-badge{display:inline-flex;align-items:center;gap:8px;background:var(--clr-primary);
  color:#fff;padding:6px 16px;border-radius:99px;font-size:13px;font-weight:700;
  letter-spacing:.04em;margin-top:12px;text-decoration:none}
.doc-section{margin-top:6px}
.doc-section .card-header h2{font-size:15px;font-weight:700;color:var(--clr-text);
  border-bottom:2px solid var(--clr-border);padding-bottom:8px;margin-bottom:14px}
.endpoint-box{background:var(--clr-code-bg);border:1px solid var(--clr-border);
  border-radius:var(--radius-md);padding:14px 18px;font-family:var(--font-mono);
  font-size:13px;margin-bottom:10px;overflow-x:auto;color:var(--clr-text-secondary)}
.endpoint-box .method{color:var(--clr-primary);font-weight:700;margin-right:10px}
.param-table{width:100%;border-collapse:collapse;font-size:14px}
.param-table th{text-align:left;padding:8px 12px;font-size:11px;font-weight:700;letter-spacing:.06em;
  text-transform:uppercase;color:var(--clr-text-muted);background:var(--clr-code-bg);
  border-bottom:1px solid var(--clr-border)}
.param-table td{padding:9px 12px;border-bottom:1px solid var(--clr-border-light);vertical-align:top}
.param-table tr:last-child td{border-bottom:none}
.badge-req{background:#fee2e2;color:#b91c1c;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}
.badge-opt{background:#e0f2fe;color:#0369a1;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}
.json-block{background:var(--clr-code-bg);border:1px solid var(--clr-border);
  border-radius:var(--radius-md);padding:14px 18px;font-family:var(--font-mono);
  font-size:12.5px;line-height:1.75;overflow-x:auto;white-space:pre;
  color:var(--clr-text-secondary);max-height:420px;overflow-y:auto}
.try-box{display:flex;gap:10px;flex-wrap:wrap}
.try-input{flex:1;min-width:180px;height:42px;padding:0 14px;border:1.5px solid var(--clr-border);
  border-radius:var(--radius-sm);font-size:14px;background:var(--clr-surface);color:var(--clr-text);
  font-family:var(--font-mono);outline:none;transition:border-color .2s}
.try-input:focus{border-color:var(--clr-primary)}
.try-btn{height:42px;padding:0 20px;background:var(--clr-primary);color:#fff;border:none;
  border-radius:var(--radius-sm);font-weight:700;cursor:pointer;font-size:14px;
  transition:background .18s}
.try-btn:hover{background:var(--clr-primary-dark)}
#try-result{margin-top:10px;display:none}
.response-status{font-size:12px;font-weight:700;margin-bottom:6px}
.status-ok{color:var(--clr-success)}.status-err{color:var(--clr-danger)}
.back-link{display:inline-flex;align-items:center;gap:6px;color:var(--clr-text-secondary);
  text-decoration:none;font-size:13px;font-weight:500;margin-bottom:14px}
.back-link:hover{color:var(--clr-primary)}
 .sub-heading{font-size:14px;font-weight:700;margin:14px 0 6px;color:var(--clr-text)}
 .sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
</style>
</head>
<body>
<header>
  <div class="header-content">
    <h2><i class="fa-solid fa-globe"></i> <?php echo $h($T['header_title']); ?></h2>
    <div class="header-actions">
      <button id="theme-toggle" class="icon-btn" aria-label="<?php echo $h($T['theme_toggle']); ?>">
        <i class="fa-solid fa-moon" id="theme-icon"></i>
      </button>
      <div class="language-switcher">
        <a href="?lang=en" <?php if ($lang==='en') echo 'class="active"'; ?>>EN</a>
        <a href="?lang=zh-cn" <?php if ($lang==='zh-cn') echo 'class="active"'; ?>>简体</a>
        <a href="?lang=zh-tw" <?php if ($lang==='zh-tw') echo 'class="active"'; ?>>繁體</a>
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
    <span class="api-version-badge"><i class="fa-solid fa-code"></i> v<?php echo API_VERSION; ?></span>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_base_url']); ?></h2></div>
    <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?></div>
    <div class="endpoint-box"><span class="method">POST</span><?php echo $h($baseUrl); ?></div>
    <p style="font-size:13px;color:var(--clr-text-muted)"><?php echo $T['api_post_desc']; ?></p>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_auth']); ?></h2></div>
    <p style="font-size:14px;margin-bottom:12px"><?php echo $authNote; ?></p>
    <div class="endpoint-box">curl -H "Authorization: Bearer YOUR_API_KEY" "<?php echo $h($baseUrl); ?>?q=google.com"</div>
    <p style="font-size:13px;color:var(--clr-text-muted);margin-bottom:6px"><?php echo $T['api_auth_keys_note']; ?></p>
    <p style="font-size:13px;color:var(--clr-text-muted);margin-bottom:6px"><?php echo $h($T['api_auth_local_label']); ?></p>
    <div class="json-block">$apiKeys = ['paste-your-sk-code-here'];</div>
    <div class="json-block">SUPER_WHOIS_API_KEYS=replace-with-a-long-random-secret</div>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_rate']); ?></h2></div>
    <p style="font-size:14px;margin-bottom:12px"><?php echo $rateNote; ?></p>
    <table class="param-table">
      <tr><th><?php echo $h($T['api_rate_header_name']); ?></th><th><?php echo $h($T['api_rate_header_desc']); ?></th></tr>
      <tr><td><code>RateLimit-Limit</code></td><td><?php echo $h($T['api_rate_limit_label']); ?></td></tr>
      <tr><td><code>RateLimit-Remaining</code></td><td><?php echo $h($T['api_rate_remaining_label']); ?></td></tr>
      <tr><td><code>RateLimit-Reset</code></td><td><?php echo $h($T['api_rate_reset_label']); ?></td></tr>
      <tr><td><code>Retry-After</code></td><td><?php echo $h($T['api_retry_after_desc']); ?></td></tr>
    </table>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_params']); ?></h2></div>
    <table class="param-table">
      <tr><th><?php echo $h($T['api_param_name']); ?></th><th><?php echo $h($T['api_param_required']); ?></th><th><?php echo $h($T['api_param_desc']); ?></th></tr>
      <tr>
        <td><code>q</code> / <code>queries</code></td>
        <td><span class="badge-req"><?php echo $h($T['api_param_required']); ?></span></td>
        <td><?php echo $T['api_param_q_desc']; ?> <?php echo $T['api_post_desc']; ?> <?php echo $h(sprintf($T['api_batch_limits_note'], API_MAX_BATCH, API_AUTH_MAX_BATCH)); ?></td>
      </tr>
      <tr>
        <td><code>key</code></td>
        <td><span class="badge-opt"><?php echo $h($T['api_optional']); ?></span></td>
        <td><?php echo $T['api_param_key_desc']; ?></td>
      </tr>
      <tr>
        <td><code>dns</code></td>
        <td><span class="badge-opt"><?php echo $h($T['api_optional']); ?></span></td>
        <td><?php echo $T['api_dns_param_desc']; ?></td>
      </tr>
      <tr>
        <td><code>raw</code></td>
        <td><span class="badge-opt"><?php echo $h($T['api_optional']); ?></span></td>
        <td><?php echo $T['api_raw_param_desc']; ?></td>
      </tr>
      <tr>
        <td><code>pretty</code></td>
        <td><span class="badge-opt"><?php echo $h($T['api_optional']); ?></span></td>
        <td><?php echo $T['api_pretty_param_desc']; ?></td>
      </tr>
      <tr>
        <td><code>lang</code></td>
        <td><span class="badge-opt"><?php echo $h($T['api_optional']); ?></span></td>
        <td><?php echo $T['api_lang_param_desc']; ?></td>
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
    <p class="sub-heading"><?php echo $h($T['api_endpoint_dns']); ?></p>
    <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?>?q=google.com&amp;dns=true</div>
    <p class="sub-heading"><?php echo $h($T['api_endpoint_batch']); ?></p>
    <div class="endpoint-box"><span class="method">GET</span><?php echo $h($baseUrl); ?>?q=google.com,github.com,cloudflare.com&amp;raw=false</div>
    <div class="endpoint-box"><span class="method">POST</span>{"queries":["google.com","github.com"],"raw":false}</div>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_response']); ?></h2></div>
    <p style="font-size:13px;color:var(--clr-text-muted);margin-bottom:10px"><?php echo $h($T['api_status_note']); ?></p>
    <table class="param-table">
      <tr><th><?php echo $h($T['api_col_field']); ?></th><th><?php echo $h($T['api_col_type']); ?></th><th><?php echo $h($T['api_col_desc']); ?></th></tr>
      <tr><td><code>query</code></td><td>string</td><td><?php echo $h($T['api_field_query']); ?></td></tr>
      <tr><td><code>query_type</code></td><td>string</td><td><?php echo $T['api_field_query_type']; ?></td></tr>
      <tr><td><code>query_method</code></td><td>string</td><td><?php echo $h($T['api_field_query_method']); ?></td></tr>
      <tr><td><code>lookup_domain</code></td><td>string|null</td><td><?php echo $h($T['api_field_lookup_domain']); ?></td></tr>
      <tr><td><code>unicode_domain</code></td><td>string?</td><td><?php echo $h($T['api_field_unicode_domain']); ?></td></tr>
      <tr><td><code>is_subdomain</code></td><td>boolean?</td><td><?php echo $h($T['api_field_is_subdomain']); ?></td></tr>
      <tr><td><code>status</code></td><td>string</td><td><?php echo $T['api_field_status']; ?></td></tr>
      <tr><td><code>whois_server</code></td><td>string|null</td><td><?php echo $T['api_field_whois_server']; ?></td></tr>
       <tr><td><code>attempted_servers</code></td><td>array?</td><td><?php echo $h($T['api_field_attempted_servers']); ?></td></tr>
      <tr><td><code>timestamp</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_timestamp']); ?></td></tr>
      <tr><td><code>query_ms</code></td><td>integer</td><td><?php echo $h($T['api_field_query_ms']); ?></td></tr>
      <tr><td><code>cached</code></td><td>boolean</td><td><?php echo $h($T['api_field_cached']); ?></td></tr>
      <tr><td><code>cache_age_s</code></td><td>integer</td><td><?php echo $h($T['api_field_cache_age']); ?></td></tr>
      <tr><td><code>stale</code></td><td>boolean?</td><td><?php echo $h($T['api_field_stale']); ?></td></tr>
      <tr><td><code>duration_ms</code></td><td>number</td><td><?php echo $h($T['api_field_duration']); ?></td></tr>
      <tr><td><code>availability</code></td><td>string?</td><td><?php echo $h($T['api_field_availability']); ?></td></tr>
      <tr><td><code>upstream_status</code></td><td>integer?</td><td><?php echo $h($T['api_field_upstream_status']); ?></td></tr>
      <tr><td><code>dns_records</code></td><td>object?</td><td><?php echo $h($T['api_field_dns_records']); ?></td></tr>
      <tr><td><code>error_code</code></td><td>string?</td><td><?php echo $h($T['api_field_error_code']); ?></td></tr>
      <tr><td><code>request_id</code></td><td>string</td><td><?php echo $h($T['api_field_request_id']); ?></td></tr>
      <tr><td><code>api_version</code></td><td>string</td><td><?php echo $h($T['api_field_api_version']); ?></td></tr>
      <tr><td><code>data</code></td><td>object</td><td><?php echo $T['api_field_data']; ?></td></tr>
      <tr><td><code>data.creation_date</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_creation']); ?></td></tr>
      <tr><td><code>data.expiration_date</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_expiration']); ?></td></tr>
      <tr><td><code>data.updated_date</code></td><td>ISO 8601</td><td><?php echo $h($T['api_field_updated']); ?></td></tr>
      <tr><td><code>data.registrar</code></td><td>string</td><td><?php echo $h($T['api_field_registrar']); ?></td></tr>
      <tr><td><code>data.registrar_iana_id</code></td><td>string</td><td><?php echo $h($T['api_field_iana_id']); ?></td></tr>
      <tr><td><code>data.registrant_address</code><br><code>data.registrant_city</code><br><code>data.registrant_region</code><br><code>data.registrant_postal_code</code></td><td>string?</td><td><?php echo $h($T['api_field_registrant_address']); ?></td></tr>
      <tr><td><code>data.nameservers</code></td><td>array</td><td><?php echo $h($T['api_field_nameservers']); ?></td></tr>
      <tr><td><code>data.status</code></td><td>array</td><td><?php echo $h($T['api_field_statuses']); ?></td></tr>
      <tr><td><code>data.dnssec</code></td><td>string</td><td><?php echo $h($T['api_field_dnssec']); ?></td></tr>
      <tr><td><code>subdomain_suggestion</code></td><td>string?</td><td><?php echo $h($T['api_field_subdomain']); ?></td></tr>
      <tr><td><code>raw</code></td><td>string?</td><td><?php echo $T['api_field_raw']; ?>; <?php echo $h(sprintf($T['api_field_raw_limit'], API_RAW_MAX_BYTES)); ?></td></tr>
      <tr><td><code>raw_truncated</code></td><td>boolean?</td><td><?php echo $h($T['api_field_raw_truncated']); ?></td></tr>
      <tr><td><code>batch/count/succeeded/failed</code></td><td><?php echo $h($T['api_field_batch_type']); ?></td><td><?php echo $h($T['api_field_batch_meta']); ?></td></tr>
    </table>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_sample']); ?> — <code>api.php?q=google.com</code></h2></div>
    <div class="json-block">{
  "query": "google.com",
  "query_type": "domain",
  "query_method": "rdap",
  "lookup_domain": "google.com",
  "whois_server": "rdap.verisign.com",
  "status": "registered",
  "cached": false,
  "cache_age_s": 0,
  "timestamp": "2026-08-08T10:23:45Z",
  "query_ms": 180,
  "api_version": "<?php echo API_VERSION; ?>",
  "data": {
    "creation_date": "1997-09-15T04:00:00Z",
    "expiration_date": "2028-09-14T04:00:00Z",
    "updated_date": "2019-09-09T15:39:04Z",
    "registrar": "MarkMonitor Inc.",
    "registrar_iana_id": "292",
    "registrar_whois": "whois.markmonitor.com",
    "nameservers": ["ns1.google.com","ns2.google.com","ns3.google.com","ns4.google.com"],
    "status": ["clientDeleteProhibited","clientTransferProhibited"],
    "dnssec": "unsigned"
  },
  "request_id": "9c2e7f6f26a9d2c1",
  "raw": "RDAP 200 from rdap.verisign.com\n--- RDAP JSON ---\n{...}"
}</div>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $T['api_batch_sample_title']; ?></h2></div>
    <div class="json-block">{
  "batch": true,
  "count": 2,
  "succeeded": 2,
  "failed": 0,
  "duration_ms": 420,
  "api_version": "<?php echo API_VERSION; ?>",
  "request_id": "9c2e7f6f26a9d2c1",
  "timestamp": "2026-08-08T10:23:45Z",
  "results": [
    { "query": "google.com", "query_type": "domain", "status": "registered", "..." : "..." },
    { "query": "github.com", "query_type": "domain", "status": "registered", "..." : "..." }
  ]
}</div>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_errors']); ?></h2></div>
    <table class="param-table">
      <tr><th>HTTP</th><th><?php echo $h($T['api_error_meaning']); ?></th></tr>
      <tr><td><code>400</code></td><td><?php echo $T['api_error_400']; ?></td></tr>
      <tr><td><code>401</code></td><td><?php echo $T['api_error_401']; ?></td></tr>
      <tr><td><code>405</code></td><td><?php echo $h($T['api_http_405']); ?></td></tr>
      <tr><td><code>413</code></td><td><?php echo $h($T['api_http_413']); ?></td></tr>
      <tr><td><code>422</code></td><td><?php echo $h($T['api_http_422']); ?></td></tr>
      <tr><td><code>429</code></td><td><?php echo $T['api_error_429']; ?></td></tr>
      <tr><td><code>503</code></td><td><?php echo $h($T['api_http_503']); ?></td></tr>
      <tr><td><code>500</code></td><td><?php echo $T['api_error_500']; ?></td></tr>
    </table>
  </div>

  <div class="illustrate-card doc-section">
    <div class="card-header"><h2><?php echo $h($T['api_section_try']); ?></h2></div>
    <div class="try-box">
      <label class="sr-only" for="try-input"><?php echo $h($T['api_try_query_label']); ?></label>
      <input type="text" class="try-input" id="try-input" placeholder="<?php echo $h($T['api_try_placeholder']); ?>" value="google.com">
      <?php if (!API_ALLOW_UNAUTHENTICATED): ?>
      <input type="password" class="try-input" id="try-key" placeholder="<?php echo $h($T['sk_placeholder']); ?>" autocomplete="off">
      <?php endif; ?>
      <button class="try-btn" onclick="runTry()">
        <i class="fa-solid fa-play"></i> <?php echo $h($T['api_try_send']); ?>
      </button>
    </div>
    <div id="try-result" role="status" aria-live="polite" aria-atomic="true">
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
    console.log(data.status);               // "registered"
    console.log(data.data.registrar);       // "MarkMonitor Inc."
    console.log(data.data.expiration_date); // "2028-09-14T04:00:00Z"
  });</div>
    <p class="sub-heading" style="margin-top:16px"><?php echo $h($T['api_example_python']); ?></p>
    <div class="json-block">import requests
resp = requests.get(<?php echo json_encode($baseUrl); ?>, params={'q': 'google.com'})
data = resp.json()
print(data['status'])
print(data['data']['registrar'])</div>
    <p class="sub-heading" style="margin-top:16px"><?php echo $h($T['api_example_curl']); ?></p>
    <div class="json-block">curl -H "Authorization: Bearer YOUR_API_KEY" "<?php echo $h($baseUrl); ?>?q=google.com&amp;raw=false" | python3 -m json.tool</div>
    <p class="sub-heading" style="margin-top:16px"><?php echo $h($T['api_example_batch']); ?></p>
    <div class="json-block">curl "<?php echo $h($baseUrl); ?>?q=google.com,github.com,cloudflare.com&amp;raw=false" | python3 -m json.tool</div>
    <p class="sub-heading" style="margin-top:16px"><?php echo $h($T['api_post_label']); ?></p>
    <div class="json-block">curl -X POST -H "Content-Type: application/json" -d '{"queries":["google.com","github.com"],"raw":false}' "<?php echo $h($baseUrl); ?>"</div>
  </div>
</main>

<footer>
  <p><?php echo $T['footer_text']; ?>
    <span class="version-badge">v<?php echo SUPER_WHOIS_VERSION; ?></span>
    | <a href="index.php?lang=<?php echo $lang; ?>"><?php echo $h($T['api_footer_lookup']); ?></a>
    | <a href="https://github.com/iezx/Super-Whois" target="_blank" rel="noopener noreferrer"><?php echo $h($T['footer_github']); ?></a>
  </p>
</footer>

<script>
const TK='swTheme',b=document.getElementById('theme-toggle'),i=document.getElementById('theme-icon');
function applyTheme(d){document.documentElement.setAttribute('data-theme',d?'dark':'light');i.className=d?'fa-solid fa-sun':'fa-solid fa-moon';try{localStorage.setItem(TK,d?'dark':'light')}catch(e){}}
(()=>{let s;try{s=localStorage.getItem(TK)}catch(e){}applyTheme(s?s==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches)})();
b.addEventListener('click',()=>applyTheme(document.documentElement.getAttribute('data-theme')!=='dark'));

const loadTxt=<?php echo json_encode($T['api_try_loading']); ?>, errTxt=<?php echo json_encode($T['api_try_network_error']); ?>;
const processedTpl=<?php echo json_encode($T['api_try_processed']); ?>, failedTpl=<?php echo json_encode($T['api_try_failed']); ?>;
function runTry(){
  const q=document.getElementById('try-input').value.trim(); if(!q) return;
  const sEl=document.getElementById('try-status'),oEl=document.getElementById('try-output');
  document.getElementById('try-result').style.display='block';
  sEl.textContent=loadTxt; sEl.className='response-status'; oEl.textContent='';
  const keyEl=document.getElementById('try-key'),options={};
  if(keyEl&&keyEl.value)options.headers={'Authorization':'Bearer '+keyEl.value};
  fetch('api.php?q='+encodeURIComponent(q),options)
    .then(r=>{const sc=r.status,ok=r.ok;return r.json().then(d=>({ok,sc,d}))})
    .then(({ok,sc,d})=>{
      const appOk=ok&&d.status!=='error'&&!(d.batch&&d.failed===d.count);
      sEl.textContent=(appOk?processedTpl:failedTpl).replace('%d',sc);
      sEl.className='response-status '+(appOk?'status-ok':'status-err');
      oEl.textContent=JSON.stringify(d,null,2);
    }).catch(e=>{sEl.textContent=errTxt;sEl.className='response-status status-err';oEl.textContent=String(e)});
}
document.getElementById('try-input')?.addEventListener('keydown',e=>{if(e.key==='Enter')runTry()});
</script>
</body>
</html>
<?php
}
