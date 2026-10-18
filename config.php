<?php
declare(strict_types=1);

/**
 * Super Whois runtime configuration.
 *
 * Every setting can be overridden by defining the constant before this file
 * is loaded. Deployment-facing settings also accept SUPER_WHOIS_* variables.
 */

if (!function_exists('superWhoisEnvBool')) {
    function superWhoisEnvBool(string $name, bool $default): bool {
        $value = getenv($name);
        if ($value === false || trim($value) === '') return $default;
        $parsed = filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
        return $parsed ?? $default;
    }
}

if (!function_exists('superWhoisEnvInt')) {
    function superWhoisEnvInt(string $name, int $default, int $min, int $max): int {
        $value = getenv($name);
        if ($value === false || !preg_match('/^-?\d+$/', trim($value))) return $default;
        return max($min, min($max, (int)$value));
    }
}

if (!defined('SUPER_WHOIS_VERSION')) define('SUPER_WHOIS_VERSION', '2.2.2');
// Keep the public API contract on its own explicit version constant so an
// older cached/deployed UI cannot silently report a stale API version.
if (!defined('SUPER_WHOIS_API_VERSION')) define('SUPER_WHOIS_API_VERSION', '2.2.2');

$configuredStorage = getenv('SUPER_WHOIS_STORAGE_DIR');
if ($configuredStorage === false || trim($configuredStorage) === '') {
    $configuredStorage = rtrim(sys_get_temp_dir(), "/\\")
        . DIRECTORY_SEPARATOR . 'super-whois-' . substr(hash('sha256', __DIR__), 0, 12);
}
$configuredStorage = rtrim(trim($configuredStorage), "/\\");
if (!defined('STORAGE_DIR')) define('STORAGE_DIR', $configuredStorage);
if (!defined('CACHE_DIR'))   define('CACHE_DIR', STORAGE_DIR . DIRECTORY_SEPARATOR . 'cache');
if (!defined('RATE_STORE'))  define('RATE_STORE', STORAGE_DIR . DIRECTORY_SEPARATOR . 'rate');
if (!defined('LOG_DIR'))     define('LOG_DIR', STORAGE_DIR . DIRECTORY_SEPARATOR . 'logs');

if (!defined('LOG_KEEP_DAYS')) define('LOG_KEEP_DAYS', 30);
if (!defined('LOG_CLIENT_IDENTIFIERS')) define('LOG_CLIENT_IDENTIFIERS', superWhoisEnvBool('SUPER_WHOIS_LOG_CLIENTS', false));
if (!defined('LOG_QUERY_VALUES')) define('LOG_QUERY_VALUES', superWhoisEnvBool('SUPER_WHOIS_LOG_QUERIES', false));
if (!defined('TRUST_PROXY')) define('TRUST_PROXY', superWhoisEnvBool('SUPER_WHOIS_TRUST_PROXY', false));

if (!defined('RATE_WINDOW')) define('RATE_WINDOW', 3600);
if (!defined('WEB_RATE_LIMIT')) define('WEB_RATE_LIMIT', superWhoisEnvInt('SUPER_WHOIS_WEB_RATE_LIMIT', 30, 1, 100000));
if (!defined('WEB_AUTH_RATE_LIMIT')) define('WEB_AUTH_RATE_LIMIT', superWhoisEnvInt('SUPER_WHOIS_WEB_AUTH_RATE_LIMIT', 300, 1, 100000));
if (!defined('API_RATE_LIMIT')) define('API_RATE_LIMIT', superWhoisEnvInt('SUPER_WHOIS_API_RATE_LIMIT', 60, 1, 100000));
if (!defined('API_AUTH_RATE_LIMIT')) define('API_AUTH_RATE_LIMIT', superWhoisEnvInt('SUPER_WHOIS_API_AUTH_RATE_LIMIT', 600, 1, 100000));

if (!defined('WEB_MAX_BATCH')) define('WEB_MAX_BATCH', superWhoisEnvInt('SUPER_WHOIS_WEB_MAX_BATCH', 20, 1, 200));
if (!defined('WEB_AUTH_MAX_BATCH')) define('WEB_AUTH_MAX_BATCH', superWhoisEnvInt('SUPER_WHOIS_WEB_AUTH_MAX_BATCH', 100, 1, 500));
if (!defined('WEB_MAX_INPUT_BYTES')) define('WEB_MAX_INPUT_BYTES', 32768);
if (!defined('API_MAX_BATCH')) define('API_MAX_BATCH', superWhoisEnvInt('SUPER_WHOIS_API_MAX_BATCH', 10, 1, 200));
if (!defined('API_AUTH_MAX_BATCH')) define('API_AUTH_MAX_BATCH', superWhoisEnvInt('SUPER_WHOIS_API_AUTH_MAX_BATCH', 50, 1, 500));
if (!defined('API_MAX_QUERY_LENGTH')) define('API_MAX_QUERY_LENGTH', 253);
if (!defined('API_MAX_BODY_BYTES')) define('API_MAX_BODY_BYTES', 32768);
if (!defined('API_RAW_MAX_BYTES')) define('API_RAW_MAX_BYTES', 131072);
if (!defined('API_MAX_RESPONSE_BYTES')) define('API_MAX_RESPONSE_BYTES', 8388608);
if (!defined('API_BATCH_DEADLINE_MS')) define('API_BATCH_DEADLINE_MS', superWhoisEnvInt('SUPER_WHOIS_API_BATCH_DEADLINE_MS', 25000, 1000, 120000));

if (!defined('API_ALLOW_UNAUTHENTICATED')) {
    define('API_ALLOW_UNAUTHENTICATED', superWhoisEnvBool('SUPER_WHOIS_API_PUBLIC', true));
}
if (!defined('API_KEYS_FILE')) define('API_KEYS_FILE', __DIR__ . '/api_keys.php');
if (!defined('API_CORS_ORIGINS')) {
    $cors = getenv('SUPER_WHOIS_CORS_ORIGINS');
    define('API_CORS_ORIGINS', ($cors === false || trim($cors) === '') ? '*' : trim($cors));
}

if (!defined('RDAP_CONNECT_TIMEOUT')) define('RDAP_CONNECT_TIMEOUT', 2);
if (!defined('RDAP_TOTAL_TIMEOUT')) define('RDAP_TOTAL_TIMEOUT', 5);
if (!defined('RDAP_MAX_REDIRECTS')) define('RDAP_MAX_REDIRECTS', 2);
if (!defined('RDAP_MAX_RESPONSE_BYTES')) define('RDAP_MAX_RESPONSE_BYTES', 1048576);
if (!defined('WHOIS_CONNECT_TIMEOUT')) define('WHOIS_CONNECT_TIMEOUT', 3);
if (!defined('WHOIS_TOTAL_TIMEOUT')) define('WHOIS_TOTAL_TIMEOUT', 6);
if (!defined('IANA_WHOIS_TIMEOUT')) define('IANA_WHOIS_TIMEOUT', 3);
if (!defined('WHOIS_MAX_RESPONSE_BYTES')) define('WHOIS_MAX_RESPONSE_BYTES', 524288);

if (!defined('CACHE_TTL_RDAP')) define('CACHE_TTL_RDAP', 86400);
if (!defined('CACHE_TTL_IANA')) define('CACHE_TTL_IANA', 604800);
if (!defined('CACHE_TTL_REGISTERED')) define('CACHE_TTL_REGISTERED', 900);
if (!defined('CACHE_TTL_NOT_FOUND')) define('CACHE_TTL_NOT_FOUND', 60);
if (!defined('CACHE_TTL_ERROR')) define('CACHE_TTL_ERROR', 15);
if (!defined('CACHE_STALE_MAX_AGE')) define('CACHE_STALE_MAX_AGE', 86400);
if (!defined('CACHE_MAX_FILES')) define('CACHE_MAX_FILES', superWhoisEnvInt('SUPER_WHOIS_CACHE_MAX_FILES', 10000, 100, 1000000));
if (!defined('CACHE_MAX_BYTES')) define('CACHE_MAX_BYTES', superWhoisEnvInt('SUPER_WHOIS_CACHE_MAX_BYTES', 268435456, 10485760, 2000000000));
if (!defined('CACHE_GC_INTERVAL')) define('CACHE_GC_INTERVAL', 3600);
if (!defined('CACHE_GC_ENABLED')) define('CACHE_GC_ENABLED', superWhoisEnvBool('SUPER_WHOIS_CACHE_GC', true));
if (!defined('LOOKUP_RAW_MAX_BYTES')) define('LOOKUP_RAW_MAX_BYTES', 262144);
if (!defined('RDAP_CIRCUIT_TTL')) define('RDAP_CIRCUIT_TTL', 15);
