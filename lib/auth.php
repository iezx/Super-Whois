<?php
declare(strict_types=1);

/** lib/auth.php — API key loading and constant-time verification. */

function getConfiguredApiKeyHashes(): array {
    static $hashes = null;
    if (is_array($hashes)) return $hashes;

    $hashes = [];
    $envKeys = getenv('SUPER_WHOIS_API_KEYS');
    if ($envKeys !== false && trim($envKeys) !== '') {
        foreach (preg_split('/[,\r\n]+/', $envKeys) ?: [] as $key) {
            $key = trim($key);
            if ($key !== '') $hashes[] = hash('sha256', $key);
        }
    }

    if (defined('API_KEYS_FILE') && is_file(API_KEYS_FILE)) {
        $apiKeys = [];
        $apiKeyHashes = [];
        require API_KEYS_FILE;
        foreach ($apiKeyHashes as $hash) {
            $hash = strtolower(trim((string)$hash));
            if (preg_match('/^[a-f0-9]{64}$/', $hash)) $hashes[] = $hash;
        }
        // Backward compatibility for existing installations. New deployments
        // should store only hashes or use SUPER_WHOIS_API_KEYS.
        foreach ($apiKeys as $key) {
            $key = trim((string)$key);
            if ($key !== '') $hashes[] = hash('sha256', $key);
        }
    }

    return $hashes = array_values(array_unique($hashes));
}

function validateApiKey(string $provided): bool {
    $provided = trim($provided);
    if ($provided === '') return false;
    $candidate = hash('sha256', $provided);
    $valid = false;
    foreach (getConfiguredApiKeyHashes() as $expected) {
        // Do not exit early; verification time should not identify a matching slot.
        $valid = hash_equals($expected, $candidate) || $valid;
    }
    return $valid;
}

function apiKeyRateIdentifier(string $provided): string {
    return 'key:' . hash('sha256', trim($provided));
}

function getRequestAuthorizationHeader(): string {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    return is_string($header) ? trim($header) : '';
}

/**
 * @return array{key:string,source:string}
 */
function getProvidedApiKey(): array {
    $auth = getRequestAuthorizationHeader();
    if (preg_match('/^Bearer\s+(.+)$/i', $auth, $m)) {
        return ['key' => trim($m[1]), 'source' => 'authorization'];
    }
    if (!empty($_SERVER['HTTP_X_API_KEY'])) {
        return ['key' => trim((string)$_SERVER['HTTP_X_API_KEY']), 'source' => 'x-api-key'];
    }
    if (isset($_GET['key'])) {
        if (!is_string($_GET['key'])) return ['key' => '', 'source' => 'invalid'];
        return ['key' => trim($_GET['key']), 'source' => 'query'];
    }
    return ['key' => '', 'source' => 'none'];
}
