<?php
/** lib/utils.php — Rate limiting, input sanitization, query classification, RIR routing */

// ── RIR Routing ───────────────────────────────────────────────────────────

function getRIRServer(string $ip): string {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'whois.arin.net';
    $l = ip2long($ip);
    $r = fn($a,$b) => $l >= ip2long($a) && $l <= ip2long($b);
    // APNIC
    if ($r('1.0.0.0','1.255.255.255')||$r('14.0.0.0','14.255.255.255')||
        $r('27.0.0.0','27.255.255.255')||$r('49.0.0.0','49.255.255.255')||
        $r('58.0.0.0','60.255.255.255')||$r('101.0.0.0','103.255.255.255')||
        $r('110.0.0.0','126.255.255.255')||$r('175.0.0.0','180.255.255.255')||
        $r('182.0.0.0','183.255.255.255')||$r('202.0.0.0','203.255.255.255')||
        $r('210.0.0.0','211.255.255.255')||$r('218.0.0.0','223.255.255.255'))
        return 'whois.apnic.net';
    // RIPE
    if ($r('2.0.0.0','2.255.255.255')||$r('5.0.0.0','5.255.255.255')||
        $r('31.0.0.0','31.255.255.255')||$r('37.0.0.0','37.255.255.255')||
        $r('46.0.0.0','46.255.255.255')||$r('77.0.0.0','95.255.255.255')||
        $r('176.0.0.0','178.255.255.255')||$r('185.0.0.0','185.255.255.255')||
        $r('188.0.0.0','195.255.255.255')||$r('212.0.0.0','213.255.255.255')||
        $r('217.0.0.0','217.255.255.255'))
        return 'whois.ripe.net';
    // LACNIC
    if ($r('177.0.0.0','177.255.255.255')||$r('179.0.0.0','179.255.255.255')||
        $r('181.0.0.0','181.255.255.255')||$r('186.0.0.0','191.255.255.255')||
        $r('200.0.0.0','201.255.255.255'))
        return 'whois.lacnic.net';
    // AFRINIC
    if ($r('41.0.0.0','41.255.255.255')||$r('102.0.0.0','102.255.255.255')||
        $r('105.0.0.0','105.255.255.255')||$r('154.0.0.0','154.255.255.255')||
        $r('196.0.0.0','197.255.255.255'))
        return 'whois.afrinic.net';
    return 'whois.arin.net';
}

// ── Rate Limiting ──────────────────────────────────────────────────────────

function rateLimitAbort(string $context, int $code, string $message, string $errorCode, array $extra = []): void {
    http_response_code($code);
    if ($context === 'api') {
        if (function_exists('apiError')) apiError($code, $message, $errorCode, $extra);
        global $apiRequestId;
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(array_merge([
            'error' => $message,
            'error_code' => $errorCode,
            'code' => $code,
            'request_id' => $apiRequestId ?? null,
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
        ], $extra), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    } else {
        echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    }
    exit();
}

/**
 * Enforce per-IP rate limiting using a single JSON file per IP.
 * On success, returns rate limit headers array.
 * On failure, sets HTTP 429 and exits.
 *
 * @param string $context  'web' or 'api' — used for response and logging
 * @param int $cost        Number of upstream work units consumed
 * @param string|null $identifier Stable client or API-key identity
 * @param int|null $limit  Explicit quota; defaults to the public context quota
 */
function enforceRateLimit(string $context = 'web', int $cost = 1, ?string $identifier = null, ?int $limit = null): array {
    $dir = RATE_STORE;
    if (!ensureRuntimeDirectory($dir)) {
        appendLog('rate_store_error', ['context' => $context]);
        rateLimitAbort($context, 503, 'Rate limit storage unavailable.', 'rate_store_unavailable');
    }
    $identifier = $identifier ?? ('ip:' . getClientIP());
    $key = hash('sha256', $context . ':' . strtolower($identifier));
    $file = $dir . DIRECTORY_SEPARATOR . $key . '.json';
    $now  = time();
    $cost = max(1, $cost);
    $limit = $limit ?? ($context === 'api' ? API_RATE_LIMIT : WEB_RATE_LIMIT);
    $fp = @fopen($file, 'c+');
    if ($fp === false) {
        appendLog('rate_store_error', ['context' => $context]);
        rateLimitAbort($context, 503, 'Rate limit storage unavailable.', 'rate_store_unavailable');
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        appendLog('rate_store_error', ['context' => $context]);
        rateLimitAbort($context, 503, 'Rate limit storage unavailable.', 'rate_store_unavailable');
    }
    $stat = fstat($fp);
    $size = (int)($stat['size'] ?? 0);
    $raw  = $size > 0 ? fread($fp, $size) : '';
    if ($raw === false) {
        flock($fp, LOCK_UN); fclose($fp);
        appendLog('rate_store_error', ['context' => $context]);
        rateLimitAbort($context, 503, 'Rate limit storage unavailable.', 'rate_store_unavailable');
    }
    $data = json_decode($raw, true) ?: ['count' => 0, 'reset' => $now + RATE_WINDOW];
    if (!isset($data['reset'], $data['count']) || $now > (int)$data['reset']) {
        $data = ['count' => 0, 'reset' => $now + RATE_WINDOW];
    }
    $data['count'] += $cost;
    $encoded = json_encode($data);
    $writeOk = is_string($encoded) && ftruncate($fp, 0) && rewind($fp)
        && fwrite($fp, $encoded) === strlen($encoded) && fflush($fp);
    flock($fp, LOCK_UN); fclose($fp);
    if (!$writeOk) {
        appendLog('rate_store_error', ['context' => $context]);
        rateLimitAbort($context, 503, 'Rate limit storage unavailable.', 'rate_store_unavailable');
    }

    $headers = [
        'RateLimit-Limit'       => $limit,
        'RateLimit-Remaining'   => max(0, $limit - $data['count']),
        'RateLimit-Reset'       => max(0, $data['reset'] - $now),
        'X-RateLimit-Limit'     => $limit,
        'X-RateLimit-Remaining' => max(0, $limit - $data['count']),
        'X-RateLimit-Reset'     => $data['reset'],
    ];

    if ($data['count'] > $limit) {
        appendLog('rate_limit_exceeded', ['context' => $context, 'count' => $data['count']]);
        http_response_code(429);
        header('Retry-After: ' . max(1, $data['reset'] - $now));
        if ($context === 'api') {
            foreach ($headers as $k => $v) header("$k: $v");
            rateLimitAbort('api', 429, 'Rate limit exceeded.', 'rate_limit_exceeded', [
                'retry_after' => max(1, $data['reset'] - $now),
                'reset_at' => gmdate('Y-m-d\TH:i:s\Z', $data['reset']),
            ]);
        } else {
            echo 'Rate limit exceeded. Try again after ' . gmdate('H:i', $data['reset']) . ' UTC.';
        }
        exit();
    }
    if (random_int(1, 200) === 1) {
        $cutoff = $now - (RATE_WINDOW * 2);
        foreach (glob($dir . DIRECTORY_SEPARATOR . '*.json') ?: [] as $candidate) {
            if ((int)@filemtime($candidate) < $cutoff) @unlink($candidate);
        }
    }
    return $headers;
}

/**
 * Sanitize query input (strip URLs, ports, whitespace).
 */
function sanitizeQuery(string $input): string {
    $q = trim($input);
    if (strlen($q) > 2048) return '';
    $q = preg_replace('/^https?:\/\//i', '', $q);
    $q = explode('/', $q, 2)[0];
    $q = preg_replace('/\s+/', '', $q);
    if (preg_match('/^\[([^\]]+)\](?::\d+)?$/', $q, $match)
        && filter_var($match[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return strtolower($match[1]);
    }
    if (substr_count($q, ':') <= 1) $q = preg_replace('/:\d+$/', '', $q);
    return rtrim($q, '.');
}

/**
 * Check whether a domain string is a valid query to dispatch.
 */
function classifyQuery(string $q): string {
    if (filter_var($q, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 'ipv4';
    if (filter_var($q, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'ipv6';
    if (preg_match('/^AS\d{1,10}$/i', $q))                   return 'asn';
    $ascii = idn_to_ascii($q, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($ascii !== false
        && strlen($ascii) <= API_MAX_QUERY_LENGTH
        && filter_var($ascii, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
        && substr_count($ascii, '.') >= 1)
        return 'domain';
    return 'invalid';
}
