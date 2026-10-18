<?php
declare(strict_types=1);

/** lib/network.php — safe client identity, DNS resolution, and bounded TCP I/O. */

function getClientIP(): string {
    static $cached = null;
    if ($cached !== null) return $cached;

    $ip = is_string($_SERVER['REMOTE_ADDR'] ?? null) ? trim($_SERVER['REMOTE_ADDR']) : '';
    if (TRUST_PROXY) {
        if (is_string($_SERVER['HTTP_CF_CONNECTING_IP'] ?? null)) {
            $candidate = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) $ip = $candidate;
        } elseif (is_string($_SERVER['HTTP_X_FORWARDED_FOR'] ?? null)) {
            $candidate = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'], 2)[0]);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) $ip = $candidate;
        }
    }
    return $cached = (filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'unknown');
}

function ipIsInCidr(string $ip, string $cidr): bool {
    [$network, $prefixText] = array_pad(explode('/', $cidr, 2), 2, null);
    $packedIp = @inet_pton($ip);
    $packedNetwork = @inet_pton((string)$network);
    if ($packedIp === false || $packedNetwork === false || strlen($packedIp) !== strlen($packedNetwork)) return false;
    $bits = strlen($packedIp) * 8;
    $prefix = filter_var($prefixText, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => $bits]]);
    if ($prefix === false) return false;
    $fullBytes = intdiv((int)$prefix, 8);
    $remainingBits = (int)$prefix % 8;
    if ($fullBytes > 0 && substr($packedIp, 0, $fullBytes) !== substr($packedNetwork, 0, $fullBytes)) return false;
    if ($remainingBits === 0) return true;
    $mask = (0xff << (8 - $remainingBits)) & 0xff;
    return (ord($packedIp[$fullBytes]) & $mask) === (ord($packedNetwork[$fullBytes]) & $mask);
}

function isPublicInternetIP(string $ip): bool {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return false;
    static $nonGlobalCidrs = [
        '0.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
        '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '198.18.0.0/15',
        '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
        '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b:1::/48', '100::/64',
        '2001:2::/48', '2001:10::/28', '2001:db8::/32', '2001:20::/28',
        '2002::/16', '3fff::/20', '5f00::/16', 'fc00::/7', 'fe80::/10', 'ff00::/8',
    ];
    foreach ($nonGlobalCidrs as $cidr) if (ipIsInCidr($ip, $cidr)) return false;
    return true;
}

/** @return list<string> */
function resolvePublicHostIPs(string $host): array {
    static $cache = [];
    $host = strtolower(rtrim(trim($host), '.'));
    if ($host === '') return [];
    if (array_key_exists($host, $cache)) return $cache[$host];
    if (filter_var($host, FILTER_VALIDATE_IP)) return $cache[$host] = (isPublicInternetIP($host) ? [$host] : []);
    if (!filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) return $cache[$host] = [];

    $records = @dns_get_record($host, DNS_A | DNS_AAAA);
    if (!is_array($records)) return $cache[$host] = [];
    $ips = [];
    foreach ($records as $record) {
        $ip = $record['ip'] ?? $record['ipv6'] ?? null;
        if (is_string($ip) && isPublicInternetIP($ip)) $ips[] = $ip;
    }
    return $cache[$host] = array_values(array_unique($ips));
}

/** Resolve a hostname to one public address and pin the subsequent socket to it. */
function getSafeWhoisIP(string $host): ?string {
    $ips = resolvePublicHostIPs($host);
    return $ips[0] ?? null;
}

function normalizeWhoisServerHost(string $server): ?string {
    $server = strtolower(trim($server));
    $server = preg_replace('#^whois://#i', '', $server) ?? '';
    $server = rtrim($server, '.');
    if (str_contains($server, '/') || str_contains($server, '@') || preg_match('/[\x00-\x20]/', $server)) return null;
    // WHOIS referrals occasionally include :43; custom ports are not accepted.
    $server = preg_replace('/\:43$/', '', $server) ?? '';
    if (filter_var($server, FILTER_VALIDATE_IP)) return $server;
    return filter_var($server, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) ? $server : null;
}

/**
 * Query a line-oriented TCP service with separate connect and total deadlines.
 *
 * @return list<string>
 */
function queryTextServer(string $server, int $port, string $query, int $timeout = WHOIS_TOTAL_TIMEOUT): array {
    $host = normalizeWhoisServerHost($server);
    if ($host === null || $port < 1 || $port > 65535) return [];
    if (isset($GLOBALS['SUPER_WHOIS_TEXT_TRANSPORT']) && is_callable($GLOBALS['SUPER_WHOIS_TEXT_TRANSPORT'])) {
        $lines = ($GLOBALS['SUPER_WHOIS_TEXT_TRANSPORT'])($host, $port, $query, $timeout);
        if (!is_array($lines)) return [];
        return array_values(array_map('strval', $lines));
    }
    $ip = getSafeWhoisIP($host);
    if ($ip === null) return [];

    $connectTimeout = max(1, min(WHOIS_CONNECT_TIMEOUT, $timeout));
    $socketHost = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "[$ip]" : $ip;
    $started = microtime(true);
    $socket = @fsockopen($socketHost, $port, $errno, $errstr, $connectTimeout);
    if ($socket === false) return [];

    $deadline = $started + max(1, $timeout);
    if (@fwrite($socket, $query . "\r\n") === false) { fclose($socket); return []; }
    $raw = '';
    while (!feof($socket) && strlen($raw) < WHOIS_MAX_RESPONSE_BYTES) {
        $remaining = $deadline - microtime(true);
        if ($remaining <= 0) break;
        $seconds = (int)floor($remaining);
        $micros = (int)(($remaining - $seconds) * 1000000);
        stream_set_timeout($socket, $seconds, $micros);
        $chunk = fgets($socket, 4096);
        if ($chunk === false) break;
        $raw .= $chunk;
    }
    fclose($socket);

    $raw = trim($raw);
    if ($raw === '') return [];
    $lines = preg_split('/\r?\n/', $raw);
    return is_array($lines) ? array_values($lines) : [];
}

/** @return list<string> */
function queryWhoisServer(string $server, string $query, int $timeout = WHOIS_TOTAL_TIMEOUT): array {
    return queryTextServer($server, 43, $query, $timeout);
}

/**
 * Query a registry WHOIS server and follow at most one safe registrar referral.
 *
 * @return array{0:list<string>,1:string}
 */
function resolveFullWhois(string $server, string $query): array {
    $normalized = normalizeWhoisServerHost($server);
    if ($normalized === null) return [[], $server];
    $lines = queryWhoisServer($normalized, $query);
    if ($lines === []) return [[], $normalized];

    $referral = null;
    foreach ($lines as $line) {
        if (preg_match('/^Registrar WHOIS Server\s*:\s*(.+)$/i', trim($line), $match)) {
            $candidate = normalizeWhoisServerHost($match[1]);
            if ($candidate !== null && strcasecmp($candidate, $normalized) !== 0) {
                $referral = $candidate;
                break;
            }
        }
    }
    if ($referral !== null) {
        $full = queryWhoisServer($referral, $query, min(5, WHOIS_TOTAL_TIMEOUT));
        if (count($full) > 5 && !whoisLooksLikeDenied($full) && !whoisIndicatesDomainAvailable($full)) {
            $queryParts = preg_split('/\s+/', trim($query));
            $expectedDomain = preg_replace('/\/e$/i', '', (string)end($queryParts));
            $mismatched = false;
            foreach ($full as $line) {
                if (preg_match('/^(?:domain(?:\s+name)?\s*:|\[domain name\])\s*(\S+)/i', trim($line), $match)
                    && strcasecmp(rtrim($match[1], '.'), $expectedDomain) !== 0) {
                    $mismatched = true;
                    break;
                }
            }
            if (!$mismatched && whoisHasRegistrationEvidence($full, parseWhoisData(censorIPs($full)))) return [$full, $referral];
        }
    }
    return [$lines, $normalized];
}
