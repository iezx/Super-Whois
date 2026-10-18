<?php
declare(strict_types=1);

/** lib/rdap.php — safe RDAP transport, IANA discovery, and normalization. */

/**
 * @return array{url:string,host:string,port:int,ips:list<string>}|null
 */
function validateRdapUrl(string $url): ?array {
    $parts = parse_url(trim($url));
    if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https') return null;
    if (isset($parts['user']) || isset($parts['pass'])) return null;
    $rawHost = strtolower((string)($parts['host'] ?? ''));
    if ($rawHost === '' || str_ends_with($rawHost, '.')) return null;
    $host = $rawHost;
    $port = (int)($parts['port'] ?? 443);
    if ($host === '' || $port !== 443) return null;
    $ips = resolvePublicHostIPs($host);
    if ($ips === []) return null;
    $path = (string)($parts['path'] ?? '/');
    if ($path === '' || $path[0] !== '/') $path = '/' . $path;
    $canonicalUrl = 'https://' . $host . $path;
    if (isset($parts['query'])) $canonicalUrl .= '?' . $parts['query'];
    return ['url' => $canonicalUrl, 'host' => $host, 'port' => $port, 'ips' => $ips];
}

/** @return array<string,string> */
function normalizeHttpHeaders(array $lines): array {
    $headers = [];
    foreach ($lines as $line) {
        if (!is_string($line) || !str_contains($line, ':')) continue;
        [$name, $value] = explode(':', $line, 2);
        $name = strtolower(trim($name));
        if ($name !== '') $headers[$name] = trim($value);
    }
    return $headers;
}

function resolveRdapRedirectUrl(string $currentUrl, string $location): ?string {
    $location = trim($location);
    if ($location === '' || preg_match('/[\x00-\x1f\x7f]/', $location)) return null;
    if (preg_match('#^https://#i', $location)) return preg_replace('/#.*$/', '', $location);
    if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $location) || str_starts_with($location, '//')) return null;

    $parts = parse_url($currentUrl);
    if (!is_array($parts) || empty($parts['host'])) return null;
    $origin = 'https://' . $parts['host'];
    if (str_starts_with($location, '/')) return $origin . preg_replace('/#.*$/', '', $location);
    $path = (string)($parts['path'] ?? '/');
    $directory = preg_replace('#/[^/]*$#', '/', $path) ?: '/';
    return $origin . $directory . preg_replace('/#.*$/', '', $location);
}

/**
 * Execute one redirect-disabled RDAP request.
 *
 * @return array{code:int,body:string,headers:array<string,string>,error:string,url:string,elapsed_ms:int}
 */
function fetchRdapOnce(string $url): array {
    $validated = validateRdapUrl($url);
    if ($validated === null) {
        return ['code' => 0, 'body' => '', 'headers' => [], 'error' => 'unsafe_url', 'url' => $url, 'elapsed_ms' => 0];
    }

    $started = microtime(true);
    if (function_exists('curl_init')) {
        $body = '';
        $headerLines = [];
        $tooLarge = false;
        $url = $validated['url'];
        $curl = curl_init($url);
        $pinnedIp = $validated['ips'][0];
        $resolveIp = filter_var($pinnedIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "[$pinnedIp]" : $pinnedIp;
        curl_setopt_array($curl, [
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_CONNECTTIMEOUT_MS => RDAP_CONNECT_TIMEOUT * 1000,
            CURLOPT_TIMEOUT_MS => RDAP_TOTAL_TIMEOUT * 1000,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_PROXY => '',
            CURLOPT_NOPROXY => '*',
            CURLOPT_USERAGENT => 'SuperWhois/' . SUPER_WHOIS_VERSION,
            CURLOPT_HTTPHEADER => ['Accept: application/rdap+json, application/json'],
            CURLOPT_ENCODING => '',
            CURLOPT_RESOLVE => [$validated['host'] . ':443:' . $resolveIp],
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$headerLines): int {
                if (preg_match('#^HTTP/#i', $line)) $headerLines = [];
                else $headerLines[] = trim($line);
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$body, &$tooLarge): int {
                if (strlen($body) + strlen($chunk) > RDAP_MAX_RESPONSE_BYTES) {
                    $tooLarge = true;
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($curl);
        $code = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $error = $tooLarge ? 'response_too_large' : ($ok === false ? (curl_error($curl) ?: 'transport_error') : '');
        unset($curl);
        return [
            'code' => $code,
            'body' => $tooLarge ? '' : $body,
            'headers' => normalizeHttpHeaders($headerLines),
            'error' => $error,
            'url' => $url,
            'elapsed_ms' => (int)round((microtime(true) - $started) * 1000),
        ];
    }

    // PHP's HTTPS stream wrapper performs a second DNS lookup and cannot pin
    // the validated address. Fail closed and let the engine use safe WHOIS.
    return [
        'code' => 0,
        'body' => '',
        'headers' => [],
        'error' => 'curl_extension_required',
        'url' => $validated['url'],
        'elapsed_ms' => (int)round((microtime(true) - $started) * 1000),
    ];
}

/**
 * Fetch an RDAP response, manually validating every redirect hop.
 * A test may inject SUPER_WHOIS_RDAP_TRANSPORT as a callable.
 */
function whoisFetchRdapResponse(string $url): array {
    if (isset($GLOBALS['SUPER_WHOIS_RDAP_TRANSPORT']) && is_callable($GLOBALS['SUPER_WHOIS_RDAP_TRANSPORT'])) {
        return ($GLOBALS['SUPER_WHOIS_RDAP_TRANSPORT'])($url);
    }

    $current = $url;
    for ($redirects = 0; $redirects <= RDAP_MAX_REDIRECTS; $redirects++) {
        $response = fetchRdapOnce($current);
        if (!in_array((int)$response['code'], [301, 302, 303, 307, 308], true)) return $response;
        $location = $response['headers']['location'] ?? '';
        $next = resolveRdapRedirectUrl($current, $location);
        if ($next === null || validateRdapUrl($next) === null) {
            $response['error'] = 'unsafe_redirect';
            return $response;
        }
        $current = $next;
    }
    return ['code' => 0, 'body' => '', 'headers' => [], 'error' => 'too_many_redirects', 'url' => $current, 'elapsed_ms' => 0];
}

function getRdapBootstrapData(): array {
    static $cache = null;
    if (is_array($cache)) return $cache;
    $data = cacheGetOrFetch('rdap_bootstrap_v2', CACHE_TTL_RDAP, static function () {
        $response = whoisFetchRdapResponse('https://data.iana.org/rdap/dns.json');
        if ((int)$response['code'] !== 200 || $response['body'] === '') return null;
        $json = json_decode($response['body'], true);
        if (!is_array($json) || empty($json['services']) || !is_array($json['services'])) return null;
        return $json;
    });
    return $cache = is_array($data) ? $data : [];
}

/** @return array<string,list<string>> */
function getRdapBootstrapIndex(): array {
    static $index = null;
    if (is_array($index)) return $index;
    $index = [];
    foreach (getRdapBootstrapData()['services'] ?? [] as $service) {
        if (!is_array($service) || count($service) < 2 || !is_array($service[0]) || !is_array($service[1])) continue;
        $bases = [];
        foreach ($service[1] as $base) {
            $base = rtrim(trim((string)$base), '/') . '/';
            // RFC 9224 prefers HTTPS. Super Whois intentionally rejects the
            // two remaining plaintext entries and falls back to WHOIS.
            if (str_starts_with(strtolower($base), 'https://')) $bases[] = $base;
        }
        $bases = array_values(array_unique($bases));
        if ($bases === []) continue;
        foreach ($service[0] as $suffix) {
            $suffix = strtolower(trim((string)$suffix, '.'));
            if ($suffix !== '') $index[$suffix] = $bases;
        }
    }
    return $index;
}

/** @return list<string> */
function resolveRdapBasesForDomain(string $domainAscii): array {
    $labels = explode('.', strtolower(trim($domainAscii, '.')));
    $index = getRdapBootstrapIndex();
    for ($i = 0, $count = count($labels); $i < $count; $i++) {
        $candidate = implode('.', array_slice($labels, $i));
        if (isset($index[$candidate])) return $index[$candidate];
    }
    return [];
}

function resolveRdapBaseForDomain(string $domainAscii): ?string {
    return resolveRdapBasesForDomain($domainAscii)[0] ?? null;
}

function rdapCircuitKey(string $base): string {
    return 'rdap_circuit:' . strtolower(rtrim($base, '/'));
}

function markRdapCircuitFailure(string $base, string $reason, int $ttl = RDAP_CIRCUIT_TTL): void {
    cacheWriteEntry(rdapCircuitKey($base), ['reason' => $reason], max(1, $ttl));
}

function rdapCircuitIsOpen(string $base): bool {
    $entry = cacheReadEntry(rdapCircuitKey($base));
    return $entry['hit'] && !$entry['stale'];
}

/** Perform an authoritative RDAP lookup and normalize it for the common engine. */
function lookupDomainViaRdap(string $domainAscii, ?array $preferredBases = null): ?array {
    $bases = [];
    foreach (resolveRdapBasesForDomain($domainAscii) as $base) {
        $bases[] = ['url' => $base, 'authoritative' => true, 'source' => 'iana'];
    }
    foreach ($preferredBases ?? [] as $base) {
        $base = rtrim(trim((string)$base), '/') . '/';
        if ($base !== '/') $bases[] = ['url' => $base, 'authoritative' => false, 'source' => 'preferred'];
    }

    $deduped = [];
    foreach ($bases as $base) {
        $key = strtolower(rtrim($base['url'], '/'));
        if (!isset($deduped[$key]) || $base['authoritative']) $deduped[$key] = $base;
    }

    foreach ($deduped as $baseInfo) {
        $base = rtrim($baseInfo['url'], '/');
        if (rdapCircuitIsOpen($base)) continue;
        $url = $base . '/domain/' . rawurlencode($domainAscii);
        $response = whoisFetchRdapResponse($url);
        $code = (int)($response['code'] ?? 0);
        $host = parse_url($base, PHP_URL_HOST) ?: $base;

        if ($code === 404 && $baseInfo['authoritative'] && empty($response['error'])) {
            return [
                'status' => 'available',
                'availability' => 'not_found',
                'method' => 'rdap',
                'server' => (string)$host,
                'parsed' => [],
                'raw' => ["RDAP 404 from $host", 'Authoritative RDAP returned not found; registration eligibility is not guaranteed.'],
                'upstream_status' => 404,
            ];
        }
        if ($code === 200) {
            $json = json_decode((string)($response['body'] ?? ''), true);
            if (!is_array($json) || strtolower((string)($json['objectClassName'] ?? '')) !== 'domain') {
                markRdapCircuitFailure($base, 'invalid_rdap_json');
                appendLog('rdap_invalid_response', ['domain' => $domainAscii, 'base' => $base]);
                continue;
            }
            cacheDelete(rdapCircuitKey($base));
            $raw = ["RDAP 200 from $host", '--- RDAP JSON ---'];
            $raw[] = json_encode($json, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) ?: '{}';
            return [
                'status' => 'registered',
                'method' => 'rdap',
                'server' => (string)$host,
                'parsed' => whoisParseRdapDomainData($json),
                'raw' => $raw,
                'upstream_status' => 200,
            ];
        }

        $retryAfter = (int)($response['headers']['retry-after'] ?? 0);
        if ($code === 429) {
            markRdapCircuitFailure($base, 'rate_limited', $retryAfter > 0 ? min($retryAfter, 300) : RDAP_CIRCUIT_TTL);
            appendLog('rdap_rate_limited', ['domain' => $domainAscii, 'base' => $base, 'retry_after' => $retryAfter]);
        } elseif (in_array($code, [401, 403], true)) {
            markRdapCircuitFailure($base, 'access_denied');
            appendLog('rdap_access_denied', ['domain' => $domainAscii, 'base' => $base, 'code' => $code]);
        } elseif ($code >= 500 || $code === 0 || !empty($response['error'])) {
            markRdapCircuitFailure($base, (string)($response['error'] ?: "http_$code"));
            appendLog('rdap_upstream_error', ['domain' => $domainAscii, 'base' => $base, 'code' => $code, 'error' => $response['error'] ?? '']);
        } else {
            appendLog('rdap_unexpected_code', ['domain' => $domainAscii, 'base' => $base, 'code' => $code]);
        }
    }
    return null;
}

function rdapVcardValue(array $vcard, string $type): mixed {
    foreach ($vcard as $value) {
        if (is_array($value) && count($value) >= 4 && strtolower((string)$value[0]) === $type) return $value[3];
    }
    return null;
}

function rdapVcardAddress(array $vcard): array {
    foreach ($vcard as $value) {
        if (!is_array($value) || count($value) < 4 || strtolower((string)$value[0]) !== 'adr') continue;
        $parts = is_array($value[3]) ? array_values($value[3]) : [];
        $params = is_array($value[1] ?? null) ? $value[1] : [];
        $fields = [
            'street' => [$parts[0] ?? '', $parts[1] ?? '', $parts[2] ?? ''],
            'locality' => $parts[3] ?? null,
            'region' => $parts[4] ?? null,
            'postal_code' => $parts[5] ?? null,
            'country' => $params['cc'] ?? $parts[6] ?? null,
        ];
        $out = [];
        foreach ($fields as $key => $part) {
            $part = rdapScalarString($part);
            if ($part !== null) $out[$key] = $part;
        }
        if (empty($out['street'])) {
            $label = rdapScalarString($params['label'] ?? null);
            if ($label !== null) $out['street'] = preg_replace('/\s+/u', ' ', $label);
        }
        if ($out !== []) return $out;
    }
    return [];
}

function rdapScalarString(mixed $value): ?string {
    if (is_array($value)) {
        $parts = [];
        array_walk_recursive($value, static function ($item) use (&$parts): void {
            if (is_scalar($item) && trim((string)$item) !== '') $parts[] = trim((string)$item);
        });
        $value = implode(' ', $parts);
    }
    if (!is_scalar($value)) return null;
    $value = trim((string)$value);
    return $value === '' ? null : preg_replace('/^(?:mailto:|tel:)/i', '', $value);
}

function whoisParseRdapDomainData(array $rdap): array {
    $out = [];
    foreach (($rdap['events'] ?? []) as $event) {
        if (!is_array($event) || empty($event['eventAction']) || empty($event['eventDate'])) continue;
        $action = strtolower((string)$event['eventAction']);
        $date = (string)$event['eventDate'];
        if (in_array($action, ['registration', 'registered'], true) && empty($out['creation_date'])) $out['creation_date'] = $date;
        if (in_array($action, ['expiration', 'expiry'], true) && empty($out['expiration_date'])) $out['expiration_date'] = $date;
        if (in_array($action, ['last changed', 'last update of rdap database'], true) && empty($out['updated_date'])) $out['updated_date'] = $date;
    }
    if (is_array($rdap['status'] ?? null)) $out['status'] = array_values(array_filter(array_map('strval', $rdap['status'])));

    $nameservers = [];
    foreach (($rdap['nameservers'] ?? []) as $nameserver) {
        if (!is_array($nameserver)) continue;
        $name = $nameserver['ldhName'] ?? $nameserver['unicodeName'] ?? null;
        if (is_string($name) && $name !== '') $nameservers[] = strtolower($name);
    }
    if ($nameservers !== []) {
        $nameservers = array_values(array_unique($nameservers));
        sort($nameservers, SORT_STRING);
        $out['nameservers'] = $nameservers;
    }
    if (is_array($rdap['secureDNS'] ?? null) && array_key_exists('delegationSigned', $rdap['secureDNS'])) {
        $out['dnssec'] = !empty($rdap['secureDNS']['delegationSigned']) ? 'signed' : 'unsigned';
    }

    foreach (($rdap['entities'] ?? []) as $entity) {
        if (!is_array($entity)) continue;
        $roles = array_map('strtolower', array_map('strval', is_array($entity['roles'] ?? null) ? $entity['roles'] : []));
        $vcard = $entity['vcardArray'][1] ?? [];
        if (!is_array($vcard)) $vcard = [];
        $fn = rdapScalarString(rdapVcardValue($vcard, 'fn'));
        $org = rdapScalarString(rdapVcardValue($vcard, 'org'));
        $email = rdapScalarString(rdapVcardValue($vcard, 'email'));
        $phone = rdapScalarString(rdapVcardValue($vcard, 'tel'));
        $address = rdapVcardAddress($vcard);

        if (in_array('registrar', $roles, true)) {
            if ($fn !== null && empty($out['registrar'])) $out['registrar'] = $fn;
            foreach (($entity['publicIds'] ?? []) as $publicId) {
                if (is_array($publicId) && stripos((string)($publicId['type'] ?? ''), 'iana') !== false && !empty($publicId['identifier'])) {
                    $out['registrar_iana_id'] = (string)$publicId['identifier'];
                    break;
                }
            }
            if (empty($out['registrar_iana_id']) && !empty($entity['handle'])) $out['registrar_iana_id'] = (string)$entity['handle'];
        }
        if (in_array('registrant', $roles, true)) {
            if ($fn !== null && empty($out['registrant_name'])) $out['registrant_name'] = $fn;
            if ($org !== null && empty($out['registrant_org'])) $out['registrant_org'] = $org;
            if ($email !== null && empty($out['registrant_email'])) $out['registrant_email'] = $email;
            if ($phone !== null && empty($out['registrant_phone'])) $out['registrant_phone'] = $phone;
            foreach ([
                'street' => 'registrant_address',
                'locality' => 'registrant_city',
                'region' => 'registrant_region',
                'postal_code' => 'registrant_postal_code',
                'country' => 'registrant_country',
            ] as $addressKey => $field) {
                if (!empty($address[$addressKey]) && empty($out[$field])) $out[$field] = $address[$addressKey];
            }
        }
        if (in_array('administrative', $roles, true) && $email !== null && empty($out['admin_email'])) $out['admin_email'] = $email;
        if (in_array('technical', $roles, true) && $email !== null && empty($out['tech_email'])) $out['tech_email'] = $email;
        if (in_array('abuse', $roles, true)) {
            if ($email !== null && empty($out['abuse_email'])) $out['abuse_email'] = $email;
            if ($phone !== null && empty($out['abuse_phone'])) $out['abuse_phone'] = $phone;
        }
    }
    return array_filter($out, static fn($value) => $value !== null && $value !== [] && $value !== '');
}
