<?php
declare(strict_types=1);
// lib/whois.php — WHOIS lookup, fallback chain, routing, and server resolution

// ── Restricted WHOIS / RDAP fallback ───────────────────────────────────────

/**
 * Web WHOIS portals for TLDs that often block direct port-43 access.
 */
function whoisGetWebLookupUrl(string $tld): ?string {
    static $map = [
        'ch' => 'https://www.nic.ch/whois/',
        'li' => 'https://www.nic.li/',
        'es' => 'https://www.dominios.es/en/tools/search',
        'ao' => 'https://dns.ao/',
        'tt' => 'https://whois.nic.tt/',
        'uy' => 'https://nic.uy/whois/',
        'ba' => 'https://www.nic.ba/',
        // IANA lists the .SB registration portal at nic.net.sb.
        'sb' => 'http://www.nic.net.sb/',
        'gr' => 'https://grweb.ics.forth.gr/public/whois',
        'it' => 'https://www.nic.it/en/tools/whois',
        'fr' => 'https://www.afnic.fr/',
        'eu' => 'https://www.eurid.eu/en/register-a-eu-domain/whois-domain-lookup/',
        'nl' => 'https://www.sidn.nl/whois',
        'br' => 'https://registro.br/tecnologia/ferramentas/whois/',
        'pl' => 'https://www.dns.pl/en/whois',
        'pt' => 'https://www.dns.pt/en/services/whois/',
        'se' => 'https://internetstiftelsen.se/en/domain/',
        'fi' => 'https://domain.fi/info/en/index/services/whois.html',
        'no' => 'https://www.norid.no/en/om-domenenavn/sjekk-domenenavn/',
        'at' => 'https://www.nic.at/en/service/whois-service',
        'dk' => 'https://www.dk-hostmaster.dk/en/find-whois',
        'cz' => 'https://www.nic.cz/whois/',
        'sk' => 'https://www.sk-nic.sk/en/whois/',
        'ro' => 'https://www.rotld.ro/en/whois/',
        'hr' => 'https://www.dns.hr/en/whois',
        'tr' => 'https://www.nic.tr/whois.php',
        'cn' => 'https://whois.cnnic.cn/',
        'jp' => 'https://jprs.jp/en/whois/',
        'kr' => 'https://whois.kr/',
        'tw' => 'https://whois.twnic.net.tw/',
        'hk' => 'https://www.hkdnr.hk/en_US/whois-search/',
        'sg' => 'https://www.sgnic.sg/domain-registration/whois-search',
        'my' => 'https://mynic.my/en/whois/',
        'id' => 'https://pandi.id/en/domain/whois/',
        'th' => 'https://whois.thnic.co.th/',
        'vn' => 'https://whois.vnnic.vn/',
        'ph' => 'https://www.dot.ph/whois',
        'nz' => 'https://www.dnc.org.nz/whois/search-the-whois-database/',
        'au' => 'https://whois.auda.org.au/',
        'za' => 'https://www.registry.net.za/whois.php',
    ];
    $tld = strtolower(trim($tld, '.'));
    return $map[$tld] ?? (getIANARegistryMetadata($tld)['url'] ?? null);
}

/**
 * True if WHOIS response clearly indicates access-denied/rate-limited.
 */
function whoisLooksLikeDenied(array $lines): bool {
    $raw = strtolower(implode("\n", $lines));
    $patterns = [
        '/\baccess denied\b/i',
        '/\baccess restricted\b/i',
        '/\bquery(?:ing)? (?:is )?not permitted\b/i',
        '/\brequests?\s+of\s+this\s+client\s+are\s+not\s+permitted\b/i',
        '/\bqueries? (?:from|for) your (?:ip|host) (?:address )?(?:have been )?(?:blocked|denied)\b/i',
        '/\bquota exceeded\b/i',
        '/\brate[\s-]?limit(?:ed|ing)?\b/i',
        '/\btoo many requests\b/i',
        '/\berror:\s*55\b/i',
        '/\bport\s*43\s*(?:queries?|access)\s*(?:are )?(?:not supported|not allowed|disabled)\b/i',
        '/\bplease use (?:the )?web whois\b/i',
        '/\bwhois service unavailable\b/i',
        // Chinese denial patterns
        '/查询过于频繁/u',
        '/访问被拒绝/u',
        '/请求被拒绝/u',
        '/连接被拒绝/u',
        '/您的IP.*(?:已被|被)\s*(?:限制|禁止|封锁)/u',
        '/该IP.*(?:已被|被)\s*(?:限制|禁止|封锁)/u',
        '/超出查询.*限制/u',
        '/已被禁止查询/u',
        '/请稍后再试/u',
        '/服务不可用/u',
        // Additional English patterns
        '/\bquery refused\b/i',
        '/\bconnection has been rejected\b/i',
        '/\btemporarily blocked\b/i',
        '/\byour ip has been (?:temporarily )?(?:blocked|blacklisted)\b/i',
    ];
    foreach ($patterns as $p) {
        if (preg_match($p, $raw) === 1) return true;
    }
    if (preg_match('/\bno whois server\b/i', $raw) === 1 && preg_match('/\bdomain name:\b/i', $raw) !== 1) {
        return true;
    }

    return false;
}

function whoisIndicatesDomainAvailable(array $lines, string $domain = ''): bool {
    $patterns = [
        '/^no match for\b/i',
        '/^(?:domain\s+)?not found\.?$/i',
        '/^no (?:matching )?(?:record|entries|data)(?: found)?(?: in (?:the )?database)?\.?$/i',
        '/^no entries found(?: for .+)?\.?$/i',
        '/^(?:the )?domain\b.+\bis not registered\.?$/i',
        '/^(?:object|domain) does not exist\.?$/i',
        '/^no object found\.?$/i',
        '/^status\s*:\s*(?:free|available)\b/i',
        '/^available for registration\.?$/i',
        '/^(?:没有匹配的记录|域名不存在|该域名尚未注册|你要查询的域名不存在|该域名没有注册记录|没有找到相关信息|查詢的域名不存在|查询的域名不存在)[。.]?$/u',
    ];
    foreach ($lines as $line) {
        $line = trim((string)$line, " \t\r\n%>");
        if ($domain !== '' && preg_match('/^no match for\s+["\']?([a-z0-9.-]+)["\']?\.?$/i', $line, $match)) {
            if (strcasecmp(rtrim($match[1], '.'), rtrim($domain, '.')) === 0) return true;
            continue;
        }
        if ($domain !== '' && preg_match('/^' . preg_quote($domain, '/') . '\s+is free\.?$/i', $line) === 1) return true;
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $line) === 1) return true;
        }
    }
    return false;
}

function whoisHasRegistrationEvidence(array $lines, array $parsed = []): bool {
    foreach (['registrar', 'creation_date', 'expiration_date', 'updated_date', 'nameservers', 'status',
              'registrant_name', 'registrant_org', 'registrant_country', 'registrant_address', 'registrant_city', 'registrant_region', 'registrant_postal_code'] as $field) {
        if (!empty($parsed[$field])) return true;
    }
    foreach ($lines as $line) {
        if (preg_match('/^(?:domain(?:\s+name)?|object|registrar|name\s*server|nserver)\s*:/i', trim((string)$line))) {
            return true;
        }
    }
    return false;
}

function buildWhoisDomainQueryByTld(string $domainAscii, string $tld): string {
    if ($tld === 'de') return '-T dn,ace ' . $domainAscii;
    if ($tld === 'jp') return $domainAscii . '/e';
    return $domainAscii;
}

function lookupDomainOtherMethods(string $domainAscii, array $attemptedServers = []): ?array {
    $labels = explode('.', $domainAscii);
    $tld = strtolower((string)end($labels));

    // SWITCH Domain Check for .ch/.li
    if (in_array($tld, ['ch', 'li'], true)) {
        $dcLines = queryTextServer('whois.nic.ch', 4343, $domainAscii, 7);
        if (!empty($dcLines)) {
            $joined = trim(implode("\n", $dcLines));
            if (preg_match('/^\s*1\s*:/m', $joined) === 1) {
                return [
                    'status' => 'available',
                    'method' => 'special',
                    'server' => 'whois.nic.ch:4343',
                    'parsed' => [],
                    'raw'    => array_merge(['Domain Check response (SWITCH)'], $dcLines),
                ];
            }
            if (preg_match('/^\s*0\s*:/m', $joined) === 1) {
                return [
                    'status' => 'registered',
                    'method' => 'special',
                    'server' => 'whois.nic.ch:4343',
                    'parsed' => [],
                    'raw'    => array_merge(['Domain Check response (SWITCH)'], $dcLines),
                ];
            }
        }
    }

    // IANA WHOIS discovery as final protocol-level fallback.
    $ianaServer = getIANAWhoisServer($tld);
    if ($ianaServer === null) return null;
    foreach ($attemptedServers as $attempted) {
        if (strcasecmp((string)$attempted, $ianaServer) === 0) return null;
    }
    $query = buildWhoisDomainQueryByTld($domainAscii, $tld);
    [$rawLines, $usedServer] = resolveFullWhois($ianaServer, $query);
    if (empty($rawLines) || whoisLooksLikeDenied($rawLines)) return null;

    if (whoisIndicatesDomainAvailable($rawLines, $domainAscii)) {
        return [
            'status' => 'available',
            'method' => 'whois-iana',
            'server' => $usedServer,
            'parsed' => [],
            'raw'    => $rawLines,
        ];
    }

    $censored = censorIPs($rawLines);
    $parsed = parseWhoisData($censored);
    if (!whoisHasRegistrationEvidence($censored, $parsed)) return null;
    return [
        'status' => 'registered',
        'method' => 'whois-iana',
        'server' => $usedServer,
        'parsed' => $parsed,
        'raw'    => $rawLines,
    ];
}

/**
 * Reviewed RDAP hints for special suffixes; WHOIS uses the common chain.
 */
function lookupRestrictedDomainFallback(string $domainAscii): ?array {
    $labels = explode('.', $domainAscii);
    $tld = strtolower((string)end($labels));

    // IANA bootstrap is authoritative. The one reviewed manual base remains a
    // non-authoritative compatibility fallback; its 404 is never treated as
    // proof of availability.
    if (in_array($tld, ['ch', 'li'], true)) {
        $rdap = lookupDomainViaRdap($domainAscii, ['https://rdap.nic.li/']);
    } else {
        $rdap = lookupDomainViaRdap($domainAscii);
    }
    if ($rdap !== null) return $rdap;

    return null;
}

/**
 * Unified cached domain lookup — registrable apex, RDAP first, WHOIS fallback.
 */
function lookupDomain(string $domainAscii, array $whoisServers): array {
    $inputDomain = strtolower(trim($domainAscii, '.'));
    $lookupDomain = normalizeDomainForLookup($inputDomain);
    if ($lookupDomain === null) {
        return [
            'status' => 'error',
            'error_code' => 'not_registrable',
            'method' => 'none',
            'server' => '',
            'parsed' => [],
            'raw' => ['The query is not a registrable domain under the ICANN Public Suffix List.'],
            'lookup_domain' => null,
            '_cache' => ['hit' => false, 'stale' => false, 'age' => 0],
        ];
    }

    $cacheKey = 'domain_lookup_v3:' . $lookupDomain;
    $cached = cacheGetOrCompute(
        $cacheKey,
        static fn() => boundLookupRawResult(lookupDomainUncached($lookupDomain, $whoisServers)),
        static function ($result): int {
            return match ($result['status'] ?? 'error') {
                'registered' => CACHE_TTL_REGISTERED,
                'available' => CACHE_TTL_NOT_FOUND,
                default => CACHE_TTL_ERROR,
            };
        },
        static fn($result): bool => ($result['status'] ?? 'error') === 'error',
        CACHE_STALE_MAX_AGE,
        static fn($stale): bool => is_array($stale) && ($stale['status'] ?? '') === 'registered'
    );
    $result = is_array($cached['value']) ? $cached['value'] : [
        'status' => 'error', 'method' => 'none', 'server' => '', 'parsed' => [], 'raw' => ['Lookup failed.'],
    ];
    $result['lookup_domain'] = $lookupDomain;
    if ($inputDomain !== $lookupDomain) {
        $result['input_domain'] = $inputDomain;
        $result['is_subdomain'] = true;
    }
    $result['_cache'] = ['hit' => $cached['hit'], 'stale' => $cached['stale'], 'age' => $cached['age']];
    return $result;
}

function boundLookupRawResult(array $result): array {
    if (!is_array($result['raw'] ?? null)) return $result;
    $bounded = [];
    $used = 0;
    foreach ($result['raw'] as $line) {
        $line = (string)$line;
        $remaining = LOOKUP_RAW_MAX_BYTES - $used;
        if ($remaining <= 0) { $result['raw_truncated'] = true; break; }
        if (strlen($line) + 1 > $remaining) {
            $bounded[] = substr($line, 0, max(0, $remaining - 1));
            $result['raw_truncated'] = true;
            break;
        }
        $bounded[] = $line;
        $used += strlen($line) + 1;
    }
    $result['raw'] = $bounded;
    return $result;
}

function lookupDomainUncached(string $domainAscii, array $whoisServers): array {
    $labels = explode('.', $domainAscii);
    $tld = strtolower((string)end($labels));

    // Special routes are hints; a failed RDAP route must still try WHOIS.
    $route = getRoutedProviderForDomain($domainAscii);
    if ($route !== null) {
        $result = lookupRestrictedDomainFallback($domainAscii);
        if ($result !== null) {
            $result['method'] = $result['method'] ?? ('special:' . $route['provider']);
            return $result;
        }
    }

    // Stage 2: RDAP first (for all non-routed domains)
    $rdap = $route === null ? lookupDomainViaRdap($domainAscii) : null;
    if ($rdap !== null) return $rdap;

    // Stage 3: dynamic IANA WHOIS discovery. The local snapshot remains a
    // compatibility fallback: a stale IANA referral must not prevent a
    // reviewed local route from rescuing the lookup.
    $candidateServers = [];
    foreach ([getIANAWhoisServer($tld), resolveWhoisServer($domainAscii, $whoisServers)] as $candidate) {
        if (!is_string($candidate) || $candidate === '') continue;
        $candidate = normalizeWhoisServerHost($candidate);
        if ($candidate === null) continue;
        $duplicate = false;
        foreach ($candidateServers as $known) {
            if (strcasecmp($known, $candidate) === 0) { $duplicate = true; break; }
        }
        if (!$duplicate) $candidateServers[] = $candidate;
    }

    if ($candidateServers === []) {
        $other = lookupDomainOtherMethods($domainAscii);
        if ($other !== null) return $other;
        return [
            'status' => 'error',
            'error_code' => 'no_whois_server',
            'method' => 'none',
            'server' => '',
            'attempted_servers' => [],
            'parsed' => [],
            'raw' => ['No WHOIS server is published for this TLD, and RDAP/other fallback methods failed.'],
            'web_url' => whoisGetWebLookupUrl($tld),
        ];
    }

    $attemptedServers = [];
    $lastServer = '';
    $deniedLines = null;
    $invalidLines = null;
    foreach ($candidateServers as $server) {
        $attemptedServers[] = $server;
        $query = buildWhoisDomainQueryByTld($domainAscii, $tld);
        [$rawLines, $usedServer] = resolveFullWhois($server, $query);
        $lastServer = $usedServer !== '' ? $usedServer : $server;
        if (empty($rawLines)) continue;

        if (whoisLooksLikeDenied($rawLines)) {
            if ($deniedLines === null) $deniedLines = $rawLines;
            continue;
        }

        if (whoisIndicatesDomainAvailable($rawLines, $domainAscii)) {
            return [
                'status' => 'available',
                'availability' => 'not_found',
                'method' => 'whois',
                'server' => $lastServer,
                'parsed' => [],
                'raw' => $rawLines,
            ];
        }

        $censored = censorIPs($rawLines);
        $parsed = parseWhoisData($censored);
        if (!whoisHasRegistrationEvidence($censored, $parsed)) {
            if ($invalidLines === null) $invalidLines = $rawLines;
            continue;
        }
        return [
            'status' => 'registered',
            'method' => 'whois',
            'server' => $lastServer,
            'parsed' => $parsed,
            'raw' => $rawLines,
        ];
    }

    // A final IANA referral/special method can still succeed after both
    // primary candidates time out or return a denial page.
    $other = lookupDomainOtherMethods($domainAscii, $attemptedServers);
    if ($other !== null) return $other;

    if ($deniedLines !== null) {
        return [
            'status' => 'restricted',
            'error_code' => 'registry_access_restricted',
            'method' => 'whois',
            'server' => $lastServer,
            'attempted_servers' => $attemptedServers,
            'parsed' => [],
            'raw' => $deniedLines,
            'web_url' => whoisGetWebLookupUrl($tld),
        ];
    }
    if ($invalidLines !== null) {
        return [
            'status' => 'error',
            'error_code' => 'invalid_upstream_response',
            'method' => 'whois',
            'server' => $lastServer,
            'attempted_servers' => $attemptedServers,
            'parsed' => [],
            'raw' => $invalidLines,
            'web_url' => whoisGetWebLookupUrl($tld),
        ];
    }
    return [
        'status' => 'error',
        'error_code' => 'whois_unreachable',
        'method' => 'whois',
        'server' => $lastServer,
        'attempted_servers' => $attemptedServers,
        'parsed' => [],
        'raw' => ['Could not reach any published WHOIS server. TCP/43 may be blocked by the deployment network or the registry may be temporarily unavailable.'],
        'web_url' => whoisGetWebLookupUrl($tld),
    ];
}

/**
 * Provider routing table for suffixes requiring dedicated lookup methods.
 */
function getRoutedProviderForDomain(string $domainAscii): ?array {
    $domainAscii = strtolower(trim($domainAscii, '.'));
    if ($domainAscii === '' || !str_contains($domainAscii, '.')) return null;

    static $routes = [
        'nic_ch' => ['ch'],
        'nic_li' => ['li'],
        'ao_session_web' => ['ao'],
        'nic_tt' => ['tt'],
        'nic_uy' => ['uy'],
        'nic_ba' => ['ba'],
        'nic_gr' => ['gr'],
        'nic_hk' => ['hk', 'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk', 'idv.hk', '公司.hk', '個人.hk', '網絡.hk', '組織.hk', '教育.hk', '政府.hk'],
        // .tw WHOIS often blocked — prefer RDAP
        'nic_tw' => ['tw', 'com.tw', 'net.tw', 'org.tw', 'edu.tw', 'gov.tw', 'idv.tw'],
        // .kr WHOIS restricted
        'nic_kr' => ['kr', 'co.kr', 'or.kr', 'ne.kr', 'go.kr', 'ac.kr', 're.kr'],
        // .cn WHOIS rate-limited
        'nic_cn' => ['cn', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn'],
        // .jp WHOIS requires special query format
        'nic_jp' => ['jp', 'co.jp', 'ne.jp', 'ac.jp', 'go.jp', 'or.jp', 'gr.jp'],
        // Legacy web provider suffixes
        'legacy_web' => [
            'bo','bn','com.bn','org.bn','net.bn','edu.bn','gov.bn',
            'bt',
            'cu','com.cu','edu.cu','gob.cu','inf.cu','nat.cu','net.cu','org.cu',
            'dz','gf','ge','gq',
            'gt','com.gt','edu.gt','org.gt','gob.gt','net.gt','ind.gt','mil.gt',
            'gy','hn','hu','jo','lk','mt',
            'np','com.np','edu.np','gov.np','net.np','org.np','mil.np','name.np','coop.np',
            'nf','om','pa','ph','sv','tj',
            've','com.ve','org.ve','info.ve','net.ve','web.ve','co.ve','emprende.ve','la.ve','1.a.ve',
            'mq',
        ],
    ];

    $best = null;
    $bestLen = -1;
    foreach ($routes as $provider => $suffixes) {
        foreach ($suffixes as $suffix) {
            $suffix = strtolower($suffix);
            if ($domainAscii === $suffix || str_ends_with($domainAscii, '.' . $suffix)) {
                $len = strlen($suffix);
                if ($len > $bestLen) {
                    $best = ['provider' => $provider, 'suffix' => $suffix];
                    $bestLen = $len;
                }
            }
        }
    }
    return $best;
}

// ── WHOIS Server Resolution ────────────────────────────────────────────────

/**
 * Find a WHOIS server from the local whois_servers.php list only.
 */
function resolveWhoisServer(string $domainAscii, array $whoisServers): ?string {
    $labels = explode('.', strtolower($domainAscii));
    // Longest suffix wins, including registry structures deeper than co.uk.
    for ($i = 0, $count = count($labels); $i < $count; $i++) {
        $suffix = implode('.', array_slice($labels, $i));
        if (isset($whoisServers[$suffix])) {
            $server = normalizeWhoisServerHost(trim((string)$whoisServers[$suffix]));
            if ($server !== null) return $server;
        }
    }
    return null;
}

/**
 * Query whois.iana.org to discover WHOIS server for unknown TLDs.
 */
function getIANAWhoisServer(string $tld): ?string {
    static $cache = [];
    $tld = strtolower(trim($tld, '.'));
    if (array_key_exists($tld, $cache)) return $cache[$tld];

    $key = 'iana_whois:' . $tld;
    $entry = cacheReadEntry($key, 0, CACHE_STALE_MAX_AGE);
    if ($entry['hit'] && is_string($entry['value'])) {
        return $cache[$tld] = $entry['value'];
    }

    $lines = queryWhoisServer('whois.iana.org', $tld, IANA_WHOIS_TIMEOUT);
    $server = null;
    foreach ($lines as $line) {
        if (preg_match('/^(?:whois|refer):\s*(.+)$/i', trim($line), $m)) {
            $server = normalizeWhoisServerHost($m[1]);
            break;
        }
    }
    if ($server === null) $server = getIANARegistryMetadata($tld)['server'] ?? null;
    // Never persist a transient discovery failure for seven days.
    if ($server !== null) cacheWriteEntry($key, $server, CACHE_TTL_IANA);
    elseif ($entry['hit'] && is_string($entry['value'])) $server = $entry['value'];
    return $cache[$tld] = $server;
}

/** HTTPS discovery also works when the deployment blocks IANA TCP/43. */
function getIANARegistryMetadata(string $tld): array {
    $tld = strtolower(trim($tld, '.'));
    if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $tld)) return [];
    static $memo = [];
    if (array_key_exists($tld, $memo)) return $memo[$tld];
    $value = cacheGetOrFetch('iana_registry_v1:' . $tld, CACHE_TTL_IANA, static function () use ($tld) {
        $response = whoisFetchRdapResponse('https://www.iana.org/domains/root/db/' . $tld . '.html');
        if (($response['code'] ?? 0) !== 200 || !empty($response['error'])) return null;
        $html = (string)($response['body'] ?? '');
        $text = html_entity_decode(preg_replace('/<[^>]*>/', ' ', $html), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $metadata = [];
        if (preg_match('/WHOIS Server:\s*([a-z0-9.-]+)/i', $text, $match)) {
            $server = normalizeWhoisServerHost($match[1]);
            if ($server !== null) $metadata['server'] = $server;
        }
        if (preg_match('~URL for registration services:.*?<a\b[^>]*href=["\'](https?://[^"\'<>]+)["\']~is', $html, $match)) {
            $url = html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if (filter_var($url, FILTER_VALIDATE_URL) && !isset(parse_url($url)['user'])) $metadata['url'] = $url;
        }
        return $metadata === [] ? null : $metadata;
    });
    return $memo[$tld] = is_array($value) ? $value : [];
}
