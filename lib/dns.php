<?php
// lib/dns.php — DNS record lookup (A, AAAA, MX, TXT, NS, CNAME)

/**
 * Fetch DNS records (A, AAAA, MX, TXT, NS) for a domain.
 * Returns structured data suitable for JSON output.
 */
function lookupDNSRecords(string $domain): array {
    $ascii = idn_to_ascii(trim($domain, '.'), IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($ascii === false || !filter_var($ascii, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        return ['domain' => $domain, 'records' => [], 'errors' => ['Invalid domain.'], 'cached' => false, 'cache_age_s' => 0];
    }
    $ascii = strtolower($ascii);
    $cached = cacheGetOrCompute(
        'dns_lookup_v1:' . $ascii,
        static fn() => lookupDNSRecordsUncached($ascii),
        static function ($value): int {
            $ttls = [];
            foreach (($value['records'] ?? []) as $records) {
                foreach ($records as $record) {
                    if (isset($record['ttl']) && is_numeric($record['ttl'])) $ttls[] = (int)$record['ttl'];
                }
            }
            return $ttls === [] ? 30 : max(30, min(300, min($ttls)));
        },
        static fn() => false,
        0
    );
    $result = is_array($cached['value']) ? $cached['value'] : ['domain' => $ascii, 'records' => [], 'errors' => ['DNS lookup failed.']];
    $result['cached'] = $cached['hit'];
    $result['cache_age_s'] = $cached['age'];
    return $result;
}

function lookupDNSRecordsUncached(string $domain): array {
    $result = [
        'domain' => $domain,
        'records' => [],
        'errors'  => [],
    ];

    // A records
    $aRecords = @dns_get_record($domain, DNS_A);
    if ($aRecords !== false) {
        foreach ($aRecords as $r) {
            $result['records']['A'][] = [
                'ip'       => $r['ip'] ?? '',
                'ttl'      => $r['ttl'] ?? null,
            ];
        }
    }

    // AAAA records
    $aaaaRecords = @dns_get_record($domain, DNS_AAAA);
    if ($aaaaRecords !== false) {
        foreach ($aaaaRecords as $r) {
            $result['records']['AAAA'][] = [
                'ipv6'     => $r['ipv6'] ?? '',
                'ttl'      => $r['ttl'] ?? null,
            ];
        }
    }

    // MX records
    $mxRecords = @dns_get_record($domain, DNS_MX);
    if ($mxRecords !== false) {
        usort($mxRecords, fn($a, $b) => ($a['pri'] ?? 0) <=> ($b['pri'] ?? 0));
        foreach ($mxRecords as $r) {
            $result['records']['MX'][] = [
                'host'     => $r['target'] ?? '',
                'priority' => $r['pri'] ?? null,
                'ttl'      => $r['ttl'] ?? null,
            ];
        }
    }

    // TXT records
    $txtRecords = @dns_get_record($domain, DNS_TXT);
    if ($txtRecords !== false) {
        foreach ($txtRecords as $r) {
            $txt = $r['txt'] ?? '';
            if ($txt !== '') {
                $result['records']['TXT'][] = [
                    'txt' => $txt,
                    'ttl' => $r['ttl'] ?? null,
                ];
            }
        }
    }

    // NS records
    $nsRecords = @dns_get_record($domain, DNS_NS);
    if ($nsRecords !== false) {
        foreach ($nsRecords as $r) {
            $result['records']['NS'][] = [
                'target' => $r['target'] ?? '',
                'ttl'    => $r['ttl'] ?? null,
            ];
        }
    }

    // CNAME records (only if no other records exist for this name)
    $cnameRecords = @dns_get_record($domain, DNS_CNAME);
    if ($cnameRecords !== false) {
        foreach ($cnameRecords as $r) {
            $result['records']['CNAME'][] = [
                'target' => $r['target'] ?? '',
                'ttl'    => $r['ttl'] ?? null,
            ];
        }
    }

    if (empty($result['records'])) {
        $result['errors'][] = 'No DNS records found.';
    }

    return $result;
}
