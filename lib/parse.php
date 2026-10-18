<?php
// lib/parse.php — WHOIS data parsing, date normalization, and display helpers

function censorIPs(array $lines): array {
    $pat = '/(\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?=[a-f0-9:.]*[a-f])(?:[a-f0-9]{1,4}:){2,7}[a-f0-9:.]+\b)/i';
    return array_map(fn($l) => preg_replace($pat, '[REDACTED]', $l), $lines);
}

function normaliseDate(string $raw): string {
    $raw   = trim($raw);
    // Strip [REDACTED] and similar noise from IP censoring
    $clean = preg_replace('/\[REDACTED\]/i', '', $raw);
    $clean = preg_replace('/\s+REDACTED\b/i', '', $clean);
    // Strip timezone abbreviations (UTC, CST, EST, etc.)
    $clean = preg_replace('/\s+[A-Z]{2,5}$/', '', $clean);
    $clean = trim($clean);
    // Handle DD.MM.YYYY format (common in .ua, .ru, etc.)
    if (preg_match('/^(\d{1,2})\.(\d{1,2})\.(\d{4})$/', $clean, $m)) {
        $clean = "$m[3]-$m[2]-$m[1]";
    }
    $ts = strtotime($clean);
    return ($ts !== false && $ts > 0) ? gmdate('Y-m-d H:i:s', $ts) . ' UTC' : $raw;
}

function normaliseDateISO(string $raw): string {
    $raw   = trim($raw);
    $clean = preg_replace('/\[REDACTED\]/i', '', $raw);
    $clean = preg_replace('/\s+REDACTED\b/i', '', $clean);
    $clean = preg_replace('/\s+[A-Z]{2,5}$/', '', $clean);
    $clean = trim($clean);
    if (preg_match('/^(\d{1,2})\.(\d{1,2})\.(\d{4})$/', $clean, $m)) {
        $clean = "$m[3]-$m[2]-$m[1]";
    }
    $ts = strtotime($clean);
    return ($ts !== false && $ts > 0) ? gmdate('Y-m-d\TH:i:s\Z', $ts) : $raw;
}

/**
 * Returns a human-readable "N years/months/days ago" string from a date.
 */
function relativeTime(string $date, string $lang = 'en'): string {
    $ts = strtotime($date);
    if (!$ts) return '';
    $diff = time() - $ts;
    $isZh = str_starts_with($lang, 'zh');
    $tw = ($lang === 'zh-tw');
    if ($diff < 0) {
        // Future — used for expiry
        $diff = abs($diff);
        if ($isZh) {
            if ($diff < 86400)       return $tw ? '今天到期' : '今天到期';
            if ($diff < 2592000)     return ($tw ? '剩餘 ' : '剩余 ') . ceil($diff / 86400) . ($tw ? ' 天' : ' 天');
            if ($diff < 31536000)    return ($tw ? '剩餘 ' : '剩余 ') . ceil($diff / 2592000) . ($tw ? ' 個月' : ' 个月');
            return ($tw ? '剩餘 ' : '剩余 ') . round($diff / 31536000, 1) . ($tw ? ' 年' : ' 年');
        } else {
            if ($diff < 86400)       return 'expires today';
            if ($diff < 2592000)     return ceil($diff / 86400) . ' days left';
            if ($diff < 31536000)    return ceil($diff / 2592000) . ' months left';
            return round($diff / 31536000, 1) . ' years left';
        }
    }
    if ($isZh) {
        if ($diff < 86400)       return '今天';
        if ($diff < 2592000)     return ceil($diff / 86400) . ($tw ? ' 天前' : ' 天前');
        if ($diff < 31536000)    return ceil($diff / 2592000) . ($tw ? ' 個月前' : ' 个月前');
        return round($diff / 31536000, 1) . ($tw ? ' 年前' : ' 年前');
    } else {
        if ($diff < 86400)       return 'today';
        if ($diff < 2592000)     return ceil($diff / 86400) . ' days ago';
        if ($diff < 31536000)    return ceil($diff / 2592000) . ' months ago';
        return round($diff / 31536000, 1) . ' years ago';
    }
}

/**
 * Parse raw WHOIS lines into structured fields for display.
 * Handles diverse formats from different registrars worldwide.
 */
/**
 * Extract a single field value from a WHOIS line.
 * Handles privacy filtering, nameserver splitting, status URL extraction.
 */
function _parseWhoisExtractField(string $line, string $pattern, string $field, bool $single, array &$info, array &$seen): void {
    $value = ltrim(trim(preg_replace($pattern, '', $line, 1)), ": \t");
    // Clean up common privacy/proxy values
    $upperVal = strtoupper($value);
    if ($value === '' || $value === '-' || $value === '.' || $value === 'N/A'
        || $upperVal === 'REDACTED FOR PRIVACY'
        || $upperVal === 'PRIVACY PROTECTED'
        || $upperVal === 'DATA PROTECTED'
        || $upperVal === 'NOT DISCLOSED'
        || $upperVal === 'NOT AVAILABLE'
        || $upperVal === 'WHOISGUARD PROTECTED'
        || $upperVal === 'REDACTED'
        || $upperVal === 'DOMAIN PRIVACY PROTECTION SERVICE'
        || $upperVal === 'DATA REDACTED'
        || $upperVal === 'NON-PUBLIC DATA'
        || preg_match('/^(?:REDACTED|PRIVACY|DATA PROTECTED|NOT DISCLOSED)/i', $value)) return;
    if (!$single) {
        if ($field === 'nameservers') {
            $value = strtolower(rtrim($value, '.'));
            $value = preg_replace('/\s+\[.*\]$/', '', $value);
            // Skip non-NS values (IP addresses, "Not Disclosed", etc.)
            if (preg_match('/^\d{1,3}(\.\d{1,3}){3}$/', $value)) return;
            if (!str_contains($value, '.')) return;
            // Handle comma-separated nameservers (some registrars use this)
            $nsParts = preg_split('/[,\s]+/', $value);
            foreach ($nsParts as $ns) {
                $ns = trim($ns);
                if ($ns === '' || !str_contains($ns, '.')) continue;
                if (!in_array($ns, $info[$field], true))
                    $info[$field][] = $ns;
            }
        } else {
            // Extract URL from status lines
            if ($field === 'status') {
                if (preg_match('/^(\S+)\s+(https?:\/\/\S+)/i', $value, $sm)) {
                    $value = $sm[1] . ' ' . $sm[2];
                }
            }
            if (!in_array($value, $info[$field], true))
                $info[$field][] = $value;
        }
    } else {
        if (!isset($seen[$field])) {
            if (in_array($field, ['creation_date','expiration_date','updated_date']))
                $value = normaliseDate($value);
            $info[$field] = $value;
            $seen[$field] = true;
        } elseif ($field === 'registrant_address' && !empty($info[$field])) {
            $info[$field] .= ', ' . $value;
        }
    }
}

function parseWhoisData(array $rawResult): array {
    $info = [
        'creation_date'      => null,
        'expiration_date'    => null,
        'updated_date'       => null,
        'registrar'          => null,
        'registrar_iana_id'  => null,
        'registrar_whois'    => null,
        'abuse_email'        => null,
        'abuse_phone'        => null,
        'registrant_name'    => null,
        'registrant_org'     => null,
        'registrant_country' => null,
        'registrant_address' => null,
        'registrant_city'    => null,
        'registrant_region'  => null,
        'registrant_postal_code' => null,
        'registrant_email'   => null,
        'registrant_phone'   => null,
        'admin_email'        => null,
        'tech_email'         => null,
        'nameservers'        => [],
        'status'             => [],
        'dnssec'             => null,
    ];
    $patterns = [
        // ── Expiration dates (global variants) ─────────────────────────
        '/^Registry Expiry Date\s*:/i'                             => ['expiration_date', true],
        '/^Registrar Registration Expiration Date\s*:/i'           => ['expiration_date', true],
        '/^(?:Expir(?:y|ation|es)\s*(?:Date|Time)|Expiration Time|paid-till|expire[sd]?|renewal[- ]?date)\s*:/i' => ['expiration_date', true],
        '/^(?:Valid Until|Valid Through|Domain Expires|Expiry\b)\s*:/i' => ['expiration_date', true],
        '/^(?:expire|exp-date|expires-on)\s*:/i'                   => ['expiration_date', true],
        '/^free-date\s*:/i'                                        => ['expiration_date', true],
        '/^paid-till\s*:/i'                                        => ['expiration_date', true],
        '/^expires\s*:/i'                                          => ['expiration_date', true],

        // ── Creation dates (global variants) ───────────────────────────
        '/^(?:Registry Creation Date|Creation Date|Registration Date|Registration Time|Created(?: Date)?|Registered (?:on|date)|Domain Registration Date|created)\s*:/i' => ['creation_date', true],
        '/^(?:Created On|First Registration Date|Registration effective date)\s*:/i' => ['creation_date', true],
        '/^(?:domain_datecreated|created-date|create-date|created_at)\s*:/i' => ['creation_date', true],
        '/^created\s*:/i'                                          => ['creation_date', true],
        '/^nserver.*\s+from\s+/i'                                  => ['creation_date', true],

        // ── Updated dates (global variants) ────────────────────────────
        '/^(?:Updated Date|Last[- ]Modified|Last[- ]Updated?|Update(?:d?)\s*Time|changed|Modified)\s*:/i' => ['updated_date', true],
        '/^(?:Last Update|Last Modified On|last-update|last_updated)\s*:/i' => ['updated_date', true],
        '/^(?:domain_datelastmodified|last-modified)\s*:/i'        => ['updated_date', true],

        // ── Registrar ──────────────────────────────────────────────────
        '/^Registrar WHOIS Server\s*:/i'                           => ['registrar_whois', true],
        '/^(?:Registrar|Sponsoring Registrar|Registered by)\s*:/i' => ['registrar', true],
        '/^(?:registrar-name|registrar_name|Registration Service Provider)\s*:/i' => ['registrar', true],
        '/^Registrar:\s*/i'                                        => ['registrar', true],
        '/^Registration Service Provider:\s*/i'                    => ['registrar', true],

        // ── Registrar IANA ID ──────────────────────────────────────────
        '/^Registrar IANA ID\s*:/i'                                => ['registrar_iana_id', true],
        '/^(?:registrar-id|iana-id|IANA ID)\s*:/i'                => ['registrar_iana_id', true],

        // ── Abuse contact ──────────────────────────────────────────────
        '/^Registrar Abuse Contact Email\s*:/i'                    => ['abuse_email', true],
        '/^Registrar Abuse Contact Phone\s*:/i'                    => ['abuse_phone', true],
        '/^(?:abuse-mailbox|abuse-email|Abuse Contact)\s*:/i'     => ['abuse_email', true],
        '/^(?:abuse-phone|Abuse Contact Phone)\s*:/i'             => ['abuse_phone', true],
        '/^(?:% abuse.*contact.*email|abuse-mailbox)\s*:/i'       => ['abuse_email', true],

        // ── Registrant info ────────────────────────────────────────────
        '/^Registrant Name\s*:/i'                                  => ['registrant_name', true],
        '/^Registrant Contact Name\s*:/i'                          => ['registrant_name', true],
        '/^Registrant\s*:/i'                                       => ['registrant_name', true],
        '/^(?:person|Person)\s*:/i'                                => ['registrant_name', true],
        '/^(?:registrant-name|Registrant Contact)\s*:/i'           => ['registrant_name', true],

        '/^(?:Registrant Organization|Registrant Organisation|Registrant Org)\s*:/i' => ['registrant_org', true],
        '/^(?:OrgName|netname|org-name|owner|Organization|Organisation)\s*:/i' => ['registrant_org', true],
        '/^(?:descr|Description)\s*:/i'                            => ['registrant_org', true],
        '/^(?:Registrant Org)\s*:/i'                               => ['registrant_org', true],

        '/^(?:Registrant Street(?:\s*[12])?|Registrant Address(?:\s*(?:Line\s*)?[12])?|Street Address)\s*:/i' => ['registrant_address', true],
        '/^(?:Registrant City|Registrant Locality|City)\s*:/i'     => ['registrant_city', true],
        '/^(?:Registrant State(?:\/Province)?|Registrant Province|Registrant Region|State\/Province|Region)\s*:/i' => ['registrant_region', true],
        '/^(?:Registrant Postal Code|Registrant ZIP(?: Code)?|Postal Code|ZIP Code)\s*:/i' => ['registrant_postal_code', true],
        '/^Registrant Country\s*:/i'                               => ['registrant_country', true],
        '/^country\s*:/i'                                          => ['registrant_country', true],

        '/^Registrant Email\s*:/i'                                 => ['registrant_email', true],
        '/^Registrant Contact Email\s*:/i'                         => ['registrant_email', true],
        '/^(?:Registrant Email|e-mail|email)\s*:/i'               => ['registrant_email', true],
        '/^(?:registrant-email|Registrant Email)\s*:/i'           => ['registrant_email', true],

        '/^(?:Registrant Phone|Registrant Phone Ext|Registrant Phone Number)\s*:/i' => ['registrant_phone', true],
        '/^(?:phone|Phone|tel)\s*:/i'                              => ['registrant_phone', true],
        '/^(?:registrant-phone)\s*:/i'                             => ['registrant_phone', true],

        // ── Admin / Tech / Billing contacts ────────────────────────────
        '/^Admin(?:istrative)?\s+Contact\s+Email\s*:/i'           => ['admin_email', true],
        '/^Admin Email\s*:/i'                                      => ['admin_email', true],
        '/^(?:admin-email|admin_email|Admin Contact Email)\s*:/i'  => ['admin_email', true],
        '/^(?:Administrative Contact Email)\s*:/i'                 => ['admin_email', true],
        '/^(?:admin-c|Admin Contact)\s*:/i'                        => ['admin_email', true],

        '/^Tech(?:nical)?\s+Contact\s+Email\s*:/i'                => ['tech_email', true],
        '/^Tech Email\s*:/i'                                       => ['tech_email', true],
        '/^(?:tech-email|tech_email|Technical Contact Email)\s*:/i' => ['tech_email', true],
        '/^(?:Technical Contact Email)\s*:/i'                      => ['tech_email', true],
        '/^(?:tech-c|Tech Contact)\s*:/i'                          => ['tech_email', true],

        '/^Billing Contact Email\s*:/i'                            => ['admin_email', true],
        '/^(?:billing-email|billing_email)\s*:/i'                  => ['admin_email', true],

        // ── Nameservers ────────────────────────────────────────────────
        '/^(?:Name Server|nserver|nameserver|Name Server|Host Name)\s*:/i' => ['nameservers', false],
        '/^(?:nservers?|DNS servers?|Nameservers?)\s*:/i'          => ['nameservers', false],
        '/^(?:name-server|name_server|nserver)\s*:/i'              => ['nameservers', false],

        // ── Status ─────────────────────────────────────────────────────
        '/^(?:Domain Status|Status|state|domain-status)\s*:/i'     => ['status', false],

        // ── DNSSEC ─────────────────────────────────────────────────────
        '/^DNSSEC\s*:/i'                                           => ['dnssec', true],
        '/^(?:dnssec|DNSSEC status)\s*:/i'                         => ['dnssec', true],
    ];
    // ── Fuzzy keyword groups for second-pass classification ───────────
    // Maps field → array of keywords that appear in the label portion.
    // Checked case-insensitively against the text BEFORE the colon.
    $fuzzyKeywords = [
        'expiration_date' => ['expir', 'valid until', 'valid through', 'renewal', 'paid-till', 'free-date', 'record expires', 'domain expires', 'exp-date'],
        'creation_date'   => ['creat', 'first registration', 'registration date', 'registration time', 'registered on', 'record created', 'domain registration', 'registration effective'],
        'updated_date'    => ['update', 'modified', 'last change', 'last update', 'changed', 'last modified', 'record updated'],
        'registrar'       => ['registrar', 'sponsoring', 'registered by', 'registration service', 'registration provider'],
        'registrar_iana_id' => ['iana id', 'registrar id', 'iana-id'],
        'abuse_email'     => ['abuse.*email', 'abuse.*mail', 'complaint.*email', 'abuse-mailbox'],
        'abuse_phone'     => ['abuse.*phone', 'complaint.*phone', 'abuse.*tel'],
        'registrant_name' => ['registrant.*name', 'holder.*name', 'owner.*name', 'contact.*name', 'domain holder'],
        'registrant_org'  => ['registrant.*org', 'organization', 'organisation', 'company', 'holder.*org', 'owner.*org'],
        'registrant_country' => ['registrant.*country', 'country', 'registrant.*nation'],
        'registrant_address' => ['registrant.*address', 'registrant.*street', 'street address'],
        'registrant_city'    => ['registrant.*city', 'registrant.*locality'],
        'registrant_region'  => ['registrant.*state', 'registrant.*province', 'registrant.*region'],
        'registrant_postal_code' => ['registrant.*postal', 'registrant.*zip'],
        'registrant_email'   => ['registrant.*email', 'holder.*email', 'owner.*email', 'contact.*email', 'registrant.*e-mail'],
        'registrant_phone'   => ['registrant.*phone', 'holder.*phone', 'owner.*phone', 'contact.*phone', 'registrant.*tel'],
        'admin_email'     => ['admin.*email', 'administrative.*email', 'billing.*email', 'admin.*contact.*email'],
        'tech_email'      => ['tech.*email', 'technical.*email', 'tech.*contact.*email'],
        'nameservers'     => ['name.?server', 'nameserver', 'nserver', 'dns.?server', 'domain.?server', 'host.?name', 'domain servers in listed order', 'name server information'],
        'status'          => ['status', 'state', 'domain.?status', 'status information'],
        'dnssec'          => ['dnssec'],
    ];

    $seen = [];
    $lineCount = count($rawResult);
    for ($idx = 0; $idx < $lineCount; $idx++) {
        // trim() (not rtrim) so leading whitespace doesn't break ^ anchor matching.
        // Many WHOIS servers indent their lines.
        $line = trim($rawResult[$idx]);
        // JPRS uses bracket labels instead of key: value lines.
        $line = preg_replace('/^(?:[a-z]\.\s*)?\[([^\]]+)\]\s*(.*)$/i', '$1: $2', $line);
        if ($line === '' || $line[0] === '%' || $line[0] === '#') continue;
        // Skip comments and metadata lines (RIPE, APNIC, etc.)
        if (preg_match('/^(?:remarks?|source|nic-hdl|mnt-by|role|abuse-c|rt)\s*:/i', $line)) continue;
        if (stripos($line, '>>>') !== false || stripos($line, '<<<') !== false) continue;
        // Skip common registrar footer/notice lines
        if (preg_match('/^(?:NOTICE|Terms of Use|For more information|Please visit|The data|This whois|Service provided)\s/i', $line)) continue;
        if (preg_match('/^(?:%|% |>>>|<<<|---)/', $line)) continue;

        // ── Pass 1: Explicit regex patterns (exact match) ─────────────
        foreach ($patterns as $pattern => [$field, $single]) {
            if (!preg_match($pattern, $line)) continue;
            _parseWhoisExtractField($line, $pattern, $field, $single, $info, $seen);
            continue 2;
        }

        // ── Pass 2: Fuzzy keyword classifier (semantic match) ─────────
        // Only runs on lines with "key: value" format that weren't matched above.
        if (preg_match('/^([^:]+):\s*(.+)$/s', $line, $m)) {
            $label = strtolower(trim($m[1]));
            $value = trim($m[2]);
            // Skip if label is too long (likely a paragraph, not a field label)
            if (strlen($label) > 60) goto skip_fuzzy;
            // Skip if value is empty
            if ($value === '' || $value === '-' || $value === '.') goto skip_fuzzy;

            foreach ($fuzzyKeywords as $field => $keywords) {
                $single = ($field !== 'nameservers' && $field !== 'status');
                foreach ($keywords as $kw) {
                    if (preg_match('/\b' . $kw . '\b/i', $label)) {
                        _parseWhoisExtractField($line, '/^' . preg_quote($m[1], '/') . '\s*:\s*/i', $field, $single, $info, $seen);
                        continue 3;
                    }
                }
            }
        }
        skip_fuzzy:

        // ── Multi-line continuation: if the line is indented and follows a
        //    single-value field, append the value (handles long addresses, etc.)
        if ($rawResult[$idx][0] === ' ' || $rawResult[$idx][0] === "\t") {
            foreach ($seen as $fld => $_) {
                if ($fld === array_key_last($seen) && in_array($fld, ['registrant_name','registrant_org','registrant_address','admin_email','tech_email']) && $info[$fld] !== null) {
                    $trimmed = trim($line);
                    if ($trimmed !== '' && !preg_match('/^(?:%|#)/', $trimmed)) {
                        // Only append if it looks like a continuation (no key: pattern)
                        if (!preg_match('/^\S[\w\s-]+:\s/', $trimmed)) {
                            $info[$fld] .= ', ' . $trimmed;
                        }
                    }
                }
            }
        }
    }
    if (!empty($info['nameservers'])) sort($info['nameservers']);
    if ($info['dnssec'] !== null)
        $info['dnssec'] = str_contains(strtolower($info['dnssec']), 'unsigned') ? 'unsigned' : 'signed';
    return array_filter($info, fn($v) => $v !== null && $v !== []);
}

/**
 * Merge WHOIS parsed data with RDAP parsed data.
 * Prefers WHOIS values, fills gaps from RDAP.
 */
function mergeWhoisRdapData(array $whois, array $rdap): array {
    $mergeable = [
        'creation_date', 'expiration_date', 'updated_date',
        'registrar', 'registrar_iana_id', 'registrar_whois',
        'abuse_email', 'abuse_phone',
        'registrant_name', 'registrant_org', 'registrant_country',
        'registrant_address', 'registrant_city', 'registrant_region', 'registrant_postal_code',
        'registrant_email', 'registrant_phone',
        'admin_email', 'tech_email', 'dnssec',
    ];
    foreach ($mergeable as $field) {
        if (empty($whois[$field]) && !empty($rdap[$field])) {
            $whois[$field] = $rdap[$field];
        }
    }
    if (empty($whois['nameservers']) && !empty($rdap['nameservers'])) {
        $whois['nameservers'] = $rdap['nameservers'];
    }
    if (empty($whois['status']) && !empty($rdap['status'])) {
        $whois['status'] = $rdap['status'];
    }
    return $whois;
}

/**
 * Detect apex domain when a subdomain is queried (returns null if already apex).
 */
function detectApexDomain(string $query): ?string {
    $ascii = idn_to_ascii(trim($query, '.'), IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($ascii === false) return null;
    $registrable = getRegistrableDomain($ascii);
    if ($registrable === null || strcasecmp($registrable, $ascii) === 0) return null;
    return $registrable;
}

/**
 * Return the readable Unicode form of an IDN A-label, or null when the input
 * is already Unicode/ASCII or cannot be converted.  The A-label remains the
 * canonical lookup value; this helper is presentation metadata only.
 */
function idnToUnicodeDomain(string $domain): ?string {
    $candidate = trim($domain, " .\t\n\r\0\x0B");
    if ($candidate === '' || !function_exists('idn_to_utf8')) return null;
    $ascii = idn_to_ascii($candidate, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($ascii === false || $ascii === '') return null;
    $unicode = idn_to_utf8($ascii, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($unicode === false || $unicode === '' || strcasecmp($unicode, $candidate) === 0) return null;
    return $unicode;
}

/**
 * Detect nameserver provider name from a nameserver hostname.
 */
function detectNSProvider(string $ns): ?string {
    $ns = strtolower($ns);
    $map = [
        'cloudflare.com'         => 'Cloudflare',
        'ns.cloudflare.com'      => 'Cloudflare',
        'google.com'             => 'Google',
        'googledomains.com'      => 'Google',
        'googledns.com'          => 'Google',
        'awsdns'                 => 'AWS Route 53',
        'amazonaws.com'          => 'AWS',
        'azure-dns.com'          => 'Azure DNS',
        'azure-dns.net'          => 'Azure DNS',
        'azure-dns.org'          => 'Azure DNS',
        'azure-dns.info'         => 'Azure DNS',
        'dnsimple.com'           => 'DNSimple',
        'ns1.com'                => 'NS1',
        'nsone.net'              => 'NS1',
        'dynect.net'             => 'Dyn',
        'ultradns.net'           => 'UltraDNS',
        'ultradns.org'           => 'UltraDNS',
        'ultradns.com'           => 'UltraDNS',
        'ultradns.biz'           => 'UltraDNS',
        'cloudns.net'            => 'ClouDNS',
        'he.net'                 => 'HE',
        'registrar-servers.com'  => 'Namecheap',
        'domaincontrol.com'      => 'GoDaddy',
        'namebrightdns.com'      => 'NameBright',
        'vercel-dns.com'         => 'Vercel',
        'netlify.com'            => 'Netlify',
        'hover.com'              => 'Hover',
        'name.com'               => 'Name.com',
        'dnsmadeeasy.com'        => 'DNS Made Easy',
        'dnspod.com'             => 'DNSPod',
        'dnspod.cn'              => 'DNSPod',
        'dnsv2.com'              => 'DNSPod (Tencent)',
        'dnsv3.com'              => 'DNSPod (Tencent)',
        'dnsv5.com'              => 'DNSPod (Tencent)',
        'dns-diy.com'            => 'DNSPod',
        'hichina.com'            => 'HiChina',
        'aliyun.com'             => 'Aliyun',
        'alidns.com'             => 'Aliyun',
        'huaweicloud.com'        => 'Huawei Cloud',
        'bdydns.com'             => 'Baidu',
        'tencentcloud.com'       => 'Tencent',
        'dns.com.cn'             => 'DNS.COM.CN',
        'west.cn'                => 'West.cn',
        'west263.com'            => 'West.cn',
        'myhostadmin.net'        => 'ChinaNet',
        'xincache.com'           => 'Xinnet',
        'dns.la'                 => 'DNS.LA',
        'domaindns.com'          => 'HiChina',
        'zndns.com'              => 'ZNDNS',
        'dnsdun.com'             => 'DNSDun',
        'dnsdun.net'             => 'DNSDun',
        'jdcloud.com'            => 'JD Cloud',
        'dnspai.com'             => 'DNSPai',
    ];
    foreach ($map as $pattern => $provider) {
        if (str_contains($ns, $pattern)) return $provider;
    }
    return null;
}

/**
 * Get country flag emoji from a 2-letter country code.
 */
function countryFlag(string $cc): string {
    $cc = strtoupper(trim($cc));
    if (preg_match('/^[A-Z]{2}$/', $cc) !== 1 || !class_exists('IntlChar')) return '';
    $flag = '';
    foreach (str_split($cc) as $c) {
        $flag .= IntlChar::chr(0x1F1E6 + ord($c) - ord('A'));
    }
    return $flag;
}
