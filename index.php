<?php
/**
 * index.php — Super Whois v2.2.2
 * OneFour-inspired UI: two-column result, TLD autocomplete, structured registrar panel.
 */
require_once __DIR__ . '/config.php';

ini_set('pcre.backtrack_limit', '100000');

if (!function_exists('idn_to_ascii')) {
    die('<p style="font-family:sans-serif;color:red">Error: PHP <code>intl</code> extension is missing.</p>');
}

require_once __DIR__ . '/whois_core.php';
require_once __DIR__ . '/languages.php';

// SK is accepted only from POST; localStorage keeps the optional code in this browser client-side.
$skCode = '';
if (isset($_POST['sk']) && is_string($_POST['sk'])) $skCode = trim($_POST['sk']);

$isSKValid = false;
if ($skCode !== '') {
    $isSKValid = validateApiKey($skCode);
}

// ── DNS AJAX endpoint ──────────────────────────────────────────────────
if (isset($_GET['dns'])) {
    header('Content-Type: application/json; charset=UTF-8');
    header('Access-Control-Allow-Origin: *');
    header('Cache-Control: no-store');
    if (!is_string($_GET['dns'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid domain.'], JSON_UNESCAPED_UNICODE);
        exit();
    }
    enforceRateLimit('web', 1);
    $dnsDomain = sanitizeQuery($_GET['dns']);
    if ($dnsDomain === '' || classifyQuery($dnsDomain) !== 'domain') {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid domain.'], JSON_UNESCAPED_UNICODE);
        exit();
    }
    $dnsResult = lookupDNSRecords($dnsDomain);
    $dnsTtls = [];
    foreach (($dnsResult['records'] ?? []) as $records) {
        foreach ($records as $record) {
            if (isset($record['ttl']) && is_numeric($record['ttl'])) $dnsTtls[] = (int)$record['ttl'];
        }
    }
    $browserTtl = $dnsTtls === [] ? 30 : max(30, min(300, min($dnsTtls)));
    header('Cache-Control: public, max-age=' . $browserTtl);
    echo json_encode($dnsResult, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit();
}

// Security headers
foreach ([
    'Cache-Control: private, no-store',
    'X-Content-Type-Options: nosniff',
    'X-Frame-Options: SAMEORIGIN',
    'Referrer-Policy: no-referrer',
    'Permissions-Policy: clipboard-write=(self)',
] as $h) header($h);

// Redirect bare request to lang-qualified URL
if (empty($_SERVER['QUERY_STRING']) && empty($_POST)) {
    $dl = $_COOKIE['lang'] ?? 'en';
    header('Location: index.php?lang=' . $dl);
    exit();
}

// Language
$supported_langs = ['en', 'zh-cn', 'zh-tw'];
$lang = 'en';
if (isset($_GET['lang']) && is_string($_GET['lang'])) {
    $gl = strtolower(trim($_GET['lang']));
    // Backward compatibility: 'zh' → 'zh-cn'
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

require_once __DIR__ . '/whois_servers.php';

// Query — supports batch (comma-separated or newline-separated)
$current_query = '';
$batch_queries = [];
$batch_error = '';
$batchLimit = $isSKValid ? WEB_AUTH_MAX_BATCH : WEB_MAX_BATCH;
if (isset($_POST['query']) && is_string($_POST['query']))    $current_query = trim($_POST['query']);
elseif (isset($_GET['query']) && is_string($_GET['query'])) $current_query = trim($_GET['query']);

if ($current_query !== '') {
    // Bound work before deduplication so repeated input cannot bypass the cap.
    $raw_queries = strlen($current_query) <= WEB_MAX_INPUT_BYTES
        ? array_values(array_filter(array_map('trim', preg_split('/[,\n]+/', $current_query) ?: [])))
        : [];
    if ($raw_queries === [] || count($raw_queries) > $batchLimit) {
        $batch_error = sprintf($T['batch_limit_error'] ?? 'A maximum of %d queries is allowed.', $batchLimit);
        $current_query = '';
    } elseif (count($raw_queries) > 1) {
        // Batch mode: multiple queries
        $seen = [];
        foreach ($raw_queries as $rq) {
            $sq = sanitizeQuery($rq);
            $key = strtolower($sq);
            if ($sq !== '' && !isset($seen[$key])) {
                $seen[$key] = true;
                $batch_queries[] = $sq;
            }
        }
        $current_query = sanitizeQuery($raw_queries[0]); // for display in input
    } else {
        $current_query = sanitizeQuery($current_query);
        if ($current_query !== '') $batch_queries = [$current_query];
    }
}

if (count($batch_queries) > $batchLimit) {
    $batch_error = sprintf($T['batch_limit_error'] ?? 'A maximum of %d queries is allowed.', $batchLimit);
    $batch_queries = [];
}
if ($current_query !== '' && $batch_error === '') {
    $rateIdentifier = $isSKValid ? apiKeyRateIdentifier($skCode) : null;
    $rateLimit = $isSKValid ? WEB_AUTH_RATE_LIMIT : WEB_RATE_LIMIT;
    enforceRateLimit('web', max(1, count($batch_queries)), $rateIdentifier, $rateLimit);
}

// ── Blocked/Restricted WHOIS detection ───────────────────────────────────

function renderDenialCard(string $domain, string $server, string $msg, ?string $webUrl,
                          array $censored, array $T, string $lang, int $ms, string $method = 'whois'): string {
    $h   = fn($s) => htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8');
    $parts = explode('.', $domain);
    $tld = strtoupper(end($parts));

    $o  = '<div class="result-card status-restricted">';
    $o .= '<div class="rc-header">';
    $o .= '<div class="rc-domain">' . renderDomainLabel($domain) . '</div>';
    $o .= '<div class="rc-badges"><span class="badge badge-restricted">'
        . $T['status_restricted'] . '</span></div>';
    $o .= '<div class="rc-meta"><span class="rc-server">' . $h($server) . '</span>';
    $o .= '<span class="rc-time">' . $ms . 'ms · ' . $h($method) . '</span></div>';
    $o .= '</div>'; // rc-header

    $o .= '<div class="denial-body">';
    $headline = $T['denial_headline'];
    $sub = $T['denial_sub'];
    $o .= '<div class="denial-icon"><i class="fa-solid fa-lock" aria-hidden="true"></i></div>';
    $o .= '<div class="denial-headline">' . $h($headline) . '</div>';
    $o .= '<div class="denial-sub">' . $h($sub) . '</div>';
    if ($webUrl) {
        $btnLabel = $T['denial_btn_label'] . ' .' . $tld;
        $o .= '<a href="' . $h($webUrl) . '" target="_blank" rel="noopener noreferrer" class="denial-btn">'
            . $h($btnLabel) . ' →</a>';
    }
    if ($msg) {
        $o .= '<div class="denial-raw-msg">' . $h($msg) . '</div>';
    }
    $o .= '</div>'; // denial-body
    $o .= buildRawBlock($censored, $T);
    $o .= '</div>';
    return $o;
}

// ── Result Rendering Functions ─────────────────────────────────────────────

function renderDomainResult(string $domain, array $T, string $lang, array $whoisServers): void {
    $domainAscii = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($domainAscii === false) {
        echo renderErrorCard($T['invalid_query']); return;
    }
    $apexSuggestion = detectApexDomain($domain);

    $t0     = microtime(true);
    $result = lookupDomain($domainAscii, $whoisServers);
    $elapsed = round((microtime(true) - $t0) * 1000);
    $displayDomain = is_string($result['lookup_domain'] ?? null) && $result['lookup_domain'] !== ''
        ? $result['lookup_domain'] : $domain;

    appendLog('domain_lookup', [
        'query'  => $domain,
        'server' => $result['server'] ?? '',
        'method' => $result['method'] ?? '',
        'status' => $result['status'] ?? '',
        'ms'     => $elapsed,
    ]);

    if ($apexSuggestion) echo renderApexHint($apexSuggestion, $lang, $T);
    if (!empty($result['_cache']['stale'])) echo renderErrorCard($T['stale_warning']);

    switch ($result['status'] ?? 'error') {
        case 'available':
            $raw = censorIPs($result['raw'] ?? []);
            echo renderAvailableCard($displayDomain, $result['server'], $raw, $T, $lang, $elapsed, $result['method'] ?? 'rdap');
            return;

        case 'registered':
            $raw = censorIPs($result['raw'] ?? []);
            // Detect held status
            $held = false;
            foreach (($result['parsed']['status'] ?? []) as $status) {
                $t = strtolower((string)$status);
                if (str_contains($t, 'serverhold') || str_contains($t, 'clienthold')
                    || str_contains($t, 'registry lock') || str_contains($t, 'pendingdelete')) {
                    $held = true; break;
                }
            }
            foreach (($result['raw'] ?? []) as $line) {
                if ($held) break;
                $t = strtolower(trim($line));
                if (preg_match('/^(?:domain\s+)?status\s*:/i', $t) &&
                    (str_contains($t,'serverhold')||str_contains($t,'clienthold')||
                     str_contains($t,'registry lock')||str_contains($t,'pendingdelete'))) {
                    $held = true; break;
                }
            }
            echo renderRegisteredCard($displayDomain, $result['server'], $result['parsed'], $raw, $T, $lang, $elapsed, $held, $result['method'] ?? 'rdap');
            return;

        case 'restricted':
            $raw = censorIPs($result['raw'] ?? []);
            $webUrl = $result['web_url'] ?? whoisGetWebLookupUrl(explode('.', $domainAscii)[count(explode('.', $domainAscii))-1] ?? '');
            $routeSuffix = $result['route_suffix'] ?? null;
            if ($webUrl === null && $routeSuffix !== null) {
                $webUrl = whoisGetWebLookupUrl($routeSuffix);
            }
            $msg = (($result['error_code'] ?? '') === 'registry_access_restricted')
                ? ($T['lookup_error_restricted'] ?? $T['special_route_msg'])
                : $T['special_route_msg'];
            echo renderDenialCard($displayDomain, $result['server'], $msg, $webUrl, $raw, $T, $lang, $elapsed, $result['method'] ?? 'special');
            return;

        default: // error
            echo renderLookupErrorCard($displayDomain, $result, $T, $lang);
            return;
    }
}

function renderIPResult(string $ip, array $T, string $lang): void {
    $server = getRIRServer($ip);
    $t0     = microtime(true);
    $raw    = queryWhoisServer($server, $ip);
    $elapsed = round((microtime(true) - $t0) * 1000);
    appendLog('ip_lookup', ['query' => $ip, 'server' => $server, 'ms' => $elapsed]);
    $censored = censorIPs($raw);
    $h = fn($s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    echo '<div class="result-card">';
    if (count($censored) > 3) {
        echo '<div class="rc-header">';
        echo '<div class="rc-domain">' . $h($ip) . '</div>';
        echo '<div class="rc-meta"><span class="rc-server">' . $T['searched_from'] . ': ' . $h($server) . '</span>';
        echo '<span class="rc-time">' . $elapsed . 'ms · whois</span></div></div>';
        echo '<div class="raw-data-wrapper"><pre>' . $h(implode("\n", $censored)) . '</pre></div>';
    } else {
        echo '<p class="error-msg">' . $T['no_info_found'] . '</p>';
    }
    echo '</div>';
}

function renderASNResult(string $asn, array $T, string $lang): void {
    $server  = 'whois.arin.net';
    $t0      = microtime(true);
    $raw     = queryWhoisServer($server, strtoupper($asn));
    $elapsed = round((microtime(true) - $t0) * 1000);
    appendLog('asn_lookup', ['query' => $asn, 'server' => $server, 'ms' => $elapsed]);
    $censored = censorIPs($raw);
    $h = fn($s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    echo '<div class="result-card">';
    if (count($censored) > 3) {
        echo '<div class="rc-header">';
        echo '<div class="rc-domain">' . $h(strtoupper($asn)) . '</div>';
        echo '<div class="rc-meta"><span class="rc-server">' . $T['searched_from'] . ': ' . $h($server) . '</span>';
        echo '<span class="rc-time">' . $elapsed . 'ms · whois</span></div></div>';
        echo '<div class="raw-data-wrapper"><pre>' . $h(implode("\n", $censored)) . '</pre></div>';
    } else {
        echo '<p class="error-msg">' . $T['no_info_found'] . '</p>';
    }
    echo '</div>';
}

function renderErrorCard(string $msg): string {
    return '<div class="result-card" role="alert"><p class="error-msg">' . htmlspecialchars($msg, ENT_QUOTES, 'UTF-8') . '</p></div>';
}

function renderLookupErrorCard(string $domain, array $result, array $T, string $lang): string {
    $h = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
    $code = strtolower(trim((string)($result['error_code'] ?? '')));
    $reasonKey = match ($code) {
        'whois_unreachable' => 'lookup_error_transport',
        'no_whois_server' => 'lookup_error_no_server',
        'invalid_upstream_response' => 'lookup_error_invalid_response',
        'registry_access_restricted' => 'lookup_error_restricted',
        default => 'lookup_error_reason',
    };
    $reason = $T[$reasonKey] ?? ($T['lookup_error_reason'] ?? $T['no_info_found']);
    $server = trim((string)($result['server'] ?? ''));
    $attempted = [];
    foreach (($result['attempted_servers'] ?? []) as $candidate) {
        if (is_string($candidate) && trim($candidate) !== '') $attempted[] = trim($candidate);
    }
    $webUrl = is_string($result['web_url'] ?? null) ? trim($result['web_url']) : '';
    if ($webUrl === '') {
        $parts = explode('.', strtolower(trim($domain, '.')));
        $webUrl = whoisGetWebLookupUrl((string)end($parts)) ?? '';
    }
    $retryUrl = '?lang=' . rawurlencode($lang) . '&query=' . rawurlencode($domain);

    $o = '<div class="result-card lookup-error-card" role="alert">';
    $o .= '<div class="lookup-error-head">';
    $o .= '<div class="lookup-error-icon"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i></div>';
    $o .= '<div class="lookup-error-copy">';
    $o .= '<div class="lookup-error-title">' . $h($T['lookup_error_title'] ?? $T['no_info_found']) . '</div>';
    $o .= '<div class="lookup-error-domain">' . renderDomainLabel($domain) . '</div>';
    $o .= '</div></div>';
    $o .= '<p class="lookup-error-reason">' . $h($reason) . '</p>';
    $o .= '<p class="lookup-error-retry">' . $h($T['lookup_error_retry'] ?? '') . '</p>';
    $o .= '<div class="lookup-error-meta">';
    if ($server !== '') $o .= '<span><strong>' . $h($T['lookup_error_server'] ?? 'WHOIS server') . ':</strong> ' . $h($server) . '</span>';
    if ($attempted !== []) $o .= '<span><strong>' . $h($T['lookup_error_attempted'] ?? 'Attempted servers') . ':</strong> ' . $h(implode(', ', $attempted)) . '</span>';
    if ($code !== '') $o .= '<span class="lookup-error-code"><strong>' . $h($T['lookup_error_code'] ?? 'Diagnostic code') . ':</strong> ' . $h($code) . '</span>';
    $o .= '</div>';
    $o .= '<div class="lookup-error-actions">';
    $o .= '<a class="lookup-error-link" href="' . $h($retryUrl) . '"><i class="fa-solid fa-rotate-right" aria-hidden="true"></i> ' . $h($T['search_button'] ?? 'Retry') . '</a>';
    if ($webUrl !== '') {
        $officialUrl = $webUrl;
        $o .= '<a class="lookup-error-link lookup-error-link-secondary" href="' . $h($officialUrl) . '" target="_blank" rel="noopener noreferrer"><i class="fa-solid fa-arrow-up-right-from-square" aria-hidden="true"></i> ' . $h($T['lookup_error_official'] ?? 'Open official registry lookup') . '</a>';
    }
    $o .= '</div></div>';
    return $o;
}

function renderApexHint(string $apex, string $lang, array $T): string {
    $url = htmlspecialchars('?lang=' . $lang . '&query=' . urlencode($apex), ENT_QUOTES, 'UTF-8');
    $h   = fn($s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    return '<div class="subdomain-hint">'
        . '<span class="sh-icon"><i class="fa-solid fa-lightbulb" aria-hidden="true"></i></span>'
        . '<span>' . $h($T['subdomain_hint']) . ' <a href="' . $url . '" class="sh-link">' . renderDomainLabel($apex) . '</a>' . $h($T['subdomain_hint_suffix']) . '</span>'
        . '<a href="' . $url . '" class="sh-btn">' . $h($T['subdomain_search_btn']) . '</a>'
        . '</div>';
}

function renderAvailableCard(string $domain, string $server, array $censored, array $T, string $lang, int $ms, string $method = 'whois'): string {
    $h   = fn($s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    $url = '?lang=' . $lang . '&query=' . urlencode($domain);
    $o   = '<div class="result-card status-available">';
    $o  .= '<div class="rc-header">';
    $o  .= '<div class="rc-domain">' . renderDomainLabel($domain) . '</div>';
    $o  .= '<div class="rc-badges"><span class="badge badge-avail">' . $T['domain_available_badge'] . '</span></div>';
    $o  .= '<div class="rc-meta"><span class="rc-server">' . $T['searched_from'] . ': ' . $h($server) . '</span>';
    $o  .= '<span class="rc-time">' . $ms . 'ms · ' . $h($method) . '</span></div></div>';
    $o  .= '<p class="status-text-avail"><i class="fa-solid fa-circle-check" aria-hidden="true"></i>' . $T['domain_available'] . '</p>';
    $o  .= buildCopyBtn($url, $T);
    // DNS Records button (even for available domains, shows if DNS exists)
    $o .= '<div class="dns-section">';
    $o .= '<button class="dns-btn" onclick="loadDNS(\'' . $h($domain) . '\', this)">';
    $o .= '<i class="fa-solid fa-server"></i> ';
    $o .= $T['dns_records'];
    $o .= '</button>';
    $o .= '<div class="dns-results" id="dns-results-' . $h($domain) . '"></div>';
    $o .= '</div>';
    $o  .= buildRawBlock($censored, $T);
    $o  .= '</div>';
    return $o;
}

function renderRegisteredCard(string $domain, string $server, array $p, array $censored, array $T, string $lang, int $ms, bool $held, string $method = 'whois'): string {
    $h   = fn($s) => htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8');
    $url = '?lang=' . $lang . '&query=' . urlencode($domain);

    // Expiry badge
    $expiryBadge = '';
    if (!empty($p['expiration_date'])) {
        $ts = strtotime($p['expiration_date']);
        if ($ts !== false && $ts > 0) {
            $diff = $ts - time();
            if ($diff < 0) {
                $expiryBadge = '<span class="badge badge-expired">' . $T['expired_badge'] . '</span>';
            } elseif ($diff < 60 * 86400) {
                $expiryBadge = '<span class="badge badge-expiring">' . $T['expiring_badge'] . '</span>';
            }
        }
    }

    $o = '<div class="result-card' . ($held ? ' status-held' : '') . '">';

    // ── Header ──
    $o .= '<div class="rc-header">';
    $o .= '<div class="rc-domain">' . renderDomainLabel($domain) . '</div>';
    $o .= '<div class="rc-badges">';
    if ($expiryBadge) $o .= $expiryBadge;
    if ($held)        $o .= '<span class="badge badge-held">' . $T['held_badge'] . '</span>';
    $o .= '</div>';
    $o .= '<div class="rc-meta">';
    if (!empty($p['registrar_iana_id'])) $o .= '<span class="badge-iana">IANA: ' . $h($p['registrar_iana_id']) . '</span>';
    $o .= '<span class="rc-server">' . $h($server) . '</span>';
    $o .= '<span class="rc-time">' . $ms . 'ms · ' . $h($method) . '</span>';
    $o .= '</div>';
    $o .= '</div>'; // rc-header

    // ── Copy link ──
    $o .= buildCopyBtn($url, $T);

    // ── If $p is empty, show a notice and skip the structured columns ──
    if (empty($p)) {
        $o .= '<p class="parse-warning"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i> ' . $h($T['parse_failed_notice']) . '</p>';
        $o .= buildRawBlock($censored, $T);
        $o .= '</div>';
        return $o;
    }

    // ── Two-column body ──
    $o .= '<div class="rc-body">';

    // Left column
    $o .= '<div class="rc-left">';

    // Dates
    $dateFields = [
        'creation_date'   => $T['date_created'],
        'expiration_date' => $T['date_expires'],
        'updated_date'    => $T['date_updated'],
    ];
    $hasDate = array_intersect_key($p, $dateFields);
    if (!empty($hasDate)) {
        $o .= '<div class="rc-dates-row">';
        foreach ($dateFields as $key => $label) {
            if (!isset($p[$key])) continue;
            $rel = relativeTime($p[$key], $lang);
            $o .= '<div class="rc-date-cell">';
            $o .= '<div class="rc-date-label">' . $h($label) . '</div>';
            $o .= '<div class="rc-date-value">' . $h(substr($p[$key], 0, 10)) . '</div>';
            if ($rel) $o .= '<div class="rc-date-rel">' . $h($rel) . '</div>';
            $o .= '</div>';
        }
        $o .= '</div>';
    }

    // Contact row (phone + email)
    $showContact = !empty($p['registrant_phone']) || !empty($p['abuse_email']);
    if ($showContact) {
        $o .= '<div class="rc-contact-row">';
        if (!empty($p['registrant_phone'])) {
            $o .= '<div class="rc-contact-cell">';
            $o .= '<div class="rc-contact-label">' . $T['contact_phone'] . '</div>';
            $o .= '<div class="rc-contact-value">' . $h($p['registrant_phone']) . '</div>';
            $o .= '</div>';
        }
        if (!empty($p['abuse_email'])) {
            $o .= '<div class="rc-contact-cell">';
            $o .= '<div class="rc-contact-label">' . $T['contact_abuse_email'] . '</div>';
            $o .= '<div class="rc-contact-value">' . $h($p['abuse_email']) . '</div>';
            $o .= '</div>';
        }
        $o .= '</div>';
    }

    // Registrant info row (name, org, email)
    $showRegistrant = !empty($p['registrant_name']) || !empty($p['registrant_org'])
                   || !empty($p['registrant_address']) || !empty($p['registrant_city'])
                   || !empty($p['registrant_region']) || !empty($p['registrant_postal_code'])
                   || !empty($p['registrant_email']) || !empty($p['admin_email'])
                   || !empty($p['tech_email']);
    if ($showRegistrant) {
        $o .= '<div class="rc-contact-row">';
        if (!empty($p['registrant_name'])) {
            $o .= '<div class="rc-contact-cell">';
            $o .= '<div class="rc-contact-label">' . $T['contact_registrant'] . '</div>';
            $o .= '<div class="rc-contact-value">' . $h($p['registrant_name']) . '</div>';
            $o .= '</div>';
        }
        if (!empty($p['registrant_org'])) {
            $o .= '<div class="rc-contact-cell">';
            $o .= '<div class="rc-contact-label">' . $T['contact_organization'] . '</div>';
            $o .= '<div class="rc-contact-value">' . $h($p['registrant_org']) . '</div>';
            $o .= '</div>';
        }
        $o .= '</div>';
        // Email row
        $emails = [];
        if (!empty($p['registrant_email'])) $emails[] = $p['registrant_email'];
        if (!empty($p['admin_email'])) $emails[] = $p['admin_email'];
        if (!empty($p['tech_email'])) $emails[] = $p['tech_email'];
        if (!empty($emails)) {
            $o .= '<div class="rc-contact-row">';
            $o .= '<div class="rc-contact-cell" style="flex:2">';
            $o .= '<div class="rc-contact-label">' . $T['contact_emails'] . '</div>';
            $o .= '<div class="rc-contact-value">' . $h(implode(' · ', array_unique($emails))) . '</div>';
            $o .= '</div>';
            $o .= '</div>';
        }
        $addressParts = [];
        foreach (['registrant_address', 'registrant_city', 'registrant_region', 'registrant_postal_code'] as $addressField) {
            if (!empty($p[$addressField])) $addressParts[] = trim((string)$p[$addressField]);
        }
        $addressText = implode(', ', array_unique(array_filter($addressParts)));
        if ($addressText !== '') {
            $o .= '<div class="rc-contact-row">';
            $o .= '<div class="rc-contact-cell" style="flex:2">';
            $o .= '<div class="rc-contact-label">' . $T['contact_address'] . '</div>';
            $o .= '<div class="rc-contact-value">' . $h($addressText) . '</div>';
            $o .= '</div>';
            $o .= '</div>';
        }
    }

    $o .= '</div>'; // rc-left

    // Right column — Registrar panel
    $hasReg = !empty($p['registrar']) || !empty($p['registrar_iana_id']) || !empty($p['registrant_country'])
           || !empty($p['registrar_whois']) || !empty($p['abuse_phone']) || !empty($p['abuse_email']);
    $o .= '<div class="rc-right">';
    $o .= '<div class="registrar-panel">';
    $o .= '<div class="rp-heading"><i class="fa-solid fa-building-columns" aria-hidden="true"></i> ' . $T['registrar_heading'] . '</div>';
    if ($hasReg) {
        if (!empty($p['registrar_iana_id'])) {
            $o .= '<div class="rp-iana"><span class="badge-iana">IANA: ' . $h($p['registrar_iana_id']) . '</span></div>';
        }
        if (!empty($p['registrar'])) {
            $o .= '<div class="rp-name"><i class="fa-solid fa-caret-right" aria-hidden="true"></i> ' . $h($p['registrar']) . '</div>';
        }
        if (!empty($p['registrant_country'])) {
            $flag = countryFlag($p['registrant_country']);
            $o .= '<div class="rp-row">' . $flag . ' ' . $h($p['registrant_country']) . '</div>';
        }
        if (!empty($p['registrar_whois'])) {
            $o .= '<div class="rp-row"><i class="fa-solid fa-globe" aria-hidden="true"></i> ' . $h($p['registrar_whois']) . '</div>';
        }
        if (!empty($p['abuse_phone'])) {
            $o .= '<div class="rp-row"><i class="fa-solid fa-phone" aria-hidden="true"></i> ' . $h($p['abuse_phone']) . '</div>';
        }
        if (!empty($p['abuse_email'])) {
            $o .= '<div class="rp-row"><i class="fa-solid fa-envelope" aria-hidden="true"></i> ' . $h($p['abuse_email']) . '</div>';
        }
    } else {
        $o .= '<div class="rp-row" style="color:var(--clr-text-muted);font-size:13px;">'
            . $T['privacy_protected'] . '</div>';
    }
    $o .= '</div>'; // registrar-panel
    $o .= '</div>'; // rc-right

    $o .= '</div>'; // rc-body

    // ── Status + Nameservers row ──
    $hasStatus = !empty($p['status']);
    $hasNS     = !empty($p['nameservers']);
    $dnssecVal = $p['dnssec'] ?? null;
    if ($hasStatus || $hasNS || $dnssecVal !== null) {
        $o .= '<div class="rc-bottom">';

        if ($hasStatus) {
            $o .= '<div class="rc-section">';
            $o .= '<div class="rc-section-title"><i class="fa-solid fa-bolt" aria-hidden="true"></i> ' . $T['group_status'] . '</div>';
            foreach ($p['status'] as $s) {
                // Extract just the status code (before the URL)
                $code = trim(explode(' ', trim($s))[0]);
                $url2 = (str_contains($s, 'http')) ? trim(substr($s, strpos($s, 'http'))) : null;
                $o .= '<div class="rc-status-item">';
                $o .= '<span class="status-dot"></span>';
                if ($url2) {
                    $o .= '<a href="' . $h($url2) . '" target="_blank" rel="noopener" class="status-link">' . $h($code) . '</a>';
                } else {
                    $o .= $h($code);
                }
                // Status description
                $desc = getStatusDescription($code, $lang);
                if ($desc) $o .= '<span class="status-desc"> — ' . $h($desc) . '</span>';
                $o .= '</div>';
            }
            $o .= '</div>';
        }

        if ($hasNS || $dnssecVal !== null) {
            $o .= '<div class="rc-section">';
            $o .= '<div class="rc-section-title"><i class="fa-solid fa-tower-broadcast" aria-hidden="true"></i> ' . $T['group_nameservers'] . '</div>';
            if ($hasNS) {
                foreach ($p['nameservers'] as $ns) {
                    $provider = detectNSProvider($ns);
                    $o .= '<div class="rc-ns-item">';
                    $o .= '<span class="ns-dot">●</span> ' . $h($ns);
                    if ($provider) $o .= ' <span class="ns-badge">' . $h($provider) . '</span>';
                    $o .= '</div>';
                }
            }
            // DNSSEC merged into nameserver section
            if ($dnssecVal !== null) {
                $isSigned = strtolower($dnssecVal) === 'signed';
                $dnssecLabel = $isSigned
                    ? ($lang === 'zh-cn' ? '已签名' : ($lang === 'zh-tw' ? '已簽署' : 'Signed'))
                    : ($lang === 'zh-cn' ? '未签名' : ($lang === 'zh-tw' ? '未簽署' : 'Unsigned'));
                $badgeClass = $isSigned ? 'dnssec-badge dnssec-signed' : 'dnssec-badge dnssec-unsigned';
                $o .= '<div class="rc-ns-item" style="margin-top:8px;padding-top:8px;border-top:1px solid var(--clr-border-light);">';
                $o .= '<span class="' . $badgeClass . '"><i class="fa-solid fa-lock" aria-hidden="true"></i> DNSSEC: ' . $h($dnssecLabel) . '</span>';
                $o .= '</div>';
            }
            $o .= '</div>';
        }

        $o .= '</div>'; // rc-bottom
    }

    // ── DNS Records button ──
    $o .= '<div class="dns-section">';
    $o .= '<button class="dns-btn" onclick="loadDNS(\'' . $h($domain) . '\', this)">';
    $o .= '<i class="fa-solid fa-server"></i> ';
    $o .= $T['dns_records'];
    $o .= '</button>';
    $o .= '<div class="dns-results" id="dns-results-' . $h($domain) . '"></div>';
    $o .= '</div>';

    $o .= buildRawBlock($censored, $T);
    $o .= '</div>'; // result-card
    return $o;
}

function getStatusDescription(string $code, string $lang): string {
    $map = [
        'clientTransferProhibited' => ['en' => 'Registrar has locked the domain to prevent transfer to another registrar.', 'zh' => '注册商已锁定域名以防止转移至另一注册商。', 'zh-tw' => '註冊商已鎖定域名，以防止轉移至其他註冊商。'],
        'clientDeleteProhibited'   => ['en' => 'Registrar has locked to prevent deletion.', 'zh' => '注册商已锁定以防止删除。', 'zh-tw' => '註冊商已鎖定，以防止刪除。'],
        'clientUpdateProhibited'   => ['en' => 'Registrar has locked to prevent updates.', 'zh' => '注册商已锁定以防止更新。', 'zh-tw' => '註冊商已鎖定，以防止更新。'],
        'serverTransferProhibited' => ['en' => 'Registry locked — transfer prohibited.', 'zh' => '注册局锁定 — 禁止转移。', 'zh-tw' => '註冊局已鎖定 — 禁止轉移。'],
        'serverDeleteProhibited'   => ['en' => 'Registry locked — deletion prohibited.', 'zh' => '注册局锁定 — 禁止删除。', 'zh-tw' => '註冊局已鎖定 — 禁止刪除。'],
        'serverUpdateProhibited'   => ['en' => 'Registry locked — updates prohibited.', 'zh' => '注册局锁定 — 禁止更新。', 'zh-tw' => '註冊局已鎖定 — 禁止更新。'],
        'pendingDelete'            => ['en' => 'Domain is pending deletion.', 'zh' => '域名待删除中。', 'zh-tw' => '域名待刪除中。'],
        'pendingTransfer'          => ['en' => 'Domain is pending transfer.', 'zh' => '域名待转移中。', 'zh-tw' => '域名待轉移中。'],
        'active'                   => ['en' => 'Domain is active.', 'zh' => '域名处于活跃状态。', 'zh-tw' => '域名處於活躍狀態。'],
        'ok'                       => ['en' => 'Domain is in normal status.', 'zh' => '域名状态正常。', 'zh-tw' => '域名狀態正常。'],
    ];
    $code = strtolower($code);
    foreach ($map as $k => $v) {
        if (strtolower($k) === $code) return $v[$lang] ?? ($lang === 'zh-tw' ? ($v['zh-tw'] ?? $v['zh']) : ($v['zh'] ?? $v['en']));
    }
    return '';
}

function buildCopyBtn(string $url, array $T): string {
    $esc = htmlspecialchars(json_encode($url), ENT_QUOTES, 'UTF-8');
    return '<div class="copy-row">'
        . '<button class="copy-link-btn" onclick="copyToClipboard(' . $esc . ', this)">'
        . '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>'
        . ' ' . htmlspecialchars($T['copy_link_button'], ENT_QUOTES, 'UTF-8')
        . '</button></div>';
}

/** Render the technical A-label with a readable Unicode IDN in parentheses. */
function renderDomainLabel(string $domain): string {
    $h = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
    $html = $h(strtoupper($domain));
    $unicode = idnToUnicodeDomain($domain);
    if ($unicode !== null) {
        $html .= ' <span class="idn-unicode" lang="und">(' . $h($unicode) . ')</span>';
    }
    return $html;
}

function buildRawBlock(array $lines, array $T): string {
    return '<div class="raw-data-container">'
        . '<button class="details-toggle" onclick="toggleDetails(this)">'
        . htmlspecialchars($T['show_raw_data'], ENT_QUOTES, 'UTF-8')
        . '</button>'
        . '<div class="details-content"><pre>'
        . htmlspecialchars(implode("\n", $lines), ENT_QUOTES, 'UTF-8')
        . '</pre></div></div>';
}

?><!DOCTYPE html>
<html lang="<?php echo $lang; ?>">
<head>
<meta charset="UTF-8">
<title><?php echo htmlspecialchars($T['page_title'], ENT_QUOTES, 'UTF-8'); ?></title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="<?php echo htmlspecialchars($T['meta_description'], ENT_QUOTES, 'UTF-8'); ?>">
<meta name="application-version" content="<?php echo SUPER_WHOIS_VERSION; ?>">
<link rel="stylesheet" href="./style.css">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
</head>
<body>

<header>
  <div class="header-content">
    <h2><i class="fa-solid fa-globe"></i> <?php echo htmlspecialchars($T['header_title'], ENT_QUOTES, 'UTF-8'); ?></h2>
    <div class="header-actions">
      <div class="color-picker-dropdown" id="color-picker-dropdown">
        <button id="color-picker-btn" class="icon-btn" aria-label="<?php echo htmlspecialchars($T['theme_color'] ?? 'Accent color', ENT_QUOTES, 'UTF-8'); ?>" title="<?php echo htmlspecialchars($T['theme_color'] ?? 'Accent color', ENT_QUOTES, 'UTF-8'); ?>">
          <i class="fa-solid fa-palette"></i>
        </button>
        <div class="color-menu" id="color-menu" role="menu">
          <button class="color-opt opt-cyan active" data-color="cyan" title="<?php echo htmlspecialchars($T['color_cyan'], ENT_QUOTES, 'UTF-8'); ?> (#00f0ff)"><span class="dot"></span><?php echo htmlspecialchars($T['color_cyan'], ENT_QUOTES, 'UTF-8'); ?></button>
          <button class="color-opt opt-emerald" data-color="emerald" title="<?php echo htmlspecialchars($T['color_emerald'], ENT_QUOTES, 'UTF-8'); ?> (#10b981)"><span class="dot"></span><?php echo htmlspecialchars($T['color_emerald'], ENT_QUOTES, 'UTF-8'); ?></button>
          <button class="color-opt opt-purple" data-color="purple" title="<?php echo htmlspecialchars($T['color_purple'], ENT_QUOTES, 'UTF-8'); ?> (#a855f7)"><span class="dot"></span><?php echo htmlspecialchars($T['color_purple'], ENT_QUOTES, 'UTF-8'); ?></button>
          <button class="color-opt opt-amber" data-color="amber" title="<?php echo htmlspecialchars($T['color_amber'], ENT_QUOTES, 'UTF-8'); ?> (#f59e0b)"><span class="dot"></span><?php echo htmlspecialchars($T['color_amber'], ENT_QUOTES, 'UTF-8'); ?></button>
        </div>
      </div>
      <button id="theme-toggle" class="icon-btn" aria-label="<?php echo htmlspecialchars($T['theme_toggle'], ENT_QUOTES, 'UTF-8'); ?>">
        <i class="fa-solid fa-moon" id="theme-icon"></i>
      </button>
      <div class="language-switcher">
        <?php $qs = !empty($current_query) ? '&query=' . urlencode($current_query) : ''; ?>
        <a href="<?php echo htmlspecialchars('?lang=en' . $qs); ?>" <?php if ($lang==='en') echo 'class="active"'; ?>>EN</a>
        <a href="<?php echo htmlspecialchars('?lang=zh-cn' . $qs); ?>" <?php if ($lang==='zh-cn') echo 'class="active"'; ?>>简体</a>
        <a href="<?php echo htmlspecialchars('?lang=zh-tw' . $qs); ?>" <?php if ($lang==='zh-tw') echo 'class="active"'; ?>>繁體</a>
      </div>
      <a href="api.php?lang=<?php echo $lang; ?>" class="api-badge" target="_blank" rel="noopener">
        <i class="fa-solid fa-code"></i> API
      </a>
    </div>
  </div>
</header>

<main>
  <div class="search-card">
    <form method="post" action="?lang=<?php echo $lang; ?>" autocomplete="off" id="search-form" role="search">
      <input type="hidden" name="sk" id="sk-hidden">
      <div class="input-wrapper">
        <i class="fa-regular fa-clock input-icon-left"></i>
         <input type="text" name="query" id="query-input"
                aria-label="<?php echo htmlspecialchars($T['query_input_label'], ENT_QUOTES, 'UTF-8'); ?>"
                placeholder="<?php echo htmlspecialchars($T['placeholder'], ENT_QUOTES, 'UTF-8'); ?>"
               required spellcheck="false" maxlength="10000"
               value="<?php echo htmlspecialchars($current_query, ENT_QUOTES, 'UTF-8'); ?>"
               autocomplete="off">
        <div id="autocomplete-dropdown" class="ac-dropdown" role="listbox"></div>
      </div>
      <button type="submit" class="submit-button" id="submit-btn" aria-label="<?php echo htmlspecialchars($T['search_button'], ENT_QUOTES, 'UTF-8'); ?>">
        <i class="fa-solid fa-location-arrow" id="submit-icon"></i>
      </button>
    </form>
    <div class="sk-row">
      <label class="sk-label" for="sk-input"><i class="fa-solid fa-key sk-icon" aria-hidden="true"></i><?php echo htmlspecialchars($T['sk_label'], ENT_QUOTES, 'UTF-8'); ?></label>
      <input type="password" id="sk-input" class="sk-input"
             placeholder="<?php echo htmlspecialchars($T['sk_placeholder'], ENT_QUOTES, 'UTF-8'); ?>"
             value="<?php echo htmlspecialchars($skCode, ENT_QUOTES, 'UTF-8'); ?>"
              autocomplete="off" spellcheck="false">
      <span id="sk-local-status" class="sk-local-status" aria-live="polite"></span>
      <button type="button" id="sk-clear-local" class="clear-button btn-ghost btn-sm" title="<?php echo htmlspecialchars($T['sk_clear_local_aria'], ENT_QUOTES, 'UTF-8'); ?>" aria-label="<?php echo htmlspecialchars($T['sk_clear_local_aria'], ENT_QUOTES, 'UTF-8'); ?>">
        <i class="fa-solid fa-trash-can" aria-hidden="true"></i><?php echo htmlspecialchars($T['sk_clear_local'], ENT_QUOTES, 'UTF-8'); ?>
      </button>
      <span id="sk-badge" class="sk-badge <?php echo $isSKValid ? 'sk-valid' : ($skCode !== '' ? 'sk-invalid' : 'sk-hidden'); ?>">
        <?php if ($isSKValid): ?>
          <i class="fa-solid fa-check"></i> <?php echo htmlspecialchars($T['sk_active'], ENT_QUOTES, 'UTF-8'); ?>
        <?php elseif ($skCode !== ''): ?>
          <i class="fa-solid fa-xmark"></i> <?php echo htmlspecialchars($T['sk_invalid'], ENT_QUOTES, 'UTF-8'); ?>
        <?php endif; ?>
      </span>
    </div>
  </div>

  <?php
  if ($batch_error !== '') echo renderErrorCard($batch_error);
  if (!empty($batch_queries)) {
    $batchCount = count($batch_queries);
    $isBatch = $batchCount > 1;
    if ($isBatch) {
      echo '<div id="batch-toolbar" class="batch-toolbar">';
      echo '<div class="batch-toolbar-row">';
      echo '<span class="batch-count">' . htmlspecialchars(sprintf($T['batch_count'] ?? 'Batch: %d queries', $batchCount), ENT_QUOTES, 'UTF-8') . '</span>';
      if ($isSKValid) echo '<span class="sk-badge sk-valid"><i class="fa-solid fa-bolt"></i> '
          . htmlspecialchars($T['sk_higher_quota'] ?? 'Higher quota', ENT_QUOTES, 'UTF-8') . '</span>';
      echo '<div class="batch-filters" id="batch-filters"></div>';
      echo '<div class="batch-actions">';
      echo '<button class="batch-action-btn" id="batch-expand-all" title="' . htmlspecialchars($T['batch_expand_all'], ENT_QUOTES, 'UTF-8') . '" aria-label="' . htmlspecialchars($T['batch_expand_all'], ENT_QUOTES, 'UTF-8') . '"><i class="fa-solid fa-angles-down" aria-hidden="true"></i></button>';
      echo '<button class="batch-action-btn" id="batch-collapse-all" title="' . htmlspecialchars($T['batch_collapse_all'], ENT_QUOTES, 'UTF-8') . '" aria-label="' . htmlspecialchars($T['batch_collapse_all'], ENT_QUOTES, 'UTF-8') . '"><i class="fa-solid fa-angles-up" aria-hidden="true"></i></button>';
      echo '</div>';
      echo '</div>';
      echo '</div>';
      echo '<div id="batch-available-jump" class="batch-available-jump" style="display:none">';
      echo '<i class="fa-solid fa-arrow-down"></i> <span id="batch-jump-text"></span>';
      echo '</div>';
    }
    $idx = 0;
    foreach ($batch_queries as $bq) {
      $qtype = classifyQuery($bq);
      if ($isBatch) {
        echo '<div class="batch-item" data-index="' . $idx . '" data-status="pending">';
        echo '<div class="batch-query-label" onclick="toggleBatchItem(this.parentElement)">';
        echo '<i class="fa-solid fa-chevron-down batch-chevron"></i>';
        $batchLabel = $qtype === 'domain' ? renderDomainLabel($bq) : htmlspecialchars($bq, ENT_QUOTES, 'UTF-8');
        echo '<span class="batch-query-text">' . $batchLabel . '</span>';
        echo '<span class="batch-status-badge"></span>';
        echo '</div>';
        echo '<div class="batch-item-body">';
      }
      switch ($qtype) {
        case 'ipv4': case 'ipv6': renderIPResult($bq, $T, $lang); break;
        case 'asn':  renderASNResult($bq, $T, $lang); break;
        case 'domain': renderDomainResult($bq, $T, $lang, $whoisServers); break;
        default: echo renderErrorCard($T['invalid_query']);
      }
      if ($isBatch) {
        echo '</div></div>';
        $idx++;
      }
    }
  }
  ?>

  <div id="guides-container" class="illustrate-card">
    <div class="card-header">
      <h3><?php echo htmlspecialchars($T['guide_title'], ENT_QUOTES, 'UTF-8'); ?></h3>
      <button id="toggle-guides-btn" class="btn-ghost btn-sm"></button>
    </div>
    <div id="guides-body">
      <ol>
        <li><?php echo $T['guide_step1']; ?></li>
        <li><?php echo $T['guide_step2']; ?></li>
        <li><?php echo $T['guide_step3']; ?></li>
        <li><?php echo $T['guide_step4']; ?></li>
        <li><?php echo $T['guide_step5']; ?></li>
        <li><?php echo $T['guide_step6']; ?></li>
      </ol>
    </div>
  </div>

  <div class="history-card">
    <div class="history-header">
      <h3><?php echo htmlspecialchars($T['history_records_title'], ENT_QUOTES, 'UTF-8'); ?></h3>
      <button class="clear-button btn-ghost btn-sm" onclick="clearHistory()">
        <?php echo htmlspecialchars($T['clear_history_button'], ENT_QUOTES, 'UTF-8'); ?>
      </button>
    </div>
    <p class="history-info"><?php echo htmlspecialchars($T['history_info'], ENT_QUOTES, 'UTF-8'); ?></p>
    <ul id="history-list"></ul>
  </div>
</main>

<footer>
  <p><?php echo $T['footer_text']; ?>
    <span class="version-badge">v<?php echo SUPER_WHOIS_VERSION; ?></span>
    | <a href="api.php?lang=<?php echo $lang; ?>"><?php echo $T['footer_api_link']; ?></a>
    | <a href="https://github.com/iezx/Super-Whois" target="_blank" rel="noopener noreferrer"><?php echo $T['footer_github']; ?></a>
  </p>
</footer>

<script>
(function(){
  const dnsRecordsTxt = <?php echo json_encode($T['dns_records'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); ?>;
  const dnsNoRecordsTxt = <?php echo json_encode($T['dns_no_records'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); ?>;
  const dnsErrorTxt = <?php echo json_encode($T['dns_error'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); ?>;
  // ── SK Code localStorage persistence ─────────────────────────────────
  const SK_KEY = 'swSK';
  const skInput  = document.getElementById('sk-input');
  const skHidden = document.getElementById('sk-hidden');
  const skBadge  = document.getElementById('sk-badge');
  const skLocalStatus = document.getElementById('sk-local-status');
  const skClearLocal = document.getElementById('sk-clear-local');
  const skSavedTxt = <?php echo json_encode($T['sk_saved_local']); ?>;

  function setLocalSKStatus(saved) {
    if (!skLocalStatus) return;
    skLocalStatus.textContent = saved ? skSavedTxt : '';
    skLocalStatus.classList.toggle('is-visible', !!saved);
  }

  try {
    const saved = localStorage.getItem(SK_KEY);
    if (saved) {
      if (!skInput.value) {
        skInput.value = saved;
        skHidden.value = saved;
      }
      setLocalSKStatus(true);
    } else {
      skHidden.value = skInput.value;
    }
  } catch(e) { skHidden.value = skInput.value; }

  skInput.addEventListener('input', () => {
    const v = skInput.value.trim();
    skHidden.value = v;
    try {
      if (v) { localStorage.setItem(SK_KEY, v); setLocalSKStatus(true); }
      else { localStorage.removeItem(SK_KEY); setLocalSKStatus(false); }
    } catch(e){ setLocalSKStatus(false); }
    skBadge.className = 'sk-badge sk-hidden';
    skBadge.innerHTML = '';
  });

  skClearLocal?.addEventListener('click', () => {
    try { localStorage.removeItem(SK_KEY); } catch(e){}
    skInput.value = '';
    skHidden.value = '';
    skBadge.className = 'sk-badge sk-hidden';
    skBadge.innerHTML = '';
    setLocalSKStatus(false);
    skInput.focus();
  });

  // On form submit, ensure hidden SK field is current
  document.getElementById('search-form').addEventListener('submit', () => {
    skHidden.value = skInput.value.trim();
  });

  // ── Theme & Accent Color ─────────────────────────────────────────────
  const TK = 'swTheme';
  const CK = 'swAccentColor';
  const btn = document.getElementById('theme-toggle');
  const ico = document.getElementById('theme-icon');
  const colorBtn = document.getElementById('color-picker-btn');
  const colorMenu = document.getElementById('color-menu');

  function applyTheme(dark) {
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    ico.className = dark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
    try { localStorage.setItem(TK, dark ? 'dark' : 'light'); } catch(e){}
  }

  function applyAccentColor(color) {
    const valid = ['cyan', 'emerald', 'purple', 'amber'];
    if (!valid.includes(color)) color = 'cyan';
    document.documentElement.setAttribute('data-accent', color);
    try { localStorage.setItem(CK, color); } catch(e){}
    if (colorMenu) {
      colorMenu.querySelectorAll('.color-opt').forEach(opt => {
        opt.classList.toggle('active', opt.getAttribute('data-color') === color);
      });
    }
  }

  (() => {
    let s; try { s = localStorage.getItem(TK); } catch(e){}
    applyTheme(s ? s==='dark' : window.matchMedia('(prefers-color-scheme: dark)').matches);
    let c; try { c = localStorage.getItem(CK); } catch(e){}
    applyAccentColor(c || 'cyan');
  })();

  btn.addEventListener('click', () =>
    applyTheme(document.documentElement.getAttribute('data-theme') !== 'dark'));

  if (colorBtn && colorMenu) {
    colorBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const open = colorMenu.style.display === 'flex';
      colorMenu.style.display = open ? 'none' : 'flex';
    });
    document.addEventListener('click', (e) => {
      if (!e.target.closest('#color-picker-dropdown')) {
        colorMenu.style.display = 'none';
      }
    });
    colorMenu.querySelectorAll('.color-opt').forEach(opt => {
      opt.addEventListener('click', () => {
        const selected = opt.getAttribute('data-color');
        applyAccentColor(selected);
        colorMenu.style.display = 'none';
      });
    });
  }

  // ── Autocomplete TLD Suggestions ──────────────────────────────────────
  // Curated popular suggestions only; registry coverage comes from IANA, not this UI list.
  const POPULAR_TLDS = ['com','net','org','io','co','app','dev','ai','me','info','biz','xyz','online','shop','tech','cloud','store'];
  const TOP_TLDS   = POPULAR_TLDS.slice(0, 8);
  const input      = document.getElementById('query-input');
  const dropdown   = document.getElementById('autocomplete-dropdown');
  let acActive = -1, acItems = [];

  /**
   * Extract the registrable base name:
   *   "example"       → "example"
   *   "example.com"   → "example"
   *   "sub.example.com" → "example"  (skip sub-labels)
   */
  function getBaseName(val) {
    val = val.trim().replace(/^https?:\/\//i, '').split('/')[0];
    const parts = val.split('.').filter(Boolean);
    if (parts.length === 0) return '';
    if (parts.length === 1) return parts[0];
    if (parts.length > 2) return ''; // avoid rewriting multi-label suffixes/subdomains without the PSL
    return parts[parts.length - 2];
  }

  function showAC(val) {
    val = val.trim();
    if (!val || val.includes(' ')) { hideAC(); return; }
    const base = getBaseName(val);
    if (!base || base.length < 2) { hideAC(); return; }

    // If the user typed a dot, show ALL TLDs; otherwise show TOP 8
    const pool = val.includes('.') ? POPULAR_TLDS : TOP_TLDS;
    // Current TLD the user has typed (if any), to mark it active
    const typedTLD = val.includes('.') ? val.split('.').slice(1).join('.').toLowerCase() : null;

    acItems = pool.map(tld => base + '.' + tld);
    // If the typed TLD isn't in pool, prepend the literal typed value
    if (typedTLD && !pool.includes(typedTLD)) {
      acItems.unshift(val.toLowerCase());
    }

    dropdown.innerHTML = '';
    acActive = -1;
    acItems.forEach((item) => {
      const li = document.createElement('div');
      const isCurrent = (item === val.toLowerCase());
      li.className = 'ac-item' + (isCurrent ? ' ac-current' : '');
      li.setAttribute('role', 'option');
      li.innerHTML = '<span class="ac-icon"><i class="fa-solid fa-globe" aria-hidden="true"></i></span>'
        + '<span class="ac-text">' + escHtml(item) + '</span>'
        + '<span class="ac-badge">' + escHtml(<?php echo json_encode($T['domain_type_label']); ?>) + '</span>';
      li.addEventListener('mousedown', e => {
        e.preventDefault();
        input.value = item;
        hideAC();
        document.getElementById('search-form').submit();
      });
      dropdown.appendChild(li);
    });
    dropdown.style.display = 'block';
  }

  function hideAC() {
    dropdown.style.display = 'none';
    acActive = -1;
  }

  function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  input.addEventListener('input', () => showAC(input.value));
  input.addEventListener('focus', () => { if (input.value) showAC(input.value); });
  document.addEventListener('click', e => { if (!e.target.closest('.input-wrapper')) hideAC(); });

  input.addEventListener('keydown', e => {
    const items = dropdown.querySelectorAll('.ac-item');
    if (!items.length || dropdown.style.display === 'none') return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      acActive = Math.min(acActive + 1, items.length - 1);
      items.forEach((el,i) => el.classList.toggle('ac-hover', i===acActive));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      acActive = Math.max(acActive - 1, -1);
      items.forEach((el,i) => el.classList.toggle('ac-hover', i===acActive));
    } else if (e.key === 'Enter' && acActive >= 0) {
      e.preventDefault();
      input.value = acItems[acActive];
      hideAC();
      document.getElementById('search-form').submit();
    } else if (e.key === 'Escape') {
      hideAC();
    }
  });

  // ── Guides toggle ─────────────────────────────────────────────────────
  const guideContainer = document.getElementById('guides-container');
  const toggleBtn      = document.getElementById('toggle-guides-btn');
  const guideBody      = document.getElementById('guides-body');
  const showTxt = <?php echo json_encode($T['toggle_guides_button']); ?>;
  const hideTxt = <?php echo json_encode($T['hide_guides_button']); ?>;
  let guideOpen = false;
  guideBody.style.display = 'none';
  toggleBtn.textContent = showTxt;
  toggleBtn.addEventListener('click', () => {
    guideOpen = !guideOpen;
    guideBody.style.display = guideOpen ? 'block' : 'none';
    toggleBtn.textContent = guideOpen ? hideTxt : showTxt;
  });

  // ── History ───────────────────────────────────────────────────────────
  const HK = 'swHistory_v3';
  const noHistTxt = <?php echo json_encode($T['no_history']); ?>;
  const clickHint = <?php echo json_encode($T['history_click_hint']); ?>;
  const deleteHistoryTxt = <?php echo json_encode($T['delete_history_item']); ?>;
  const histList  = document.getElementById('history-list');
  const form      = document.getElementById('search-form');

  function loadHistory() {
    let h = []; try { h = JSON.parse(localStorage.getItem(HK)||'[]'); } catch(e){}
    if (!Array.isArray(h)) h = [];
    h = h.filter(item => typeof item === 'string');
    histList.innerHTML = '';
    if (!h.length) { histList.innerHTML = '<li class="no-history">' + noHistTxt + '</li>'; return; }
    h.slice(-10).reverse().forEach(item => {
      const li = document.createElement('li');
      li.className = 'history-item';
      const queryBtn = document.createElement('button');
      queryBtn.type = 'button';
      queryBtn.className = 'history-query';
      queryBtn.textContent = item;
      queryBtn.title = clickHint;
      queryBtn.onclick = () => { input.value = item; saveHistory(item); form.requestSubmit(); };
      const deleteBtn = document.createElement('button');
      deleteBtn.type = 'button';
      deleteBtn.className = 'history-delete';
      deleteBtn.textContent = '×';
      deleteBtn.title = deleteHistoryTxt;
      deleteBtn.setAttribute('aria-label', deleteHistoryTxt + ': ' + item);
      deleteBtn.onclick = () => {
        try { localStorage.setItem(HK, JSON.stringify(h.filter(value => value !== item))); } catch(e){}
        loadHistory();
        (histList.querySelector('.history-delete') || document.getElementById('query-input')).focus();
      };
      li.append(queryBtn, deleteBtn);
      histList.appendChild(li);
    });
  }

  function saveHistory(q) {
    q = q.trim();
    if (!q) return;
    // Split batch queries — save each individually
    const parts = q.split(/[,\n]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
    let h = []; try { h = JSON.parse(localStorage.getItem(HK)||'[]'); } catch(e){}
    if (!Array.isArray(h)) h = [];
    parts.forEach(p => { h = h.filter(i => i !== p); h.push(p); });
    if (h.length > 20) h.splice(0, h.length - 20);
    try { localStorage.setItem(HK, JSON.stringify(h)); } catch(e){}
  }

  form.addEventListener('submit', () => {
    const q = input.value.trim();
    if (q) saveHistory(q);
    // Loading spinner
    const btn = document.getElementById('submit-btn');
    const ico = document.getElementById('submit-icon');
    btn.disabled = true;
    ico.className = 'fa-solid fa-spinner fa-spin';
  });

  window.clearHistory = () => {
    try { localStorage.removeItem(HK); } catch(e){}
    loadHistory();
  };

  loadHistory();

  // ── Copy link ─────────────────────────────────────────────────────────
  const copiedTxt = <?php echo json_encode($T['copied_feedback']); ?>;
  const copyFailTxt = <?php echo json_encode($T['copy_failed']); ?>;

  window.copyToClipboard = (path, btn2) => {
    const url = new URL(path, window.location.href).href;
    const orig = btn2.innerHTML;
    const ok = () => {
      btn2.textContent = copiedTxt; btn2.disabled = true;
      setTimeout(() => { btn2.innerHTML = orig; btn2.disabled = false; }, 2000);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(url).then(ok).catch(() => fbCopy(url, ok));
    } else { fbCopy(url, ok); }
  };

  function fbCopy(text, onOk) {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.cssText = 'position:fixed;top:-9999px;opacity:0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { if (document.execCommand('copy')) onOk(); else alert(copyFailTxt+'\n'+text); }
    catch(e) { alert(copyFailTxt+'\n'+text); }
    document.body.removeChild(ta);
  }

  // ── DNS Records ───────────────────────────────────────────────────
  window.loadDNS = (domain, btn) => {
    const container = document.getElementById('dns-results-' + domain);
    if (!container) return;
    // Toggle if already loaded
    if (container.style.display === 'block') {
      container.style.display = 'none';
      btn.classList.remove('dns-btn-active');
      return;
    }
    if (container.dataset.loaded) {
      container.style.display = 'block';
      btn.classList.add('dns-btn-active');
      return;
    }
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ' + dnsRecordsTxt + '…';
    fetch('?dns=' + encodeURIComponent(domain))
      .then(async r => {
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || dnsErrorTxt);
        return data;
      })
      .then(data => {
        container.innerHTML = renderDNS(data, domain);
        container.style.display = 'block';
        container.dataset.loaded = '1';
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-server"></i> ' + dnsRecordsTxt;
        btn.classList.add('dns-btn-active');
      })
      .catch(error => {
        container.innerHTML = '<div class="dns-error">' + escHtml(error.message || dnsErrorTxt) + '</div>';
        container.style.display = 'block';
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-server"></i> ' + dnsRecordsTxt;
      });
  };

  function renderDNS(data, domain) {
    const errors = Array.isArray(data.errors) ? data.errors : (data.error ? [data.error] : []);
    if (errors.length && (!data.records || Object.keys(data.records).length === 0)) {
      return '<div class="dns-error">' + escHtml(dnsNoRecordsTxt) + '</div>';
    }
    const recs = data.records || {};
    const types = ['A','AAAA','MX','TXT','NS','CNAME'];
    let html = '<div class="dns-card">';
    html += '<div class="dns-title"><i class="fa-solid fa-server"></i> ' + dnsRecordsTxt + ' — ' + escHtml(domain.toUpperCase()) + '</div>';
    let hasRecords = false;
    types.forEach(type => {
      if (!recs[type] || recs[type].length === 0) return;
      hasRecords = true;
      html += '<div class="dns-type-block">';
      html += '<div class="dns-type-header"><span class="dns-type-badge">' + type + '</span></div>';
      html += '<div class="dns-records-list">';
      recs[type].forEach(r => {
        html += '<div class="dns-record-row">';
        if (type === 'A') {
          html += '<span class="dns-val">' + escHtml(r.ip) + '</span>';
          if (r.ttl != null) html += '<span class="dns-ttl">TTL ' + r.ttl + '</span>';
        } else if (type === 'AAAA') {
          html += '<span class="dns-val">' + escHtml(r.ipv6) + '</span>';
          if (r.ttl != null) html += '<span class="dns-ttl">TTL ' + r.ttl + '</span>';
        } else if (type === 'MX') {
          html += '<span class="dns-pri">' + r.priority + '</span>';
          html += '<span class="dns-val">' + escHtml(r.host) + '</span>';
          if (r.ttl != null) html += '<span class="dns-ttl">TTL ' + r.ttl + '</span>';
        } else if (type === 'TXT') {
          html += '<span class="dns-val dns-txt">' + escHtml(r.txt) + '</span>';
          if (r.ttl != null) html += '<span class="dns-ttl">TTL ' + r.ttl + '</span>';
        } else if (type === 'NS' || type === 'CNAME') {
          html += '<span class="dns-val">' + escHtml(r.target) + '</span>';
          if (r.ttl != null) html += '<span class="dns-ttl">TTL ' + r.ttl + '</span>';
        }
        html += '</div>';
      });
      html += '</div></div>';
    });
    if (!hasRecords) {
      html += '<div class="dns-empty">' + dnsNoRecordsTxt + '</div>';
    }
    html += '</div>';
    return html;
  }

  // ── Raw data toggle ─────────────────────────────────────────────────────
  const showRawTxt = <?php echo json_encode($T['show_raw_data']); ?>;
  const hideRawTxt = <?php echo json_encode($T['hide_raw_data']); ?>;
  window.toggleDetails = btn3 => {
    const c = btn3.nextElementSibling;
    const v = c.style.display === 'block';
    c.style.display = v ? 'none' : 'block';
    btn3.textContent = v ? showRawTxt : hideRawTxt;
  };

  // ── Batch post-processing ──────────────────────────────────────────────
  const batchFoundTxt = <?php echo json_encode($T['batch_found']); ?>;
  const batchAllTxt = <?php echo json_encode($T['batch_all']); ?>;
  const batchErrorTxt = <?php echo json_encode($T['batch_error']); ?>;
  const batchJumpTpl = <?php echo json_encode($T['batch_available_jump']); ?>;
  const batchItems = document.querySelectorAll('.batch-item');
  if (batchItems.length > 1) {
    const counts = {available:0, registered:0, restricted:0, error:0};
    const allTexts = [];
    let firstAvail = null;

    batchItems.forEach(item => {
      const body = item.querySelector('.batch-item-body');
      if (!body) return;
      const html = body.innerHTML;
      const label = item.querySelector('.batch-query-text');
      const qname = label ? label.textContent : '';
      allTexts.push(qname);

      // Detect status from rendered content
      let status = 'error';
      if (html.includes('status-available') || html.includes('badge-avail')
          || html.includes('<?php echo addslashes($T['domain_available']); ?>')) {
        status = 'available';
      } else if (html.includes('status-restricted') || html.includes('badge-restricted')
                 || html.includes('<?php echo addslashes($T['status_restricted']); ?>')) {
        status = 'restricted';
      } else if (html.includes('rc-header') || html.includes('rc-domain')
                 || html.includes('registrar-panel') || html.includes('badge-iana')) {
        status = 'registered';
      }
      // Also check for IP/ASN results (have rc-header but no registrar-panel)
      if (status === 'registered' && !html.includes('registrar-panel')
          && !html.includes('rc-dates-row') && html.includes('raw-data-wrapper')) {
        status = 'found'; // IP/ASN — treat as registered for filtering
      }

      item.setAttribute('data-status', status);
      if (status === 'available') counts.available++;
      else if (status === 'registered' || status === 'found') counts.registered++;
      else if (status === 'restricted') counts.restricted++;
      else counts.error++;

      // Set status badge
      const badge = item.querySelector('.batch-status-badge');
      if (badge) {
        if (status === 'available') {
          badge.className = 'batch-status-badge badge-avail';
          badge.textContent = <?php echo json_encode($T['domain_available_badge']); ?>;
          if (!firstAvail) firstAvail = item;
        } else if (status === 'registered' || status === 'found') {
          badge.className = 'batch-status-badge badge-reg';
          badge.textContent = status === 'found' ? batchFoundTxt : <?php echo json_encode($T['batch_registered'] ?? 'Registered'); ?>;
        } else if (status === 'restricted') {
          badge.className = 'batch-status-badge badge-restrict';
          badge.textContent = <?php echo json_encode($T['status_restricted']); ?>;
        } else {
          badge.className = 'batch-status-badge badge-err';
          badge.textContent = <?php echo json_encode($T['lookup_error_title'] ?? $T['no_info_found']); ?>;
        }
      }
    });

    // Auto-collapse for large batches
    if (batchItems.length >= 50) {
      batchItems.forEach(item => item.classList.add('batch-collapsed'));
    }

    // Build filter buttons
    const filtersEl = document.getElementById('batch-filters');
    if (filtersEl) {
      const filterData = [
        {key:'all', label:batchAllTxt, count:batchItems.length},
        {key:'available', label:<?php echo json_encode($T['domain_available_badge']); ?>, count:counts.available},
        {key:'registered', label:<?php echo json_encode($T['batch_registered'] ?? 'Registered'); ?>, count:counts.registered},
        {key:'restricted', label:<?php echo json_encode($T['status_restricted']); ?>, count:counts.restricted},
        {key:'error', label:batchErrorTxt, count:counts.error},
      ];
      filterData.forEach(f => {
        if (f.count === 0 && f.key !== 'all') return;
        const btn = document.createElement('button');
        btn.className = 'batch-filter-btn' + (f.key === 'all' ? ' active' : '');
        btn.innerHTML = f.label + '<span class="filter-count">' + f.count + '</span>';
        btn.onclick = () => {
          filtersEl.querySelectorAll('.batch-filter-btn').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          batchItems.forEach(item => {
            if (f.key === 'all') {
              item.classList.remove('batch-hidden');
            } else {
              item.classList.toggle('batch-hidden', item.getAttribute('data-status') !== f.key);
            }
          });
        };
        filtersEl.appendChild(btn);
      });
    }

    // Jump to first available
    if (firstAvail && counts.available > 0) {
      const jumpEl = document.getElementById('batch-available-jump');
      const jumpTxt = document.getElementById('batch-jump-text');
      if (jumpEl && jumpTxt) {
        jumpTxt.textContent = batchJumpTpl.replace('%d', counts.available);
        jumpEl.style.display = 'block';
        jumpEl.onclick = () => {
          // Filter to available first
          filtersEl.querySelectorAll('.batch-filter-btn').forEach(b => b.classList.remove('active'));
          const availBtn = filtersEl.querySelector('.batch-filter-btn:nth-child(2)');
          if (availBtn) availBtn.click();
          firstAvail.scrollIntoView({behavior:'smooth', block:'center'});
          firstAvail.style.boxShadow = '0 0 0 3px var(--clr-success)';
          setTimeout(() => firstAvail.style.boxShadow = '', 2000);
        };
      }
    }

    // Expand / Collapse all
    const expBtn = document.getElementById('batch-expand-all');
    const colBtn = document.getElementById('batch-collapse-all');
    if (expBtn) expBtn.onclick = () => batchItems.forEach(i => i.classList.remove('batch-collapsed'));
    if (colBtn) colBtn.onclick = () => batchItems.forEach(i => i.classList.add('batch-collapsed'));
  }

  window.toggleBatchItem = el => el.classList.toggle('batch-collapsed');
})();
</script>
</body>
</html>
