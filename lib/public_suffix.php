<?php
declare(strict_types=1);

/** lib/public_suffix.php — registrable-domain matching using the PSL ICANN section. */

if (!defined('PUBLIC_SUFFIX_LIST_FILE')) {
    define('PUBLIC_SUFFIX_LIST_FILE', dirname(__DIR__) . '/data/public_suffix_list.dat');
}

/**
 * @return array{exact:array<string,true>,wildcard:array<string,true>,exception:array<string,true>}
 */
function loadPublicSuffixRules(): array {
    static $rules = null;
    if (is_array($rules)) return $rules;

    $rules = ['exact' => [], 'wildcard' => [], 'exception' => []];
    $handle = @fopen(PUBLIC_SUFFIX_LIST_FILE, 'rb');
    if ($handle === false) return $rules;

    $inIcann = false;
    while (($line = fgets($handle)) !== false) {
        $line = trim($line);
        if ($line === '// ===BEGIN ICANN DOMAINS===') { $inIcann = true; continue; }
        if ($line === '// ===END ICANN DOMAINS===') break;
        if (!$inIcann || $line === '' || str_starts_with($line, '//')) continue;

        $type = 'exact';
        if ($line[0] === '!') {
            $type = 'exception';
            $line = substr($line, 1);
        } elseif (str_starts_with($line, '*.')) {
            $type = 'wildcard';
            $line = substr($line, 2);
        }
        $ascii = idn_to_ascii($line, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($ascii !== false && $ascii !== '') $rules[$type][strtolower($ascii)] = true;
    }
    fclose($handle);
    return $rules;
}

/**
 * Return the eTLD+1 used for registry lookups, or null when the input itself
 * is a public suffix / invalid. PRIVATE PSL rules are deliberately ignored.
 */
function getRegistrableDomain(string $domain): ?string {
    $ascii = idn_to_ascii(trim($domain, ". \t\n\r\0\x0B"), IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($ascii === false) return null;
    $ascii = strtolower($ascii);
    if (!filter_var($ascii, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) return null;

    $labels = explode('.', $ascii);
    $count = count($labels);
    if ($count < 2) return null;

    $rules = loadPublicSuffixRules();
    $publicSuffixLabels = 1; // prevailing '*' rule
    $exceptionLabels = null;

    for ($i = 0; $i < $count; $i++) {
        $candidate = implode('.', array_slice($labels, $i));
        $candidateLabels = $count - $i;
        if (isset($rules['exception'][$candidate])) {
            $exceptionLabels = max(1, $candidateLabels - 1);
            break;
        }
        if (isset($rules['exact'][$candidate])) {
            $publicSuffixLabels = max($publicSuffixLabels, $candidateLabels);
        }
        if ($i > 0 && isset($rules['wildcard'][$candidate])) {
            $publicSuffixLabels = max($publicSuffixLabels, $candidateLabels + 1);
        }
    }

    if ($exceptionLabels !== null) $publicSuffixLabels = $exceptionLabels;
    if ($count <= $publicSuffixLabels) return null;
    return implode('.', array_slice($labels, -($publicSuffixLabels + 1)));
}

function normalizeDomainForLookup(string $domain): ?string {
    return getRegistrableDomain($domain);
}

