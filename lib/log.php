<?php
// lib/log.php — Structured JSON logging with auto-cleanup

/**
 * Append a structured JSON line to today's log file.
 * All logging funnels through here — no more per-IP fragmented files.
 */
function appendLog(string $event, array $context = []): void {
    $dir = LOG_DIR;
    if (!ensureRuntimeDirectory($dir)) return;
    $file = $dir . DIRECTORY_SEPARATOR . gmdate('Y-m-d') . '.log';
    if (!LOG_QUERY_VALUES) {
        foreach (['query', 'domain'] as $sensitiveKey) unset($context[$sensitiveKey]);
    }
    $base = [
        'ts'    => gmdate('Y-m-d\TH:i:s\Z'),
        'event' => $event,
    ];
    if (LOG_CLIENT_IDENTIFIERS) $base['client'] = hash('sha256', getClientIP());
    $entry = json_encode(array_merge($base, $context),
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
    $fp = @fopen($file, 'ab');
    if ($fp) { flock($fp, LOCK_EX); fwrite($fp, $entry); flock($fp, LOCK_UN); fclose($fp); }
    // Cleanup old logs roughly 1% of the time to avoid overhead
    if (mt_rand(1, 100) === 1) cleanOldLogs();
}

/**
 * Delete log files older than LOG_KEEP_DAYS days.
 */
function cleanOldLogs(): void {
    $dir = LOG_DIR;
    if (!is_dir($dir)) return;
    $cutoff = time() - (LOG_KEEP_DAYS * 86400);
    foreach (glob($dir . '/*.log') ?: [] as $f) {
        if (filemtime($f) < $cutoff) @unlink($f);
    }
}
