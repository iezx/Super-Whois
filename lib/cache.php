<?php
declare(strict_types=1);

/** lib/cache.php — lock-safe JSON file cache with stale-on-error support. */

function ensureRuntimeDirectory(string $dir): bool {
    if (is_dir($dir)) return true;
    return @mkdir($dir, 0750, true) || is_dir($dir);
}

function ensureCacheDir(): void {
    ensureRuntimeDirectory(CACHE_DIR);
    ensureRuntimeDirectory(CACHE_DIR . DIRECTORY_SEPARATOR . '.locks');
}

function cacheFilePath(string $key): string {
    return CACHE_DIR . DIRECTORY_SEPARATOR . hash('sha256', $key) . '.json';
}

function cacheLockPath(string $key): string {
    // A fixed set of lock stripes bounds inode/file growth while preserving
    // single-flight behavior for identical keys.
    return CACHE_DIR . DIRECTORY_SEPARATOR . '.locks' . DIRECTORY_SEPARATOR
        . substr(hash('sha256', $key), 0, 3) . '.lock';
}

/**
 * @return array{hit:bool,stale:bool,value:mixed,age:int,expires_at:int}
 */
function cacheReadEntry(string $key, int $legacyTtl = 0, int $maxStaleAge = 0): array {
    $miss = ['hit' => false, 'stale' => false, 'value' => null, 'age' => 0, 'expires_at' => 0];
    $file = cacheFilePath($key);
    $fp = @fopen($file, 'rb');
    if ($fp === false) return $miss;

    if (!flock($fp, LOCK_SH)) { fclose($fp); return $miss; }
    $raw = stream_get_contents($fp);
    $mtime = (int)(@fstat($fp)['mtime'] ?? 0);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!is_string($raw) || $raw === '') return $miss;

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) return $miss;

    $now = time();
    if (array_key_exists('value', $decoded) && isset($decoded['created_at'], $decoded['expires_at'])) {
        $createdAt = (int)$decoded['created_at'];
        $expiresAt = (int)$decoded['expires_at'];
        $value = $decoded['value'];
    } else {
        // Read caches produced by v2.2.1; the next write upgrades the format.
        $createdAt = $mtime;
        $expiresAt = $mtime + max(0, $legacyTtl);
        $value = $decoded;
    }

    $age = max(0, $now - $createdAt);
    if ($expiresAt >= $now) {
        return ['hit' => true, 'stale' => false, 'value' => $value, 'age' => $age, 'expires_at' => $expiresAt];
    }
    if ($maxStaleAge > 0 && $now - $expiresAt <= $maxStaleAge) {
        return ['hit' => true, 'stale' => true, 'value' => $value, 'age' => $age, 'expires_at' => $expiresAt];
    }
    return $miss;
}

function cacheWriteEntry(string $key, mixed $value, int $ttl): bool {
    ensureCacheDir();
    if (!is_dir(CACHE_DIR)) return false;

    $now = time();
    $payload = json_encode([
        'created_at' => $now,
        'expires_at' => $now + max(1, $ttl),
        'value' => $value,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if (!is_string($payload)) return false;

    $fp = @fopen(cacheFilePath($key), 'c+b');
    if ($fp === false) return false;
    if (!flock($fp, LOCK_EX)) { fclose($fp); return false; }
    ftruncate($fp, 0);
    rewind($fp);
    $written = fwrite($fp, $payload);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    cacheScheduleGarbageCollection();
    return $written === strlen($payload);
}

function cacheScheduleGarbageCollection(): void {
    static $scheduled = false;
    if (!CACHE_GC_ENABLED || $scheduled) return;
    $marker = CACHE_DIR . DIRECTORY_SEPARATOR . '.gc-marker';
    if (is_file($marker) && time() - (int)@filemtime($marker) < CACHE_GC_INTERVAL) return;
    $scheduled = true;
    register_shutdown_function('cacheGarbageCollect');
}

function cacheGarbageCollect(): void {
    ensureCacheDir();
    $gcLock = @fopen(CACHE_DIR . DIRECTORY_SEPARATOR . '.gc.lock', 'c+b');
    if ($gcLock === false || !flock($gcLock, LOCK_EX | LOCK_NB)) {
        if (is_resource($gcLock)) fclose($gcLock);
        return;
    }
    $marker = CACHE_DIR . DIRECTORY_SEPARATOR . '.gc-marker';
    if (is_file($marker) && time() - (int)@filemtime($marker) < CACHE_GC_INTERVAL) {
        flock($gcLock, LOCK_UN); fclose($gcLock); return;
    }
    @touch($marker);
    $files = glob(CACHE_DIR . DIRECTORY_SEPARATOR . '*.json') ?: [];
    $totalBytes = 0;
    foreach ($files as $file) $totalBytes += max(0, (int)@filesize($file));
    if (count($files) <= CACHE_MAX_FILES && $totalBytes <= CACHE_MAX_BYTES) {
        flock($gcLock, LOCK_UN); fclose($gcLock); return;
    }
    usort($files, static fn($a, $b) => ((int)@filemtime($a)) <=> ((int)@filemtime($b)));
    $targetFiles = (int)floor(CACHE_MAX_FILES * 0.9);
    $targetBytes = (int)floor(CACHE_MAX_BYTES * 0.9);
    $remainingFiles = count($files);
    foreach ($files as $file) {
        if ($remainingFiles <= $targetFiles && $totalBytes <= $targetBytes) break;
        $size = max(0, (int)@filesize($file));
        if (@unlink($file)) { $remainingFiles--; $totalBytes -= $size; }
    }
    flock($gcLock, LOCK_UN);
    fclose($gcLock);
}

function cacheDelete(string $key): void {
    $file = cacheFilePath($key);
    if (is_file($file)) @unlink($file);
}

/**
 * Read a fresh value or fetch it once across concurrent PHP workers. When a
 * refresh fails, the last known good value is returned within the stale window.
 */
function cacheGetOrFetch(string $key, int $ttl, callable $fetch, int $maxStaleAge = CACHE_STALE_MAX_AGE): mixed {
    ensureCacheDir();
    $entry = cacheReadEntry($key, $ttl, $maxStaleAge);
    if ($entry['hit'] && !$entry['stale']) {
        appendLog('cache_hit', ['key' => $key, 'age' => $entry['age']]);
        return $entry['value'];
    }

    $lock = @fopen(cacheLockPath($key), 'c+b');
    if ($lock === false || !flock($lock, LOCK_EX)) {
        if (is_resource($lock)) fclose($lock);
        return $entry['hit'] ? $entry['value'] : $fetch();
    }

    // Another worker may have refreshed while this worker waited for the lock.
    $latest = cacheReadEntry($key, $ttl, $maxStaleAge);
    if ($latest['hit'] && !$latest['stale']) {
        flock($lock, LOCK_UN);
        fclose($lock);
        return $latest['value'];
    }

    $value = $fetch();
    if ($value !== null) cacheWriteEntry($key, $value, $ttl);
    flock($lock, LOCK_UN);
    fclose($lock);

    if ($value !== null) return $value;
    $stale = $latest['hit'] ? $latest : $entry;
    if ($stale['hit']) {
        appendLog('cache_stale_fallback', ['key' => $key, 'age' => $stale['age']]);
        return $stale['value'];
    }
    return null;
}

/**
 * Dynamic-TTL single-flight cache used by lookup results.
 *
 * @return array{value:mixed,hit:bool,stale:bool,age:int}
 */
function cacheGetOrCompute(
    string $key,
    callable $compute,
    callable $ttlForValue,
    callable $isTransientFailure,
    int $maxStaleAge = CACHE_STALE_MAX_AGE,
    ?callable $canUseStale = null
): array {
    ensureCacheDir();
    $entry = cacheReadEntry($key, 0, $maxStaleAge);
    if ($entry['hit'] && !$entry['stale']) {
        return ['value' => $entry['value'], 'hit' => true, 'stale' => false, 'age' => $entry['age']];
    }

    $lock = @fopen(cacheLockPath($key), 'c+b');
    if ($lock === false || !flock($lock, LOCK_EX)) {
        if (is_resource($lock)) fclose($lock);
        $value = $compute();
        return ['value' => $value, 'hit' => false, 'stale' => false, 'age' => 0];
    }

    $latest = cacheReadEntry($key, 0, $maxStaleAge);
    if ($latest['hit'] && !$latest['stale']) {
        flock($lock, LOCK_UN);
        fclose($lock);
        return ['value' => $latest['value'], 'hit' => true, 'stale' => false, 'age' => $latest['age']];
    }

    $value = $compute();
    $stale = $latest['hit'] ? $latest : $entry;
    if ($isTransientFailure($value) && $stale['hit']
        && ($canUseStale === null || $canUseStale($stale['value']))) {
        flock($lock, LOCK_UN);
        fclose($lock);
        return ['value' => $stale['value'], 'hit' => true, 'stale' => true, 'age' => $stale['age']];
    }

    $ttl = max(1, (int)$ttlForValue($value));
    cacheWriteEntry($key, $value, $ttl);
    flock($lock, LOCK_UN);
    fclose($lock);
    return ['value' => $value, 'hit' => false, 'stale' => false, 'age' => 0];
}
