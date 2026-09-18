<?php
/*
 * Debug jobs are separate from DNS updates. Only sanitized reports are saved.
 * This include never starts a job merely because a page was opened.
 */
define('MWDDNS_DEBUG_DIR', '/tmp/mwddns-debug');
define('MWDDNS_DEBUG_LEGACY_DIR', MWDDNS_DNS_CACHE_DIR . '/debug');
define('MWDDNS_DEBUG_STORAGE_MARGIN', 1024 * 1024);
define('MWDDNS_DEBUG_MAX_REPORT', 6 * 1024 * 1024);

function mwddns_debug_settings(): array
{
    global $config;
    $raw = $config[MWDDNS_CONFIG_KEY]['debug'] ?? [];
    $raw = is_array($raw) ? $raw : [];
    $days = filter_var($raw['days'] ?? 3, FILTER_VALIDATE_INT);
    return [
        'days' => $days !== false && $days >= 1 && $days <= 14 ? $days : 3,
        'network' => ($raw['network'] ?? 'yes') === 'yes',
        'web' => ($raw['web'] ?? 'yes') === 'yes',
        'runtime' => ($raw['runtime'] ?? 'yes') === 'yes',
    ];
}

function mwddns_debug_revision(array $settings): string
{
    return hash('sha256', json_encode($settings, JSON_THROW_ON_ERROR));
}

function mwddns_debug_save(array $post): array
{
    $days = is_string($post['days'] ?? null) && ctype_digit($post['days'])
        ? (int)$post['days'] : 0;
    if ($days < 1 || $days > 14 || !is_string($post['revision'] ?? null)) {
        throw new RuntimeException('Invalid debug settings.');
    }
    $settings = ['days' => $days];
    foreach (['network', 'web', 'runtime'] as $key) {
        if (isset($post[$key]) && $post[$key] !== 'yes') {
            throw new RuntimeException('Invalid debug settings.');
        }
        $settings[$key] = isset($post[$key]);
    }
    mwddns_with_operation_lock(static function () use ($settings, $post): void {
        global $config;
        mwddns_reload_config();
        $current = mwddns_debug_settings();
        if (!hash_equals(mwddns_debug_revision($current), $post['revision'])) {
            throw new RuntimeException('Configuration changed. Reload the page before saving.');
        }
        if ($settings === $current) {
            return;
        }
        $before = $config;
        try {
            $stored = ['days' => (string)$settings['days']];
            foreach (['network', 'web', 'runtime'] as $key) {
                $stored[$key] = $settings[$key] ? 'yes' : 'no';
            }
            $config[MWDDNS_CONFIG_KEY]['debug'] = $stored;
            $saved = write_config('MWDDNS: debug collection settings saved');
            if ($saved === false || $saved === -1) {
                throw new RuntimeException('Configuration write failed.');
            }
        } catch (Throwable $e) {
            $config = $before;
            throw new RuntimeException('Configuration could not be saved. No DNS update was started.');
        }
    });
    return $settings;
}

/** The GUI-only legend and the collector derive aliases in the same order. */
function mwddns_debug_wans(): array
{
    global $config;
    $wanted = ['wan' => true];
    foreach (mwddns_get_rules() as $rule) {
        foreach (mwddns_rule_interfaces($rule) as $key) {
            $wanted[$key] = true;
        }
    }
    $items = $config['gateways']['gateway_item'] ?? [];
    if (isset($items['name'])) {
        $items = [$items];
    }
    foreach (is_array($items) ? $items : [] as $gateway) {
        if (is_string($gateway['interface'] ?? null)) {
            $wanted[$gateway['interface']] = true;
        }
    }
    $keys = array_keys(array_intersect_key($config['interfaces'] ?? [], $wanted));
    usort($keys, static function ($a, $b): int {
        if ($a === $b) {
            return 0;
        }
        return $a === 'wan' ? -1 : ($b === 'wan' ? 1 : strnatcmp($a, $b));
    });
    $rows = [];
    foreach ($keys as $key) {
        $rows[] = [
            'alias' => 'WAN_' . (count($rows) + 1),
            'key' => $key,
            'description' => (string)($config['interfaces'][$key]['descr'] ?? $key),
            'device' => (string)($config['interfaces'][$key]['if'] ?? ''),
        ];
    }
    return $rows;
}

function mwddns_debug_private_directory(string $path): bool
{
    clearstatcache(true, $path);
    return !is_link($path) && is_dir($path) && fileowner($path) === 0 &&
        (fileperms($path) & 0077) === 0;
}

function mwddns_debug_directory(): void
{
    if (!file_exists(MWDDNS_DEBUG_DIR) && !is_link(MWDDNS_DEBUG_DIR)) {
        $old = umask(0077);
        try { @mkdir(MWDDNS_DEBUG_DIR, 0700); }
        finally { umask($old); }
    }
    // Never adopt a directory planted by another user in world-writable /tmp.
    if (!mwddns_debug_private_directory(MWDDNS_DEBUG_DIR)) {
        throw new RuntimeException('Debug storage is unavailable.');
    }
}

/** Legacy reports stay downloadable; new jobs are never written to /var/run. */
function mwddns_debug_roots(): array
{
    $roots = [];
    foreach ([MWDDNS_DEBUG_DIR, MWDDNS_DEBUG_LEGACY_DIR] as $root) {
        if ($root === MWDDNS_DEBUG_LEGACY_DIR && is_link(MWDDNS_DNS_CACHE_DIR)) { continue; }
        if (mwddns_debug_private_directory($root)) { $roots[] = $root; }
    }
    return $roots;
}

function mwddns_debug_paths(): array
{
    $paths = [];
    foreach (mwddns_debug_roots() as $root) {
        foreach (glob($root . '/job-*', GLOB_ONLYDIR) ?: [] as $path) {
            $id = substr(basename($path), 4);
            if (preg_match('/^[a-f0-9]{32}$/D', $id) &&
                mwddns_debug_private_directory($path) && !isset($paths[$id])) {
                $paths[$id] = $path;
            }
        }
    }
    return $paths;
}

function mwddns_debug_path(string $id): string
{
    if (!preg_match('/^[a-f0-9]{32}$/D', $id)) {
        throw new RuntimeException('Invalid debug report.');
    }
    foreach (mwddns_debug_roots() as $root) {
        $path = $root . '/job-' . $id;
        if (file_exists($path) || is_link($path)) {
            if (!mwddns_debug_private_directory($path)) {
                throw new RuntimeException('Invalid debug report.');
            }
            return $path;
        }
    }
    return MWDDNS_DEBUG_DIR . '/job-' . $id;
}

function mwddns_debug_json(string $path): array
{
    if (is_link($path) || !is_file($path) || filesize($path) > 65536) {
        return [];
    }
    $raw = @file_get_contents($path, false, null, 0, 65537);
    $data = is_string($raw) ? json_decode($raw, true) : null;
    return is_array($data) ? $data : [];
}

function mwddns_debug_write(string $path, array $data): void
{
    $tmp = $path . '.tmp';
    if (is_link($tmp) || is_link($path)) {
        throw new RuntimeException('Debug storage is unavailable.');
    }
    $old = umask(0077);
    try {
        $json = json_encode($data, JSON_THROW_ON_ERROR) . "\n";
        if (file_put_contents($tmp, $json) === false || !rename($tmp, $path)) {
            throw new RuntimeException('Debug storage is unavailable.');
        }
    } finally {
        umask($old);
        if (is_file($tmp)) {
            @unlink($tmp);
        }
    }
}

/** Fixed labels also define the export allowlist. Never export exception text. */
function mwddns_debug_diagnostic_labels(): array
{
    return [
        'stage' => [
            'unknown' => 'Not reported', 'starting' => 'Starting collector',
            'snapshot' => 'Reading runtime snapshot', 'privacy_setup' => 'Preparing privacy filters',
            'source_order' => 'Ordering log sources', 'enumerate' => 'Finding log rotations',
            'open_file' => 'Opening log rotation', 'read_record' => 'Reading log record',
            'parse_timestamp' => 'Parsing record timestamp', 'classify_event' => 'Classifying event',
            'group_event' => 'Grouping event', 'source_summary' => 'Summarizing source',
            'allocate' => 'Allocating report groups', 'report_limit' => 'Applying report size limit',
            'serialize_report' => 'Encoding report', 'report_space' => 'Checking report storage space',
            'write_report' => 'Writing report', 'sync_report' => 'Flushing report to storage',
            'publish_report' => 'Publishing report file', 'final_status' => 'Recording completion status',
            'complete' => 'Collection complete',
        ],
        'error_code' => [
            'NONE' => 'No collection failure recorded.',
            'WALL_TIME_LIMIT' => 'Worker wall-clock deadline reached.',
            'CPU_TIME_LIMIT' => 'Worker CPU limit reached.',
            'MEMORY_ALLOCATION_FAILED' => 'Worker memory allocation failed.',
            'SNAPSHOT_TIMEOUT' => 'Runtime snapshot timed out.',
            'SNAPSHOT_FAILED' => 'Runtime snapshot failed.',
            'PROGRESS_WRITE_FAILED' => 'Progress checkpoint could not be written.',
            'IO_FAILED' => 'Collector input or output failed.',
            'DISK_SPACE' => 'Insufficient free space for the report and safety reserve.',
            'DISK_QUOTA' => 'Report storage quota was exceeded.',
            'INVALID_INPUT' => 'Collector input or report data was invalid.',
            'COLLECTOR_EXCEPTION' => 'Collector encountered an unexpected exception.',
            'START_FAILED' => 'Collector launcher failed.',
            'WORKER_STATUS_STALE' => 'No final worker status received; the cause is unconfirmed.',
            'UNKNOWN_FAILURE' => 'Failure reason was not recorded.',
        ],
    ];
}

function mwddns_debug_diagnostics(array $status): array
{
    $raw = is_array($status['diagnostics'] ?? null) ? $status['diagnostics'] : [];
    $labels = mwddns_debug_diagnostic_labels();
    $safe = [];
    foreach (['stage' => 'unknown', 'error_code' => 'NONE'] as $key => $fallback) {
        $value = $raw[$key] ?? null;
        $safe[$key] = is_string($value) && isset($labels[$key][$value]) ? $value : $fallback;
    }
    $source = $raw['source'] ?? null;
    $safe['source'] = is_string($source) &&
        in_array($source, ['none', 'system', 'dhcp', 'gateways', 'ppp', 'routing', 'php', 'nginx'], true)
        ? $source : 'none';
    foreach (['elapsed_seconds', 'cpu_seconds'] as $key) {
        $value = $raw[$key] ?? null;
        if ((is_int($value) || is_float($value)) && is_finite((float)$value) &&
            $value >= 0 && $value <= 86400) {
            $safe[$key] = (float)$value;
        }
    }
    foreach ([
        'checkpoint_at' => 4102444800, 'file_index' => 24, 'record_index' => 10000000,
        'record_bytes' => 16385, 'record_epoch' => 4102444800,
        'source_bytes_scanned' => 67108864, 'matched_events' => 100000000,
        'candidate_event_groups' => 5000, 'requested_days' => 14, 'collector_line' => 1000000,
        'total_sources' => 7, 'total_files_scanned' => 168, 'total_bytes_scanned' => 67108864,
        'total_matched_events' => 100000000, 'total_retained_events' => 100000000,
        'total_dropped_events' => 100000000, 'total_event_groups' => 5000,
        'report_bytes' => 6291456, 'report_written_bytes' => 6291456,
        'storage_free_bytes' => PHP_INT_MAX, 'storage_required_bytes' => 7340032,
        'storage_reserve_bytes' => 1048576, 'io_errno' => 255,
    ] as $key => $maximum) {
        $value = $raw[$key] ?? null;
        if (is_int($value) && $value >= 0 && $value <= $maximum &&
            ($key !== 'requested_days' || $value >= 1)) {
            $safe[$key] = $value;
        }
    }
    foreach (['network', 'web', 'runtime'] as $key) {
        if (is_bool($raw[$key] ?? null)) { $safe[$key] = $raw[$key]; }
    }
    return $safe;
}

function mwddns_debug_status(string $id): array
{
    $status = mwddns_debug_json(mwddns_debug_path($id) . '/status.json');
    $state = $status['state'] ?? 'missing';
    if (!in_array($state, ['queued', 'running', 'complete', 'failed'], true)) {
        $state = 'missing';
    }
    $recorded = $state;
    $started = is_int($status['started'] ?? null) && $status['started'] > 0 &&
        $status['started'] <= 4102444800 ? $status['started'] : 0;
    $diagnostics = mwddns_debug_diagnostics($status);
    if ($state === 'failed' && $diagnostics['error_code'] === 'NONE') {
        $diagnostics['error_code'] = 'UNKNOWN_FAILURE';
    }
    if ($started > 0 && time() - $started >= 86400) {
        $state = 'expired';
    } elseif (in_array($state, ['queued', 'running'], true) && time() - $started > 120) {
        // A missing final write does not prove timeout, OOM or worker exit.
        $state = 'failed';
        $diagnostics['error_code'] = 'WORKER_STATUS_STALE';
    }
    $version = $status['collector_version'] ?? null;
    return [
        'state' => $state, 'recorded_state' => $recorded, 'started' => $started,
        'failure_confirmed' => $recorded === 'failed',
        'collector_version' => is_string($version) &&
            preg_match('/^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$/D', $version) ? $version : null,
        'partial' => is_bool($status['partial'] ?? null) ? $status['partial'] : null,
        'diagnostics' => $diagnostics,
    ];
}

/** Rebuild a small export from allowlisted metadata, including legacy failures. */
function mwddns_debug_diagnostic_report(string $id): array
{
    $status = mwddns_debug_status($id);
    if (!in_array($status['state'], ['complete', 'failed'], true)) {
        throw new RuntimeException('Debug report is unavailable or expired.');
    }
    return [
        'schema' => 'mwddns-debug-job-v1',
        'generated_at' => date(DATE_ATOM),
        'started_at' => $status['started'] > 0 ? date(DATE_ATOM, $status['started']) : null,
        'collector_version' => $status['collector_version'],
        'state' => $status['state'], 'recorded_state' => $status['recorded_state'],
        'failure_confirmed' => $status['failure_confirmed'],
        'diagnostics' => $status['diagnostics'],
        'limits' => ['worker_wall_seconds' => 75, 'cpu_soft_seconds' => 60,
            'cpu_hard_seconds' => 65, 'memory_bytes' => 268435456,
            'scan_wall_seconds' => 60, 'scan_cpu_seconds' => 50],
        'privacy' => ['mode' => 'strict_structured', 'raw_messages_included' => false,
            'configuration_included' => false, 'exception_text_included' => false],
        'limitations' => [
            'Measurements describe the last recorded checkpoint, not the time since the page was opened.',
            'A stale checkpoint does not establish why a worker stopped or whether it has exited.',
            'The last stage, source, record timestamp and counters narrow investigation; they do not establish a root cause.',
            'File and record indexes are scan positions, not exported filenames or physical log line numbers.',
            'Older jobs may have no diagnostic measurements. No private message or traceback is exported.',
        ],
    ];
}

/** A stale GUI state must not permit removal or overlap with a live worker. */
function mwddns_debug_worker_busy(string $id): bool
{
    $path = mwddns_debug_path($id) . '/worker.lock';
    if (is_link($path)) { return true; }
    if (!file_exists($path)) { return false; }
    if (!is_file($path)) { return true; }
    $handle = @fopen($path, 'r');
    if ($handle === false) { return true; }
    try {
        if (!flock($handle, LOCK_EX | LOCK_NB)) { return true; }
        flock($handle, LOCK_UN);
        return false;
    } finally {
        fclose($handle);
    }
}

/** List metadata only; opening the page must not collect or decode full reports. */
function mwddns_debug_jobs(): array
{
    $jobs = [];
    foreach (mwddns_debug_paths() as $path) {
        $id = substr(basename($path), 4);
        if (is_link($path) || !preg_match('/^[a-f0-9]{32}$/D', $id)) { continue; }
        try { $jobs[$id] = mwddns_debug_status($id); }
        catch (Throwable $ignored) { continue; }
    }
    uasort($jobs, static fn(array $a, array $b): int => $b['started'] <=> $a['started']);
    return $jobs;
}

function mwddns_debug_remove(string $id): void
{
    $path = mwddns_debug_path($id);
    if (!is_dir($path)) { return; }
    if (in_array(mwddns_debug_status($id)['state'], ['queued', 'running'], true)) {
        throw new RuntimeException('Debug collection is already running.');
    }
    $lockPath = $path . '/worker.lock';
    if (is_link($lockPath) || (file_exists($lockPath) && !is_file($lockPath))) {
        throw new RuntimeException('Debug storage is unavailable.');
    }
    $old = umask(0077);
    try { $lock = @fopen($lockPath, 'c'); }
    finally { umask($old); }
    if ($lock === false) {
        throw new RuntimeException('Debug storage is unavailable.');
    }
    try {
        if (!flock($lock, LOCK_EX | LOCK_NB) ||
            in_array(mwddns_debug_status($id)['state'], ['queued', 'running'], true)) {
            throw new RuntimeException('Debug collection is already running.');
        }
        foreach (['request.json', 'status.json', 'report.json',
            'request.json.tmp', 'status.json.tmp', 'report.json.tmp', 'status.reserve', 'worker.lock'] as $name) {
            if (is_file($path . '/' . $name) || is_link($path . '/' . $name)) {
                @unlink($path . '/' . $name);
            }
        }
        @rmdir($path);
    } finally {
        fclose($lock);
    }
}

function mwddns_debug_start(array $settings): string
{
    mwddns_debug_directory();
    if (!is_executable('/usr/local/bin/python3.11') || !is_executable('/usr/sbin/daemon')) {
        throw new RuntimeException('Debug collector could not be started.');
    }
    if (is_link(MWDDNS_DEBUG_DIR . '/admission.lock')) {
        throw new RuntimeException('Debug storage is unavailable.');
    }
    $lock = @fopen(MWDDNS_DEBUG_DIR . '/admission.lock', 'c');
    if ($lock === false) {
        throw new RuntimeException('Debug storage is unavailable.');
    }
    try {
        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            throw new RuntimeException('Debug collection is already running.');
        }
        $free = @disk_free_space(MWDDNS_DEBUG_DIR);
        if ($free === false || $free < MWDDNS_DEBUG_MAX_REPORT + MWDDNS_DEBUG_STORAGE_MARGIN + 65536) {
            throw new RuntimeException('Debug storage has insufficient free space. Free space in /tmp and retry.');
        }
        $old = [];
        foreach (mwddns_debug_paths() as $path) {
            $id = substr(basename($path), 4);
            if (!preg_match('/^[a-f0-9]{32}$/D', $id) || is_link($path)) {
                continue;
            }
            $status = mwddns_debug_status($id);
            if (in_array($status['state'], ['queued', 'running'], true) ||
                mwddns_debug_worker_busy($id)) {
                throw new RuntimeException('Debug collection is already running.');
            }
            if ($status['state'] === 'expired' || $status['state'] === 'missing') {
                mwddns_debug_remove($id);
            } else {
                $old[$id] = $status['started'];
            }
        }
        asort($old);
        while (count($old) >= 3) {
            $id = array_key_first($old);
            mwddns_debug_remove($id);
            unset($old[$id]);
        }
        $id = bin2hex(random_bytes(16));
        $path = mwddns_debug_path($id);
        if (!mkdir($path, 0700)) {
            throw new RuntimeException('Debug storage is unavailable.');
        }
        $started = time();
        mwddns_debug_write($path . '/request.json', $settings);
        mwddns_debug_write($path . '/status.json', ['state' => 'queued', 'started' => $started]);
        // Fixed argv, closed inherited descriptors, no shell or long GUI work.
        $process = @proc_open([
            '/usr/sbin/daemon', '-f', '/usr/local/bin/python3.11', '-B',
            '/usr/local/bin/mwddns_debug.py', $id,
        ], [
            0 => ['file', '/dev/null', 'r'],
            1 => ['file', '/dev/null', 'w'],
            2 => ['file', '/dev/null', 'w'],
        ], $pipes);
        if (!is_resource($process) || proc_close($process) !== 0) {
            mwddns_debug_write($path . '/status.json', [
                'state' => 'failed', 'started' => $started,
                'diagnostics' => ['stage' => 'starting', 'source' => 'none',
                    'error_code' => 'START_FAILED', 'checkpoint_at' => time()],
            ]);
            throw new RuntimeException('Debug collector could not be started.');
        }
        return $id;
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function mwddns_debug_report_path(string $id): string
{
    $path = mwddns_debug_path($id) . '/report.json';
    if (mwddns_debug_status($id)['state'] !== 'complete' ||
        is_link($path) || !is_file($path) || filesize($path) > MWDDNS_DEBUG_MAX_REPORT) {
        throw new RuntimeException('Debug report is unavailable or expired.');
    }
    return $path;
}

/** Fixed, bounded summary fields only; raw report text is never a GUI label. */
function mwddns_debug_summary(string $json): array
{
    if (strlen($json) > MWDDNS_DEBUG_MAX_REPORT) {
        return [];
    }
    $report = json_decode($json, true, 64);
    if (!is_array($report) || !is_array($report['sources'] ?? null)) {
        return [];
    }
    $coverageLabels = [
        'unavailable' => 'Log unavailable', 'unreadable' => 'Log unreadable',
        'empty' => 'Empty log', 'stale' => 'Logs predate requested window',
        'no_records_in_window' => 'No timestamped records in requested window',
        'no_matching_events' => 'No matching events in requested window',
        'observed' => 'Records observed in requested window',
    ];
    $limitWarnings = [
        'ROTATION_FILE_LIMIT', 'SOURCE_BYTE_LIMIT', 'SOURCE_TIME_LIMIT',
        'FILE_HEAD_SKIPPED', 'OVERLONG_RECORD_SKIPPED', 'TRUNCATED_RECORD_SKIPPED',
        'FILE_READ_LIMIT', 'SOURCE_EVENT_LIMIT', 'SHARED_EVENT_LIMIT',
        'REPORT_SIZE_LIMIT', 'DHCP_HISTOGRAM_BUCKET_LIMIT',
    ];
    $allowedWarnings = array_merge($limitWarnings, [
        'LOG_UNAVAILABLE', 'ZSTD_ROTATION_NOT_SUPPORTED', 'FILE_UNREADABLE_OR_INVALID',
        'REQUESTED_START_NOT_OBSERVED', 'NO_RECORDS_IN_REQUESTED_WINDOW',
        'SOME_LINES_HAVE_NO_PARSED_TIMESTAMP', 'EMPTY_LOG',
    ]);
    $warningLabels = [
        'ROTATION_FILE_LIMIT' => 'Rotation file count limit reached.',
        'SOURCE_BYTE_LIMIT' => 'Source read-byte limit reached.',
        'SOURCE_TIME_LIMIT' => 'Allocated scan time exhausted; some records may be unread.',
        'FILE_HEAD_SKIPPED' => 'The beginning of a large log file was skipped.',
        'OVERLONG_RECORD_SKIPPED' => 'An overlong log record was skipped.',
        'TRUNCATED_RECORD_SKIPPED' => 'A partial log record was skipped.',
        'FILE_READ_LIMIT' => 'Per-file read limit reached.',
        'SOURCE_EVENT_LIMIT' => 'Candidate group capacity reached; some scanned events were dropped.',
        'SHARED_EVENT_LIMIT' => 'Shared output group limit reached.',
        'REPORT_SIZE_LIMIT' => 'Report size limit reached.',
        'DHCP_HISTOGRAM_BUCKET_LIMIT' => 'DHCP histogram bucket limit reached.',
        'LOG_UNAVAILABLE' => 'Log files were unavailable.',
        'ZSTD_ROTATION_NOT_SUPPORTED' => 'Zstandard log rotations are not supported.',
        'FILE_UNREADABLE_OR_INVALID' => 'A log file could not be read or decoded.',
        'REQUESTED_START_NOT_OBSERVED' => 'Requested start was not observed; retention or scan limits may be responsible.',
        'NO_RECORDS_IN_REQUESTED_WINDOW' => 'No records were observed in the requested window.',
        'SOME_LINES_HAVE_NO_PARSED_TIMESTAMP' => 'Some log timestamps could not be parsed.',
        'EMPTY_LOG' => 'The log was empty.',
    ];
    $seconds = static function ($value): ?float {
        return (is_int($value) || is_float($value)) && is_finite((float)$value) &&
            $value >= 0 && $value <= 75 ? (float)$value : null;
    };
    $timestamp = static function ($value): string {
        return is_string($value) && preg_match(
            '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/D', $value)
            ? $value : '';
    };
    $count = static function ($value): int {
        return is_int($value) && $value >= 0 ? $value : 0;
    };
    $rows = [];
    foreach (array_slice($report['sources'], 0, 7) as $source) {
        if (!is_array($source) || !is_string($source['source'] ?? null) ||
            !in_array($source['source'], ['system', 'dhcp', 'gateways', 'ppp', 'routing', 'php', 'nginx'], true) ||
            isset($rows[$source['source']])) {
            continue;
        }
        $warnings = [];
        foreach (array_slice(is_array($source['warnings'] ?? null) ? $source['warnings'] : [], 0, 32) as $warning) {
            if (is_string($warning) && in_array($warning, $allowedWarnings, true)) {
                $warnings[$warning] = $warning;
            }
        }
        $coverage = is_string($source['coverage'] ?? null) ? $source['coverage'] : '';
        $budget = is_array($source['budget'] ?? null) ? $source['budget'] : [];
        $rows[$source['source']] = [
            'source' => $source['source'],
            'coverage' => $coverageLabels[$coverage] ?? 'Coverage unavailable',
            'oldest' => $timestamp(array_key_exists('oldest_timestamp_in_window', $source)
                ? $source['oldest_timestamp_in_window'] : ($source['oldest_timestamp_seen'] ?? null)),
            'newest' => $timestamp(array_key_exists('newest_timestamp_in_window', $source)
                ? $source['newest_timestamp_in_window'] : ($source['newest_timestamp_seen'] ?? null)),
            'matched' => $count($source['matched_events'] ?? null),
            'retained' => $count($source['selected_events'] ?? null),
            'dropped' => $count($source['dropped_events'] ?? null),
            'groups' => $count($source['exported_event_groups'] ?? null),
            'candidate_limit' => $count($budget['events'] ?? null),
            'seconds_used' => $seconds($source['elapsed_seconds'] ?? null),
            'seconds_allocated' => $seconds($budget['seconds'] ?? null),
            'candidate_dropped' => $count($source['candidate_dropped_events'] ?? null),
            'allocation_dropped' => $count($source['allocation_dropped_events'] ?? null),
            'size_dropped' => $count($source['report_size_dropped_events'] ?? null),
            'drop_stages_available' => isset($source['candidate_dropped_events'],
                $source['allocation_dropped_events'], $source['report_size_dropped_events']),
            'limited' => (bool)array_intersect($limitWarnings, $warnings) ||
                $count($source['dropped_events'] ?? null) > 0,
            'warnings' => array_values($warnings),
            'warning_labels' => array_map(static function (string $warning) use ($warningLabels): string {
                return $warningLabels[$warning];
            }, array_values($warnings)),
        ];
    }
    return array_values($rows);
}
