<?php
/*
 * Debug jobs are separate from DNS updates. Only sanitized reports are saved.
 * This include never starts a job merely because a page was opened.
 */
define('MWDDNS_DEBUG_DIR', MWDDNS_DNS_CACHE_DIR . '/debug');
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
            if (write_config('MWDDNS: debug collection settings saved') === false) {
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

function mwddns_debug_directory(): void
{
    if (is_link(MWDDNS_DNS_CACHE_DIR) || !mwddns_runtime_dir() ||
        is_link(MWDDNS_DEBUG_DIR) ||
        (!is_dir(MWDDNS_DEBUG_DIR) && !@mkdir(MWDDNS_DEBUG_DIR, 0700))) {
        throw new RuntimeException('Debug storage is unavailable.');
    }
    @chmod(MWDDNS_DEBUG_DIR, 0700);
}

function mwddns_debug_path(string $id): string
{
    if (!preg_match('/^[a-f0-9]{32}$/D', $id)) {
        throw new RuntimeException('Invalid debug report.');
    }
    $path = MWDDNS_DEBUG_DIR . '/job-' . $id;
    if (is_link($path)) {
        throw new RuntimeException('Invalid debug report.');
    }
    return $path;
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

function mwddns_debug_status(string $id): array
{
    $status = mwddns_debug_json(mwddns_debug_path($id) . '/status.json');
    $state = $status['state'] ?? 'missing';
    if (!in_array($state, ['queued', 'running', 'complete', 'failed'], true)) {
        $state = 'missing';
    }
    $started = (int)($status['started'] ?? 0);
    if ($started > 0 && time() - $started >= 86400) {
        $state = 'expired';
    } elseif (in_array($state, ['queued', 'running'], true) && time() - $started > 120) {
        $state = 'failed';
    }
    return ['state' => $state, 'started' => $started,
        'partial' => is_bool($status['partial'] ?? null) ? $status['partial'] : null];
}

function mwddns_debug_remove(string $id): void
{
    $path = mwddns_debug_path($id);
    if (in_array(mwddns_debug_status($id)['state'], ['queued', 'running'], true)) {
        throw new RuntimeException('Debug collection is already running.');
    }
    foreach (['request.json', 'status.json', 'report.json',
        'request.json.tmp', 'status.json.tmp', 'report.json.tmp'] as $name) {
        if (is_file($path . '/' . $name) || is_link($path . '/' . $name)) {
            @unlink($path . '/' . $name);
        }
    }
    @rmdir($path);
}

function mwddns_debug_start(array $settings): string
{
    mwddns_debug_directory();
    if (!is_executable('/usr/local/bin/python3.11') || !is_executable('/usr/sbin/daemon')) {
        throw new RuntimeException('Debug collector could not be started.');
    }
    $lock = @fopen(MWDDNS_DEBUG_DIR . '/admission.lock', 'c');
    if ($lock === false) {
        throw new RuntimeException('Debug storage is unavailable.');
    }
    try {
        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            throw new RuntimeException('Debug collection is already running.');
        }
        $old = [];
        foreach (glob(MWDDNS_DEBUG_DIR . '/job-*') ?: [] as $path) {
            $id = substr(basename($path), 4);
            if (!preg_match('/^[a-f0-9]{32}$/D', $id) || is_link($path)) {
                continue;
            }
            $status = mwddns_debug_status($id);
            if (in_array($status['state'], ['queued', 'running'], true)) {
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
            mwddns_debug_write($path . '/status.json', ['state' => 'failed', 'started' => $started]);
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
        $rows[$source['source']] = [
            'source' => $source['source'],
            'coverage' => $coverageLabels[$coverage] ?? 'Coverage unavailable',
            'oldest' => $timestamp($source['oldest_timestamp_seen'] ?? null),
            'newest' => $timestamp($source['newest_timestamp_seen'] ?? null),
            'matched' => $count($source['matched_events'] ?? null),
            'retained' => $count($source['selected_events'] ?? null),
            'dropped' => $count($source['dropped_events'] ?? null),
            'groups' => $count($source['exported_event_groups'] ?? null),
            'limited' => (bool)array_intersect($limitWarnings, $warnings) ||
                $count($source['dropped_events'] ?? null) > 0,
            'warnings' => array_values($warnings),
        ];
    }
    return array_values($rows);
}
