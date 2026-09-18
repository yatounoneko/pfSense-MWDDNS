<?php
/*
 * mwddns.inc – Multi-WAN DDNS for pfSense
 *
 * Core library: config management, interface IP lookup, DNS status helpers,
 * provider registry / dispatch, cron management.
 *
 * DNS provider implementations live in /usr/local/pkg/mwddns/<key>.php
 * Each provider file must export:
 *   mwddns_{key}_fields()    – field definitions for the edit UI
 *   mwddns_{key}_validate()  – validate provider-specific POST data
 *   mwddns_{key}_update(array $ipsByType, array $rule)
 *                            – sync A/AAAA records; $ipsByType has the shape
 *                              ['A' => ['1.2.3.4'=>true, …], 'AAAA' => ['::1'=>true, …]]
 *                              Only keys for configured/available record types are present.
 *                              Returns ['ok'=>bool, 'message'=>string, 'actions'=>[…]]
 *
 * Uses capability-based pfSense config/gateway APIs; see the compatibility report.
 */

define('MWDDNS_CONFIG_KEY',   'mwddns');
define('MWDDNS_PROVIDER_DIR', '/usr/local/pkg/mwddns');
define('MWDDNS_CRON_CMD',     '/usr/local/bin/php /usr/local/bin/mwddns_cron.php');
define('MWDDNS_CRON_MINUTE',  '*/5');
define('MWDDNS_DNS_CACHE_TTL', 60);
define('MWDDNS_OBSERVATION_TTL', 360);
define('MWDDNS_DNS_CACHE_DIR', '/var/run/mwddns');
define('MWDDNS_METADATA_FILE', MWDDNS_DNS_CACHE_DIR . '/metadata.json');
define('MWDDNS_WATCHER_RC',   '/usr/local/etc/rc.d/mwddns_watcher');
define('MWDDNS_WATCHER_RCVAR','mwddns_watcher_enable');

/**
 * Write a line to syslog with a consistent prefix.
 */
/**
 * Reload through pfSense's supported API without assigning its boolean return
 * value to $config. Older installations retain the legacy API fallback.
 */
function mwddns_reload_config(): void
{
    global $config;
    if (function_exists('config_read_file')) {
        if (!config_read_file(false, false)) {
            throw new RuntimeException('MWDDNS: pfSense configuration reload failed.');
        }
    } elseif (function_exists('parse_config')) {
        $config = parse_config(true);
    } else {
        throw new RuntimeException('MWDDNS: no supported pfSense configuration API.');
    }
    if (!is_array($config) || empty($config)) {
        throw new RuntimeException('MWDDNS: refusing to operate with an empty configuration.');
    }
}

/** Private runtime files never contain provider credentials. */
function mwddns_runtime_dir(): bool
{
    return is_dir(MWDDNS_DNS_CACHE_DIR) ||
        (@mkdir(MWDDNS_DNS_CACHE_DIR, 0700, true) || is_dir(MWDDNS_DNS_CACHE_DIR));
}

function mwddns_log(string $message, int $level = LOG_INFO): void
{
    @syslog($level, '[MWDDNS] ' . $message);
}

/* =========================================================
 * i18n helpers  (GUI only; CLI/install.sh stays English)
 * ========================================================= */

/**
 * Detect the display locale from the pfSense system language setting.
 *
 * Supported return values:
 *   'zh_CN'  – Simplified Chinese  (language starts with zh_CN / zh-CN)
 *   'zh_HK'  – Traditional Chinese, Hong Kong government terminology
 *              (language starts with zh_TW, zh_HK, zh-TW, or zh-HK)
 *   'en'     – English / unsupported → fall back to original strings
 */
function mwddns_get_locale(): string
{
    global $config;
    $lang = trim($config['system']['language'] ?? '');
    if (preg_match('/^zh[_\-]CN/i', $lang)) {
        return 'zh_CN';
    }
    if (preg_match('/^zh[_\-](TW|HK)/i', $lang)) {
        return 'zh_HK';
    }
    return 'en';
}

/**
 * Translate a GUI string for the active pfSense system language.
 *
 * Looks up $key in the package locale file for the current locale.
 * Falls back to the original English string for unsupported locales or
 * missing keys.  CLI scripts (install.sh) do NOT use this function.
 *
 * @param string $key  The English source string (used as translation key).
 * @return string      Translated string, or $key when no translation exists.
 */
function mwddns_t(string $key): string
{
    static $strings = null;
    if ($strings === null) {
        $locale = mwddns_get_locale();
        if ($locale !== 'en') {
            $file = MWDDNS_PROVIDER_DIR . '/locale/' . $locale . '.php';
            if (file_exists($file)) {
                $strings = require $file;
            }
        }
        if (!is_array($strings)) {
            $strings = [];
        }
    }
    return $strings[$key] ?? $key;
}

/**
 * Return (and lazily create) a per-session CSRF token for MWDDNS forms.
 */
function mwddns_csrf_token(): string
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        if (!headers_sent()) {
            if (!session_start()) {
                return '';
            }
        } else {
            return '';
        }
    }
    if (empty($_SESSION['mwddns_csrf_token'])) {
        $_SESSION['mwddns_csrf_token'] = bin2hex(random_bytes(32));
    }
    return (string)$_SESSION['mwddns_csrf_token'];
}

/**
 * Return a hidden input containing the MWDDNS CSRF token.
 */
function mwddns_csrf_input(): string
{
    return '<input type="hidden" name="mwddns_csrf_token" value="' .
        htmlspecialchars(mwddns_csrf_token(), ENT_QUOTES) . '">';
}

/**
 * Validate an MWDDNS CSRF token.
 */
function mwddns_csrf_validate(string $token): bool
{
    $expected = mwddns_csrf_token();
    return $token !== '' && $expected !== '' && hash_equals($expected, $token);
}

/* =========================================================
 * Provider registry
 * ========================================================= */

/**
 * Return all registered DNS providers.
 * Format: [ 'key' => ['name' => 'Display Name', 'file' => '/path/to/provider.php'], … ]
 */
function mwddns_get_providers(): array
{
    return [
        'cloudflare'  => [
            'name' => 'Cloudflare',
            'file' => MWDDNS_PROVIDER_DIR . '/cloudflare.php',
        ],
        'alidns_intl' => [
            'name' => 'Alibaba Cloud DNS (International)',
            'file' => MWDDNS_PROVIDER_DIR . '/alidns.php',
        ],
        'alidns_cn'   => [
            'name' => 'Alibaba Cloud DNS (China)',
            'file' => MWDDNS_PROVIDER_DIR . '/alidns.php',
        ],
        'aliesa'      => [
            'name' => 'Alibaba Cloud ESA',
            'file' => MWDDNS_PROVIDER_DIR . '/aliesa.php',
        ],
        'powerdns'    => [
            'name' => 'PowerDNS',
            'file' => MWDDNS_PROVIDER_DIR . '/powerdns.php',
        ],
    ];
}

/**
 * Include the provider file and return true, or return false when unavailable.
 * Safe to call multiple times (uses require_once).
 */
function mwddns_load_provider(string $key): bool
{
    $providers = mwddns_get_providers();
    if (!isset($providers[$key])) {
        return false;
    }
    $file = $providers[$key]['file'];
    if (!file_exists($file)) {
        return false;
    }
    require_once($file);
    return true;
}

/**
 * Return the display name for a provider key (falls back to the raw key).
 */
function mwddns_provider_name(string $key): string
{
    $providers = mwddns_get_providers();
    return $providers[$key]['name'] ?? $key;
}

/* =========================================================
 * Config helpers
 * ========================================================= */

/**
 * Return all MWDDNS rules as a numerically-indexed array.
 *
 * pfSense's XML→PHP parser collapses a single-item list into an
 * associative array, so we normalise that case here.
 *
 * Metadata (last_updated, last_status) is merged in from the state file so
 * that callers (UI, widget) always see up-to-date status without requiring
 * those fields to live in config.xml.
 */
/** Fingerprints survive reordering without adding IDs or secrets to backups. */
function mwddns_rule_definition(array $rule): array
{
    unset($rule['last_updated'], $rule['last_status']);
    ksort($rule);
    return $rule;
}

function mwddns_rule_key(array $rule): string
{
    return hash('sha256', json_encode(mwddns_rule_definition($rule), JSON_THROW_ON_ERROR));
}

function mwddns_rules_revision(array $rules): string
{
    return hash('sha256', json_encode(array_values(array_map('mwddns_rule_definition', $rules)), JSON_THROW_ON_ERROR));
}

/** One nonblocking lock covers rule saves, deletes and complete DNS updates. */
function mwddns_with_operation_lock(callable $operation)
{
    if (!mwddns_runtime_dir()) {
        throw new RuntimeException('Cannot create the MWDDNS runtime directory.');
    }
    $lock = @fopen(MWDDNS_DNS_CACHE_DIR . '/updates.lock', 'c');
    if ($lock === false) {
        throw new RuntimeException('Cannot open the MWDDNS operation lock.');
    }
    try {
        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            throw new RuntimeException('Another MWDDNS operation is running. Please retry later.');
        }
        return $operation();
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

/** Shared network budget: never pass zero (unlimited) to CURLOPT_TIMEOUT_MS. */
function mwddns_request_timeout_ms(): int
{
    $remaining = isset($GLOBALS['mwddns_request_deadline'])
        ? (int)floor(($GLOBALS['mwddns_request_deadline'] - microtime(true)) * 1000)
        : 30000;
    return max(0, min(30000, $remaining));
}

function mwddns_get_rules(): array
{
    global $config;
    if (empty($config[MWDDNS_CONFIG_KEY]['rule'])) {
        return [];
    }
    $rules = $config[MWDDNS_CONFIG_KEY]['rule'];
    // Normalise single-rule case
    if (isset($rules['name'])) {
        $rules = [$rules];
    }
    $rules = array_values($rules);

    // Overlay metadata from the state file (does not touch config.xml)
    $metadata = mwddns_get_metadata();
    foreach ($rules as $id => &$rule) {
        $key = mwddns_rule_key($rule);
        if (isset($metadata[$key]) && is_array($metadata[$key])) {
            $rule['last_updated'] = $metadata[$key]['last_updated'] ?? '';
            $rule['last_status'] = $metadata[$key]['last_status'] ?? '';
        }
    }
    unset($rule);

    return $rules;
}

/**
 * Return a single rule by index, or null if not found.
 */
function mwddns_get_rule(int $id): ?array
{
    $rules = mwddns_get_rules();
    return $rules[$id] ?? null;
}

/**
 * Persist the full rules array back into pfSense config.xml.
 *
 * Volatile metadata (last_updated, last_status) is stripped before writing
 * so that routine cron status updates never touch config.xml.  The function
 * is a no-op when the stripped rule definitions are identical to what is
 * already stored, preventing spurious write_config() calls that would
 * otherwise trigger the Auto Configuration Backup plugin every 5 minutes.
 *
 * A revision check and the shared operation lock prevent stale GUI writes.
 * Fingerprint-keyed metadata cannot migrate to a different rule on reindex.
 */
function mwddns_save_rules(array $rules, ?string $expectedRevision = null): void
{
    $expectedRevision = $expectedRevision ?? mwddns_rules_revision(mwddns_get_rules());
    $definitions = array_values(array_map('mwddns_rule_definition', $rules));
    mwddns_with_operation_lock(static function () use ($definitions, $expectedRevision): void {
        global $config;
        mwddns_reload_config();
        $current = mwddns_get_rules();
        if (!hash_equals(mwddns_rules_revision($current), $expectedRevision)) {
            throw new RuntimeException('Configuration changed. Reload the page before saving.');
        }
        if (mwddns_rules_revision($definitions) === mwddns_rules_revision($current)) {
            return;
        }
        $before = $config;
        try {
            $config[MWDDNS_CONFIG_KEY]['rule'] = $definitions;
            if (write_config('MWDDNS: rules saved') === false) {
                throw new RuntimeException('pfSense rejected the configuration write.');
            }
        } catch (Throwable $e) {
            $config = $before; // Never issue a DNS update using an unsaved definition.
            mwddns_log('Configuration write failed: ' . get_class($e), LOG_ERR);
            throw new RuntimeException('Configuration could not be saved. No DNS update was started.', 0, $e);
        }
        // Metadata uses definition fingerprints; reindexing cannot mislabel rules.
    });
}

function mwddns_delete_rule(int $id, ?string $expectedRevision = null): void
{
    $rules = mwddns_get_rules();
    $expectedRevision = $expectedRevision ?? mwddns_rules_revision($rules);
    if (!isset($rules[$id])) {
        throw new RuntimeException('Rule no longer exists. Reload the page.');
    }
    array_splice($rules, $id, 1);
    mwddns_save_rules($rules, $expectedRevision);
}

/* =========================================================
 * Metadata state file helpers
 *
 * last_updated and last_status are volatile per-run values that change every
 * 5 minutes.  Storing them in /var/run/mwddns/metadata.json keeps them out
 * of config.xml, preventing the Auto Configuration Backup plugin from
 * triggering a backup on every cron tick.
 * ========================================================= */

/**
 * Read the full metadata map from the state file.
 * Returns an array keyed by definition fingerprint, each entry having
 * 'last_updated' and 'last_status'.  Returns [] when no file exists.
 */
function mwddns_get_metadata(): array
{
    if (!file_exists(MWDDNS_METADATA_FILE)) {
        return [];
    }
    $raw = file_get_contents(MWDDNS_METADATA_FILE);
    if ($raw === false) {
        mwddns_log('Failed to read metadata file: ' . MWDDNS_METADATA_FILE, LOG_WARNING);
        return [];
    }
    if ($raw === '') {
        return [];
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        mwddns_log('Metadata file contains invalid JSON, ignoring: ' . MWDDNS_METADATA_FILE, LOG_WARNING);
        return [];
    }
    return $data;
}

/**
 * Write the full metadata map to the state file.
 * The directory is created automatically when missing.
 */
function mwddns_save_metadata(array $metadata): void
{
    mwddns_mutate_metadata(static fn(array $old): array => $metadata);
}

/** Serialize read/merge/write and publish JSON atomically for GUI readers. */
function mwddns_mutate_metadata(callable $mutate): void
{
    if (!mwddns_runtime_dir()) {
        mwddns_log('Cannot create metadata directory.', LOG_WARNING);
        return;
    }
    $lock = @fopen(MWDDNS_DNS_CACHE_DIR . '/metadata.lock', 'c');
    if ($lock === false) {
        mwddns_log('Cannot open metadata lock.', LOG_WARNING);
        return;
    }
    $tmp = false;
    try {
        if (!flock($lock, LOCK_EX)) {
            throw new RuntimeException('Cannot acquire metadata lock.');
        }
        $json = json_encode($mutate(mwddns_get_metadata()),
            JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
        $tmp = tempnam(MWDDNS_DNS_CACHE_DIR, '.metadata-');
        if ($tmp === false || file_put_contents($tmp, $json) === false ||
            !rename($tmp, MWDDNS_METADATA_FILE)) {
            throw new RuntimeException('Cannot publish metadata.');
        }
    } catch (Throwable $e) {
        mwddns_log('Metadata write failed: ' . $e->getMessage(), LOG_WARNING);
    } finally {
        if ($tmp !== false && file_exists($tmp)) {
            @unlink($tmp);
        }
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}


/**
 * Return the metadata entry for a single rule by its array index.
 * Returns [] when no entry exists.
 */
function mwddns_get_rule_metadata(int $id): array
{
    $rule = mwddns_get_rule($id);
    $metadata = mwddns_get_metadata();
    return $rule === null ? [] : ($metadata[mwddns_rule_key($rule)] ?? []);
}

/**
 * Legacy index adapter. Update workers persist using the captured rule instead.
 */
function mwddns_set_rule_metadata_in_file(int $id, array $data): void
{
    $rule = mwddns_get_rule($id);
    if ($rule !== null) {
        mwddns_set_metadata_for_rule($rule, $data);
    }
}

function mwddns_set_metadata_for_rule(array $rule, array $data): void
{
    $key = mwddns_rule_key($rule);
    mwddns_mutate_metadata(static function (array $metadata) use ($key, $data): array {
        $metadata[$key] = array_merge($metadata[$key] ?? [], $data);
        return $metadata;
    });
}

/* =========================================================
 * Interface helpers
 * ========================================================= */

/**
 * Return the current IPv4 address of a pfSense interface key
 * (e.g. 'wan', 'opt1').  Returns null when no address is available.
 */
function mwddns_get_interface_ip(string $ifname): ?string
{
    $ip = get_interface_ip($ifname);
    return (is_string($ip) && $ip !== '0.0.0.0' && mwddns_is_ip_of_type($ip, 'A')) ? $ip : null;
}

/**
 * Return the current IPv6 address of a pfSense interface key.
 * Returns null when no address is available.
 */
function mwddns_get_interface_ipv6(string $ifname): ?string
{
    $ip = get_interface_ipv6($ifname);
    return (is_string($ip) && $ip !== '::' && mwddns_is_ip_of_type($ip, 'AAAA')) ? $ip : null;
}

/**
 * Load gateway latency/loss thresholds from config.xml.
 * Mirrors the logic used by gateway_watcher.py (reference project).
 */
function mwddns_get_gateway_thresholds(): array
{
    global $config;
    $defaults = [
        'latencyhigh' => mwddns_threshold($config['gateways']['latencyhigh'] ?? null, 500),
        'losshigh' => mwddns_threshold($config['gateways']['losshigh'] ?? null, 20, 100),
    ];
    $thresholds = ['' => $defaults];
    $items = $config['gateways']['gateway_item'] ?? [];
    if (isset($items['name'])) {
        $items = [$items];
    }
    foreach (is_array($items) ? $items : [] as $gw) {
        if (!is_array($gw) || empty($gw['name'])) {
            continue;
        }
        $thresholds[$gw['name']] = [
            'latencyhigh' => mwddns_threshold($gw['latencyhigh'] ?? null, $defaults['latencyhigh']),
            'losshigh' => mwddns_threshold($gw['losshigh'] ?? null, $defaults['losshigh'], 100),
        ];
    }
    return $thresholds;
}

function mwddns_threshold($value, float $default, float $maximum = PHP_FLOAT_MAX): float
{
    return is_numeric($value) && is_finite((float)$value) &&
        (float)$value > 0 && (float)$value <= $maximum ? (float)$value : $default;
}

/**
 * Include runtime-generated DHCP gateways, not only gateway_item entries.
 * The first three return_gateways_array arguments are shared by old and new
 * pfSense sources. Do not call the version-dependent get_dpinger_status API.
 */
function mwddns_gateway_definitions(): array
{
    global $config;
    $items = $config['gateways']['gateway_item'] ?? [];
    if (isset($items['name'])) {
        $items = [$items];
    }
    $gateways = [];
    foreach (is_array($items) ? $items : [] as $gw) {
        if (is_array($gw) && !empty($gw['name'])) {
            $gw['friendlyiface'] = $gw['interface'] ?? '';
            $gateways[$gw['name']] = $gw;
        }
    }
    if (function_exists('return_gateways_array')) {
        $runtime = return_gateways_array(true, false, true);
        if (!is_array($runtime)) {
            throw new RuntimeException('pfSense returned invalid gateway definitions.');
        }
        foreach ($runtime as $key => $gw) {
            if (!is_array($gw)) {
                continue;
            }
            $name = $gw['name'] ?? (is_string($key) ? $key : '');
            if ($name !== '') {
                $gateways[$name] = array_replace($gateways[$name] ?? [], $gw);
            }
        }
    }
    foreach ($gateways as &$gw) {
        $gw['friendlyiface'] = $gw['friendlyiface'] ??
            mwddns_normalize_ifname($gw['interface'] ?? '');
        $gw['ipprotocol'] = $gw['ipprotocol'] ??
            (strpos((string)($gw['gateway'] ?? ''), ':') !== false ? 'inet6' : 'inet');
    }
    unset($gw);
    return $gateways;
}

function mwddns_gateway_interface_map(): array
{
    $map = [];
    foreach (mwddns_gateway_definitions() as $name => $gw) {
        $map[$name] = $gw['friendlyiface'];
    }
    return $map;
}

/** dpinger -u exposes a Unix stream socket, never a regular status file. */
function mwddns_read_dpinger_socket(string $socketPath): string
{
    if (dirname($socketPath) !== '/var/run' ||
        !preg_match('/^dpinger_[^\/\x00\r\n]+\.sock$/D', basename($socketPath))) {
        return '';
    }
    $socket = @stream_socket_client('unix://' . $socketPath, $errno, $error, 1,
        STREAM_CLIENT_CONNECT);
    if ($socket === false) {
        return '';
    }
    try {
        stream_set_timeout($socket, 2);
        $line = fgets($socket, 4096);
        $meta = stream_get_meta_data($socket);
        return is_string($line) && strlen($line) < 4095 && empty($meta['timed_out'])
            ? trim($line) : '';
    } finally {
        fclose($socket);
    }
}

/** Return [gateway identifier, online/down/unknown] for one bounded report. */
function mwddns_parse_dpinger_report(string $report, array $thresholds): ?array
{
    $parts = preg_split('/\s+/', trim($report));
    if (count($parts) !== 4 || !preg_match('/^[A-Za-z0-9_.:-]+$/D', $parts[0])) {
        return null;
    }
    foreach (array_slice($parts, 1) as $value) {
        if (!is_numeric($value) || !is_finite((float)$value) || (float)$value < 0) {
            return null;
        }
    }
    $loss = (float)$parts[3];
    if ($loss > 100) {
        return null;
    }
    $limits = $thresholds[$parts[0]] ?? $thresholds[''] ?? [];
    $latencyHigh = mwddns_threshold($limits['latencyhigh'] ?? null, 500);
    $lossHigh = mwddns_threshold($limits['losshigh'] ?? null, 20, 100);
    $status = ((float)$parts[1] / 1000 < $latencyHigh && $loss < $lossHigh)
        ? 'online' : 'down';
    return [$parts[0], $status];
}

/** Missing, malformed and timed-out reports are unknown, not offline. */
function mwddns_get_gateway_statuses(array $thresholds): array
{
    $statuses = [];
    foreach (glob('/var/run/dpinger_*.sock') ?: [] as $socketPath) {
        $fallback = explode('~', substr(basename($socketPath), 8), 2)[0];
        $fallback = preg_replace('/\.sock$/', '', $fallback);
        $parsed = mwddns_parse_dpinger_report(mwddns_read_dpinger_socket($socketPath), $thresholds);
        [$name, $status] = $parsed ?? [$fallback, 'unknown'];
        // Report identifiers also work when pfSense hashes long socket names.
        // Conflicting duplicate sockets during a restart must not trigger deletion.
        if (isset($statuses[$name]) && $statuses[$name] !== $status) {
            $statuses[$name] = 'unknown';
        } else {
            $statuses[$name] = $status;
        }
    }
    return $statuses;
}

/** Select by interface AND family, using an explicit gateway before dynamic ones. */
function mwddns_select_gateway(string $ifname, string $family, array $gateways): ?array
{
    global $config;
    $configured = $config['interfaces'][$ifname][$family === 'inet6' ? 'gatewayv6' : 'gateway'] ?? '';
    $candidates = [];
    foreach ($gateways as $name => $gw) {
        if (($gw['friendlyiface'] ?? '') !== $ifname || ($gw['ipprotocol'] ?? '') !== $family) {
            continue;
        }
        $gw['name'] = $name;
        if ($configured !== '' && $name === $configured) {
            return $gw;
        }
        $candidates[$name] = $gw;
    }
    if ($configured !== '') {
        return null;
    }
    $dynamic = array_filter($candidates, static fn($gw) => !empty($gw['dynamic']));
    if (count($dynamic) === 1) {
        return reset($dynamic);
    }
    return count($candidates) === 1 ? reset($candidates) : null;
}

/**
 * Empty type => confirmed empty desired RRset (deletion remains supported).
 * Omitted type => uncertain monitoring; preserve that whole remote RRset.
 */
function mwddns_collect_ips_for_rule(array $recordTypes, array $rule, ?array &$uncertainTypes = null): array
{
    global $config;
    $ipsByType = array_fill_keys($recordTypes, []);
    $uncertainTypes = [];
    $interfaces = mwddns_rule_interfaces($rule);
    if (empty($interfaces)) {
        foreach ($recordTypes as $type) {
            $uncertainTypes[$type][] = 'No interfaces configured';
        }
        return [];
    }
    $gateways = mwddns_gateway_definitions();
    $statuses = mwddns_get_gateway_statuses(mwddns_get_gateway_thresholds());
    foreach ($interfaces as $ifname) {
        foreach ($recordTypes as $type) {
            if (!isset($config['interfaces'][$ifname])) {
                $uncertainTypes[$type][] = $ifname . ': interface is missing';
                continue;
            }
            if (!isset($config['interfaces'][$ifname]['enable'])) {
                continue; // Explicit administrative disable is not a monitoring error.
            }
            $ip = $type === 'A' ? mwddns_get_interface_ip($ifname) : mwddns_get_interface_ipv6($ifname);
            $gw = mwddns_select_gateway($ifname, $type === 'A' ? 'inet' : 'inet6', $gateways);
            if ($gw === null) {
                if ($ip !== null) {
                    $uncertainTypes[$type][] = $ifname . ': gateway mapping is unknown';
                }
                continue; // No address of this family and no gateway: not applicable.
            }
            if (isset($gw['disabled']) || isset($gw['force_down'])) {
                continue;
            }
            $unmonitored = isset($gw['monitor_disable']);
            $state = $unmonitored ? 'online' : ($statuses[$gw['name']] ?? 'unknown');
            if ($state === 'down') {
                continue;
            }
            if ($state !== 'online') {
                $uncertainTypes[$type][] = $ifname . ': gateway monitoring is unknown';
                continue;
            }
            if ($ip !== null) {
                $ipsByType[$type][$ip] = true;
            } elseif (!$unmonitored) {
                $uncertainTypes[$type][] = $ifname . ': monitored interface address is unavailable';
            }
        }
    }
    foreach (array_keys($uncertainTypes) as $type) {
        unset($ipsByType[$type]);
    }
    return $ipsByType;
}

/**
 * Return the human-readable description of an interface key.
 */
function mwddns_get_interface_desc(string $ifname): string
{
    global $config;
    $descr = $config['interfaces'][$ifname]['descr'] ?? '';
    return $descr !== '' ? $descr : strtoupper($ifname);
}

/**
 * Normalize an interface identifier to the friendly pfSense key (wan/opt1/...).
 * Falls back to the original string when no mapping exists.
 */
function mwddns_normalize_ifname(?string $ifname): ?string
{
    if ($ifname === null) {
        return null;
    }
    $trimmed = trim($ifname);
    if ($trimmed === '') {
        return null;
    }
    if (function_exists('convert_real_interface_to_friendly_interface_name')) {
        $friendly = convert_real_interface_to_friendly_interface_name($trimmed);
        if (!empty($friendly)) {
            return $friendly;
        }
    }
    return $trimmed;
}

/**
 * Return the space-separated interface list stored in a rule as a
 * clean PHP array, discarding empty entries.
 */
function mwddns_rule_interfaces(array $rule): array
{
    if (empty($rule['interfaces'])) {
        return [];
    }
    return array_values(array_filter(explode(' ', trim($rule['interfaces']))));
}

/**
 * Return the record types configured for a rule as an array.
 * Possible values: 'A', 'AAAA'.  Defaults to ['A'] for legacy rules.
 */
function mwddns_rule_record_types(array $rule): array
{
    $raw = trim($rule['record_types'] ?? '');
    if ($raw === '') {
        return ['A'];  // backward-compatible default
    }
    $types = array_values(array_filter(explode(' ', $raw)));
    // Only allow known types
    return array_values(array_filter($types, fn($t) => in_array($t, ['A', 'AAAA'], true)));
}

/**
 * Return per-interface status for a rule.
 *
 * Each element:
 *   'ifname' => pfSense interface key
 *   'desc'   => friendly description
 *   'ipv4'   => current IPv4 (null when unavailable)
 *   'ipv6'   => current IPv6 (null when unavailable)
 */
function mwddns_get_rule_ips(array $rule): array
{
    $result = [];
    foreach (mwddns_rule_interfaces($rule) as $ifname) {
        $result[] = [
            'ifname' => $ifname,
            'desc'   => mwddns_get_interface_desc($ifname),
            'ipv4'   => mwddns_get_interface_ip($ifname),
            'ipv6'   => mwddns_get_interface_ipv6($ifname),
        ];
    }
    return $result;
}

/* =========================================================
 * DNS lookup helpers
 * ========================================================= */

/**
 * Resolve all IPv4 addresses for a hostname via DNS (A records).
 * Returns an empty array on failure.
 */
function mwddns_dns_lookup(string $hostname): array
{
    return mwddns_dns_lookup_cached($hostname, 'A');
}

/**
 * Resolve all IPv6 addresses for a hostname via DNS (AAAA records).
 * Returns an empty array on failure.
 */
function mwddns_dns_lookup_aaaa(string $hostname): array
{
    return mwddns_dns_lookup_cached($hostname, 'AAAA');
}

/**
 * Return observed DNS record IPs for status matching in UI/widget.
 *
 * By default this uses recursive DNS lookups. If a provider exposes:
 *   - mwddns_{provider}_should_use_api_match(array $rule): bool
 *   - mwddns_{provider}_list_records(array $rule, string $type): ?array
 * and should_use_api_match() returns true (e.g. proxy mode enabled),
 * then provider API results are used instead of recursive DNS.
 *
 * @param array  $rule Rule config
 * @param string $type 'A' or 'AAAA'
 * @return array       List of IPs (may be empty)
 */
/**
 * Read-only GUI path. No DNS resolution or provider requests may happen here.
 * Null explicitly means missing/stale/failed observation, not an empty RRset.
 */
function mwddns_cached_observed_ips(array $rule, string $type): ?array
{
    if (!in_array($type, ['A', 'AAAA'], true)) {
        return null;
    }
    $path = MWDDNS_DNS_CACHE_DIR . '/observed_' . mwddns_rule_key($rule) . '_' . $type . '.json';
    $raw = @file_get_contents($path);
    $data = is_string($raw) ? json_decode($raw, true) : null;
    $age = time() - (int)($data['checked_at'] ?? 0);
    if (!is_array($data) || empty($data['known']) || $age < 0 ||
        $age > MWDDNS_OBSERVATION_TTL || !is_array($data['ips'] ?? null)) {
        return null;
    }
    return array_values(array_filter($data['ips'],
        static fn($ip) => is_string($ip) && mwddns_is_ip_of_type($ip, $type)));
}

/** Called by CLI workers only; publish observations, not assumed desired IPs. */
function mwddns_refresh_observations(array $rule): void
{
    if (PHP_SAPI !== 'cli' || !mwddns_runtime_dir()) {
        return;
    }
    $provider = $rule['provider'] ?? 'cloudflare';
    if (!mwddns_load_provider($provider)) {
        return;
    }
    $useApiFn = "mwddns_{$provider}_should_use_api_match";
    $listFn = "mwddns_{$provider}_list_records";
    foreach (mwddns_rule_record_types($rule) as $type) {
        if (mwddns_request_timeout_ms() === 0) {
            break;
        }
        $ips = null;
        try {
            if (function_exists($useApiFn) && $useApiFn($rule)) {
                $ips = function_exists($listFn) ? $listFn($rule, $type) : null;
            } else {
                $records = @dns_get_record($rule['hostname'] ?? '', $type === 'A' ? DNS_A : DNS_AAAA);
                if (is_array($records)) {
                    $ips = [];
                    foreach ($records as $record) {
                        $ip = $record[$type === 'A' ? 'ip' : 'ipv6'] ?? '';
                        if (is_string($ip) && mwddns_is_ip_of_type($ip, $type)) {
                            $ips[] = $ip;
                        }
                    }
                }
            }
            $known = is_array($ips);
            $ips = $known ? array_values(array_unique(array_filter($ips,
                static fn($ip) => is_string($ip) && mwddns_is_ip_of_type($ip, $type)))) : [];
            $json = json_encode(['known' => $known, 'checked_at' => time(), 'ips' => $ips], JSON_THROW_ON_ERROR);
            $path = MWDDNS_DNS_CACHE_DIR . '/observed_' . mwddns_rule_key($rule) . '_' . $type . '.json';
            $tmp = tempnam(MWDDNS_DNS_CACHE_DIR, '.observed-');
            if ($tmp !== false) {
                try {
                    if (file_put_contents($tmp, $json) !== false) {
                        rename($tmp, $path);
                    }
                } finally {
                    if (file_exists($tmp)) {
                        @unlink($tmp);
                    }
                }
            }
        } catch (Throwable $e) {
            mwddns_log('Status observation failed: ' . get_class($e), LOG_WARNING);
        }
    }
}

function mwddns_rule_record_observed_ips(array $rule, string $type): array
{
    if (!in_array($type, ['A', 'AAAA'], true)) {
        return [];
    }

    $provider = $rule['provider'] ?? 'cloudflare';
    if (mwddns_load_provider($provider)) {
        $useApiFn = "mwddns_{$provider}_should_use_api_match";
        $listFn   = "mwddns_{$provider}_list_records";
        $useApi   = false;
        if (function_exists($useApiFn)) {
            try {
                $useApi = (bool)$useApiFn($rule);
            } catch (Throwable $e) {
                $useApi = false;
            }
        }

        if ($useApi && function_exists($listFn)) {
            try {
                $ips = $listFn($rule, $type);
            } catch (Throwable $e) {
                $ips = null;
            }
            if (is_array($ips)) {
                return array_values(array_filter(
                    $ips,
                    static fn($ip) => is_string($ip) && mwddns_is_ip_of_type($ip, $type)
                ));
            }
            // Proxy mode should rely on provider API view of records.
            // Fail closed: do not fall back to recursive DNS.
            return [];
        }
    }

    return $type === 'A'
        ? mwddns_dns_lookup($rule['hostname'] ?? '')
        : mwddns_dns_lookup_aaaa($rule['hostname'] ?? '');
}

/**
 * Validate that an IP literal matches the expected DNS record type.
 */
function mwddns_is_ip_of_type(string $ip, string $type): bool
{
    $bin = @inet_pton($ip);
    if ($bin === false) {
        return false;
    }
    return $type === 'A' ? strlen($bin) === 4 : strlen($bin) === 16;
}

/**
 * Resolve DNS A/AAAA with a short file cache to reduce UI latency.
 */
function mwddns_dns_lookup_cached(string $hostname, string $type): array
{
    $hostname = trim($hostname);
    if ($hostname === '' || !in_array($type, ['A', 'AAAA'], true)) {
        return [];
    }

    $ipFilterFlag = $type === 'A' ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6;

    $cacheDirCreated = false;
    if (!is_dir(MWDDNS_DNS_CACHE_DIR)) {
        if (!mkdir(MWDDNS_DNS_CACHE_DIR, 0700, true) && !is_dir(MWDDNS_DNS_CACHE_DIR)) {
            return mwddns_dns_lookup_uncached($hostname, $type, $ipFilterFlag);
        }
        $cacheDirCreated = true;
    }
    if ($cacheDirCreated) {
        chmod(MWDDNS_DNS_CACHE_DIR, 0700);
    }

    $cacheFile = MWDDNS_DNS_CACHE_DIR . '/dns_' . hash('sha256', strtolower($hostname) . '|' . $type) . '.json';
    $now = time();
    if (file_exists($cacheFile) && ($now - (int)filemtime($cacheFile) <= MWDDNS_DNS_CACHE_TTL)) {
        $rawCached = file_get_contents($cacheFile);
        if ($rawCached !== false) {
            $cached = json_decode($rawCached, true);
            if (is_array($cached) && ($cached['type'] ?? '') === $type && is_array($cached['ips'] ?? null)) {
                return array_values(array_filter($cached['ips'], static fn($ip) => is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP, $ipFilterFlag)));
            }
        }
    }

    $ips = mwddns_dns_lookup_uncached($hostname, $type, $ipFilterFlag);
    file_put_contents($cacheFile, json_encode(['type' => $type, 'ips' => array_values($ips)], JSON_UNESCAPED_SLASHES));
    return $ips;
}

/**
 * Resolve DNS A/AAAA records without cache.
 */
function mwddns_dns_lookup_uncached(string $hostname, string $type, int $ipFilterFlag): array
{
    $ips = [];
    $records = @dns_get_record($hostname, $type === 'A' ? DNS_A : DNS_AAAA);
    if (is_array($records)) {
        foreach ($records as $rec) {
            $ip = $type === 'A' ? ($rec['ip'] ?? '') : ($rec['ipv6'] ?? '');
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP, $ipFilterFlag)) {
                $ips[] = $ip;
            }
        }
    }
    return $ips;
}

/* =========================================================
 * Update logic  (provider-agnostic dispatcher)
 * ========================================================= */

/**
 * Persist last-run metadata for a rule into the state file.
 *
 * Also updates the in-memory $rules array so callers that use the array
 * immediately after (e.g. mwddns_edit.php) see the new values without
 * having to re-read from disk.
 */
function mwddns_set_rule_metadata(array &$rules, int $id, array $result, ?int $timestamp = null): void
{
    $ts   = $timestamp ?? time();
    $meta = [
        'last_updated' => date('Y-m-d H:i:s', $ts),
        'last_status'  => !empty($result['ok']) ? 'OK' : 'Error',
    ];

    // Persist to state file (does not touch config.xml)
    if (isset($rules[$id])) {
        mwddns_set_metadata_for_rule($rules[$id], $meta);
    }

    // Keep in-memory array in sync for callers that use it immediately
    if (isset($rules[$id])) {
        $rules[$id]['last_updated'] = $meta['last_updated'];
        $rules[$id]['last_status']  = $meta['last_status'];
    }
}

/**
 * Synchronise DNS records for one rule by dispatching to its provider.
 *
 * Algorithm:
 *   1. Determine the provider key (defaults to 'cloudflare' for legacy rules).
 *   2. Load the provider file.
 *   3. Determine configured record types (A, AAAA, or both).
 *   4. Collect current IPs by type from all monitored interfaces.
 *   5. Call mwddns_{provider}_update($ipsByType, $rule) and return its result.
 *
 * $ipsByType shape passed to providers:
 *   ['A' => ['1.2.3.4' => true, …], 'AAAA' => ['2001:db8::1' => true, …]]
 * Known-empty record types remain present so providers can remove stale records.
 * Unknown record types are omitted so providers leave their RRsets untouched.
 *
 * Returns: ['ok' => bool, 'message' => string, 'actions' => [...]]
 */
function mwddns_update_rule(array $rule): array
{
    // Release the browser session lock before any external work.
    if (PHP_SAPI !== 'cli' && session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    try {
        return mwddns_with_operation_lock(static function () use ($rule): array {
            mwddns_reload_config();
            $key = mwddns_rule_key($rule);
            $found = false;
            foreach (mwddns_get_rules() as $current) {
                if (mwddns_rule_key($current) === $key) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                return ['ok' => false, 'message' => 'Rule changed or was removed. No DNS update was started.', 'actions' => []];
            }
            $previousDeadline = $GLOBALS['mwddns_request_deadline'] ?? null;
            $GLOBALS['mwddns_request_deadline'] = microtime(true) + (PHP_SAPI === 'cli' ? 90 : 20);
            try {
                try {
                    $result = mwddns_update_rule_unlocked($rule);
                } catch (Throwable $e) {
                    mwddns_log('Update failed (' . get_class($e) . ').', LOG_ERR);
                    $result = ['ok' => false, 'message' => 'Update failed; see the MWDDNS system log.', 'actions' => []];
                }
                mwddns_set_metadata_for_rule($rule, [
                    'last_updated' => date('Y-m-d H:i:s'),
                    'last_status' => !empty($result['ok']) ? 'OK' : 'Error',
                ]);
                // CLI refreshes never delay a WebGUI request.
                mwddns_refresh_observations($rule);
                return $result;
            } finally {
                if ($previousDeadline === null) {
                    unset($GLOBALS['mwddns_request_deadline']);
                } else {
                    $GLOBALS['mwddns_request_deadline'] = $previousDeadline;
                }
            }
        });
    } catch (Throwable $e) {
        mwddns_log('MWDDNS operation refused: ' . get_class($e), LOG_WARNING);
        return ['ok' => false, 'message' => 'Update not started: configuration unavailable or another operation is running. Reload and retry.', 'actions' => []];
    }
}

function mwddns_update_rule_unlocked(array $rule): array
{
    $provider = $rule['provider'] ?? 'cloudflare';  // backward-compat default
    $host     = $rule['hostname'] ?? '';
    $ruleLabel = $rule['name'] ?? $host;

    if ($host === '') {
        return ['ok' => false, 'message' => 'Rule is missing hostname.', 'actions' => []];
    }

    if (!mwddns_load_provider($provider)) {
        return ['ok' => false, 'message' => "Provider '{$provider}' is unknown or unavailable.", 'actions' => []];
    }

    $fn = "mwddns_{$provider}_update";
    if (!function_exists($fn)) {
        return ['ok' => false, 'message' => "Provider function {$fn}() not found.", 'actions' => []];
    }

    $recordTypes = mwddns_rule_record_types($rule);
    if (empty($recordTypes)) {
        $label = $ruleLabel !== '' ? $ruleLabel : 'unknown rule';
        return ['ok' => false, 'message' => "Rule has no record types configured ({$label}).", 'actions' => []];
    }

    $uncertain = [];
    $ipsByType = mwddns_collect_ips_for_rule($recordTypes, $rule, $uncertain);
    $preserved = [];
    foreach ($uncertain as $type => $reasons) {
        $preserved[] = $type . ': ' . implode('; ', array_unique($reasons));
    }
    if (empty($ipsByType)) {
        $message = 'DNS records preserved. ' . implode(' | ', $preserved);
        mwddns_log($ruleLabel . ': ' . $message, LOG_WARNING);
        return ['ok' => false, 'message' => $message, 'actions' => []];
    }

    mwddns_log("Updating {$ruleLabel} ({$host}) via {$provider}");
    $result = $fn($ipsByType, $rule);
    if (!empty($preserved)) {
        $result['ok'] = false;
        $result['message'] = ($result['message'] ?? '') . ' Other records preserved: ' . implode(' | ', $preserved);
    }
    if (!empty($result['actions']) && is_array($result['actions'])) {
        mwddns_log_actions($result['actions'], $ruleLabel, $host);
    }
    $message = $result['message'] ?? '';
    mwddns_log("Update {$ruleLabel} ({$host}) " . (!empty($result['ok']) ? 'OK' : 'FAIL') . ($message !== '' ? ": {$message}" : ''),
        !empty($result['ok']) ? LOG_INFO : LOG_ERR);
    return $result;
}

/**
 * Update all rules (or only those monitoring a specific interface) and persist
 * timestamps/status into the metadata state file.
 *
 * config.xml is NOT modified here; metadata is written to
 * /var/run/mwddns/metadata.json so that the Auto Configuration Backup plugin
 * is not triggered on every cron tick.
 */
function mwddns_update_all(?string $onlyInterface = null): array
{
    $rules               = mwddns_get_rules();
    $results             = [];
    $normalizedInterface = mwddns_normalize_ifname($onlyInterface);

    foreach ($rules as $id => $rule) {
        if ($normalizedInterface !== null) {
            $ruleInterfaces = mwddns_rule_interfaces($rule);
            if (!in_array($normalizedInterface, $ruleInterfaces, true)) {
                continue;
            }
        }

        $res          = mwddns_update_rule($rule);
        $results[$id] = $res;

        // Metadata is persisted by update_rule while holding the same operation lock.
    }

    return $results;
}

/**
 * Emit syslog lines for each provider action.
 */
function mwddns_log_actions(array $actions, string $ruleLabel, string $hostname = ''): void
{
    foreach ($actions as $action) {
        $verb = $action['action'] ?? 'action';
        $ip   = $action['ip'] ?? '';
        $type = $action['type'] ?? '';
        $ok   = !empty($action['ok']);
        $err  = trim($action['error'] ?? '');

        $parts = [];
        if ($type !== '') {
            $parts[] = $type;
        }
        if ($ip !== '') {
            $parts[] = $ip;
        }
        if ($hostname !== '') {
            $parts[] = "for {$hostname}";
        }

        $msg = "{$ruleLabel}: {$verb}";
        if (!empty($parts)) {
            $msg .= ' ' . implode(' ', $parts);
        }
        if ($err !== '') {
            $msg .= " – {$err}";
        }

        mwddns_log($msg, $ok ? LOG_INFO : LOG_ERR);
    }
}

/* =========================================================
 * Cron / package lifecycle
 * ========================================================= */

/**
 * Validate the watcher rcvar name to avoid shell injection.
 */
function mwddns_valid_watcher_rcvar(): bool
{
    return preg_match('/^[A-Za-z0-9_]+$/', MWDDNS_WATCHER_RCVAR) === 1;
}

/**
 * Set the watcher rcvar to a given value (YES/NO).
 */
function mwddns_set_watcher_rcvar(string $value): void
{
    if (!mwddns_valid_watcher_rcvar()) {
        throw new RuntimeException('Invalid watcher rcvar name.');
    }
    $rcvarCmd = '/usr/sbin/sysrc -q ' . escapeshellarg(MWDDNS_WATCHER_RCVAR) . '=' . escapeshellarg($value);
    if (mwexec($rcvarCmd) !== 0) {
        throw new RuntimeException('Failed to set watcher rcvar.');
    }
}

/**
 * Install (or refresh) the periodic cron job.
 */
function mwddns_install_cron(): void
{
    install_cron_job(MWDDNS_CRON_CMD, true, MWDDNS_CRON_MINUTE, '*', '*', '*', '*', 'root');
}

/**
 * Remove the cron job.
 */
function mwddns_remove_cron(): void
{
    install_cron_job(MWDDNS_CRON_CMD, false);
}

/**
 * Enable and restart the gateway watcher service if present.
 */
function mwddns_enable_watcher(): void
{
    if (!file_exists(MWDDNS_WATCHER_RC)) {
        throw new RuntimeException('Gateway watcher rc script is missing.');
    }
    // Report service failures instead of claiming successful installation.
    $rcdCmd   = MWDDNS_WATCHER_RC . ' restart';
    mwddns_set_watcher_rcvar('YES');
    if (mwexec($rcdCmd) !== 0) {
        throw new RuntimeException('Gateway watcher restart failed.');
    }
}

/**
 * Stop and disable the gateway watcher service if present.
 */
function mwddns_disable_watcher(): void
{
    if (!file_exists(MWDDNS_WATCHER_RC)) {
        return;
    }
    mwddns_set_watcher_rcvar('NO');
    // An already stopped service is not an uninstall failure.
    if (mwexec(MWDDNS_WATCHER_RC . ' onestatus >/dev/null 2>&1') === 0 &&
        mwexec(MWDDNS_WATCHER_RC . ' onestop') !== 0) {
        throw new RuntimeException('Gateway watcher stop failed; files were not removed.');
    }
}

/** Called by the pfSense package manager after installation. */
function mwddns_install(): void
{
    mwddns_install_cron();
    mwddns_enable_watcher();
}

/** Called by the pfSense package manager before removal. */
function mwddns_deinstall(): void
{
    mwddns_remove_cron();
    mwddns_disable_watcher();
}
