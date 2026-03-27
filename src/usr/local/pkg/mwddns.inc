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
 * Requires: pfSense 2.7+ (PHP 8.x, FreeBSD 14.x)
 */

define('MWDDNS_CONFIG_KEY',   'mwddns');
define('MWDDNS_PROVIDER_DIR', '/usr/local/pkg/mwddns');
define('MWDDNS_CRON_CMD',     '/usr/local/bin/php /usr/local/bin/mwddns_cron.php');
define('MWDDNS_CRON_MINUTE',  '*/5');
define('MWDDNS_DNS_CACHE_TTL', 60);
define('MWDDNS_DNS_CACHE_DIR', '/var/run/mwddns');

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
 */
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
    return array_values($rules);
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
 */
function mwddns_save_rules(array $rules): void
{
    global $config;
    $config[MWDDNS_CONFIG_KEY]['rule'] = array_values($rules);
    write_config('MWDDNS: rules saved');
}

/**
 * Delete a rule by index.
 */
function mwddns_delete_rule(int $id): void
{
    $rules = mwddns_get_rules();
    if (isset($rules[$id])) {
        array_splice($rules, $id, 1);
        mwddns_save_rules($rules);
    }
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
    return ($ip && $ip !== '0.0.0.0') ? $ip : null;
}

/**
 * Return the current IPv6 address of a pfSense interface key.
 * Returns null when no address is available.
 */
function mwddns_get_interface_ipv6(string $ifname): ?string
{
    $ip = get_interface_ipv6($ifname);
    return ($ip && $ip !== '::') ? $ip : null;
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
 * Only types that are configured AND have at least one available IP are included.
 *
 * Returns: ['ok' => bool, 'message' => string, 'actions' => [...]]
 */
function mwddns_update_rule(array $rule): array
{
    $provider = $rule['provider'] ?? 'cloudflare';  // backward-compat default
    $host     = $rule['hostname'] ?? '';

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

    // Gather current IPs by record type
    $ipsByType = [];
    foreach (mwddns_rule_interfaces($rule) as $ifname) {
        if (in_array('A', $recordTypes, true)) {
            $ip4 = mwddns_get_interface_ip($ifname);
            if ($ip4 !== null) {
                $ipsByType['A'][$ip4] = true;
            }
        }
        if (in_array('AAAA', $recordTypes, true)) {
            $ip6 = mwddns_get_interface_ipv6($ifname);
            if ($ip6 !== null) {
                $ipsByType['AAAA'][$ip6] = true;
            }
        }
    }

    if (empty($ipsByType)) {
        return ['ok' => false, 'message' => 'No valid IPs found on monitored interfaces for the configured record types.', 'actions' => []];
    }

    return $fn($ipsByType, $rule);
}

/**
 * Update all rules and persist timestamps/status into config.
 */
function mwddns_update_all(): array
{
    $rules   = mwddns_get_rules();
    $results = [];

    foreach ($rules as $id => $rule) {
        $res = mwddns_update_rule($rule);
        $results[$id] = $res;

        // Store last-run metadata in the normalized rules array
        $rules[$id]['last_updated'] = date('Y-m-d H:i:s');
        $rules[$id]['last_status']  = $res['ok'] ? 'OK' : 'Error';
    }

    if (!empty($rules)) {
        mwddns_save_rules($rules);
    }

    return $results;
}

/* =========================================================
 * Cron / package lifecycle
 * ========================================================= */

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

/** Called by the pfSense package manager after installation. */
function mwddns_install(): void
{
    mwddns_install_cron();
}

/** Called by the pfSense package manager before removal. */
function mwddns_deinstall(): void
{
    mwddns_remove_cron();
}
