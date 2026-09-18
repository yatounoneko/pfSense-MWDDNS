<?php
/*
 * mwddns/powerdns.php  –  PowerDNS provider for MWDDNS
 *
 * Placed at: /usr/local/pkg/mwddns/powerdns.php
 *
 * Supports provider key:  powerdns
 *
 * Authentication: X-API-Key header (PowerDNS HTTP API built-in auth).
 * API version:    /api/v1
 * Protocol:       REST – PATCH on /zones/<zone_id> with RRset replacement.
 *                 A single PATCH replaces the entire RRset for a name+type,
 *                 so we never need to know individual record IDs.
 *
 * Provider contract:
 *   mwddns_powerdns_fields()
 *   mwddns_powerdns_validate()
 *   mwddns_powerdns_update()
 */

/* =========================================================
 * Provider contract
 * ========================================================= */

function mwddns_powerdns_fields(): array
{
    return [
        [
            'key'         => 'pdns_url',
            'label'       => mwddns_t('API Server URL'),
            'type'        => 'text',
            'required'    => true,
            'placeholder' => 'https://dns.example.com',
            'help'        => mwddns_t('Base URL of the PowerDNS HTTP API, without a trailing slash. Include the port if non-standard (default 8081 for authoritative server).'),
        ],
        [
            'key'         => 'pdns_scheme',
            'label'       => mwddns_t('Connection protocol'),
            'type'        => 'select',
            'required'    => true,
            'options'     => ['https' => 'HTTPS', 'http' => 'HTTP'],
            'help'        => mwddns_t('Choose HTTP or HTTPS. HTTP sends the API key and DNS changes without encryption; use a trusted protected connection. HTTPS verifies the server certificate.'),
        ],
        [
            'key'         => 'pdns_api_key',
            'label'       => mwddns_t('API Key'),
            'type'        => 'password',
            'required'    => true,
            'placeholder' => mwddns_t('PowerDNS API key'),
            'help'        => mwddns_t('Set via api-key= in pdns.conf. Sent as the X-API-Key HTTP header. Stored in plain text in pfSense config.xml.'),
        ],
        [
            'key'         => 'pdns_server_id',
            'label'       => mwddns_t('Server ID'),
            'type'        => 'text',
            'required'    => false,
            'placeholder' => 'localhost',
            'help'        => mwddns_t('PowerDNS server identifier (almost always "localhost"). Leave blank to use the default.'),
        ],
        [
            'key'         => 'pdns_zone',
            'label'       => mwddns_t('Zone Name'),
            'type'        => 'text',
            'required'    => true,
            'placeholder' => mwddns_t('e.g. example.com'),
            'help'        => mwddns_t('The authoritative zone name in PowerDNS that contains the hostname to update. Do not include a trailing dot.'),
        ],
    ];
}

function mwddns_pdns_remote_http(string $url): bool
{
    $parts = parse_url($url);
    if (!is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'http') {
        return false;
    }
    $host = strtolower(trim($parts['host'] ?? '', '[]'));
    $loopback = in_array($host, ['localhost', '::1'], true) ||
        (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) &&
            strncmp($host, '127.', 4) === 0);
    return !$loopback;
}

/** Legacy rules derive the scheme from their URL without rewriting config.xml. */
function mwddns_pdns_normalize_transport(array $rule): array
{
    if (isset($rule['pdns_scheme']) && in_array($rule['pdns_scheme'], ['http', 'https'], true)) {
        $url = trim($rule['pdns_url'] ?? '');
        if ($url !== '') {
            $rule['pdns_url'] = $rule['pdns_scheme'] . '://' .
                preg_replace('#^[a-z][a-z0-9+.-]*://#i', '', $url);
        }
    }
    return $rule;
}

/** The administrator chooses HTTP/HTTPS; neither permits unsafe URL/header syntax. */
function mwddns_pdns_transport_error(array $rule): string
{
    if (isset($rule['pdns_scheme']) && !in_array($rule['pdns_scheme'], ['http', 'https'], true)) {
        return 'Choose HTTP or HTTPS.';
    }
    $rule = mwddns_pdns_normalize_transport($rule);
    $url = trim($rule['pdns_url'] ?? '');
    $parts = parse_url($url);
    if (!is_array($parts) || empty($parts['host']) ||
        !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true) ||
        isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) ||
        isset($parts['fragment']) || preg_match('/[\x00-\x20\x7f]/', $url)) {
        return 'PowerDNS URL must be an HTTP(S) base URL without credentials, query or fragment.';
    }
    if (preg_match('/[\x00-\x1f\x7f]/', $rule['pdns_api_key'] ?? '')) {
        return 'PowerDNS API key must not contain control characters.';
    }
    return '';
}

function mwddns_powerdns_validate(array $post, array &$errors): bool
{
    $transportError = mwddns_pdns_transport_error($post);
    if ($transportError !== '') {
        $errors[] = mwddns_t($transportError);
    }
    if (trim($post['pdns_api_key'] ?? '') === '') {
        $errors[] = mwddns_t('PowerDNS API Key is required.');
    }
    if (!preg_match('/^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/', trim($post['pdns_zone'] ?? ''))) {
        $errors[] = mwddns_t('PowerDNS Zone Name must be a valid domain name (e.g. example.com).');
    }
    return empty($errors);
}

/**
 * Synchronise PowerDNS A and/or AAAA records via RRset PATCH.
 *
 * $ipsByType  – ['A' => ['1.2.3.4'=>true, …], 'AAAA' => ['::1'=>true, …]]
 * $rule       – saved rule array from config.xml
 *
 * Returns: ['ok' => bool, 'message' => string, 'actions' => [...]]
 */
function mwddns_powerdns_update(array $ipsByType, array $rule): array
{
    $rule = mwddns_pdns_normalize_transport($rule);
    $baseUrl  = rtrim(trim($rule['pdns_url']      ?? ''), '/');
    $apiKey   = trim($rule['pdns_api_key']   ?? '');
    $serverId = trim($rule['pdns_server_id'] ?? '') ?: 'localhost';
    $zone     = trim($rule['pdns_zone']      ?? '');
    $hostname = trim($rule['hostname']       ?? '');
    $ttl      = max(1, (int)($rule['ttl']    ?? 300));

    if ($baseUrl === '' || $apiKey === '' || $zone === '') {
        return ['ok' => false, 'message' => 'PowerDNS URL, API key, or zone is missing.', 'actions' => []];
    }

    $transportError = mwddns_pdns_transport_error($rule);
    if ($transportError !== '') {
        return ['ok' => false, 'message' => $transportError, 'actions' => []];
    }
    if (mwddns_pdns_remote_http($baseUrl)) {
        mwddns_log('PowerDNS HTTP selected: API key and DNS changes are not encrypted. Use HTTPS or a protected connection.', LOG_WARNING);
    }

    // PowerDNS zone IDs use a trailing dot
    $zoneId   = rtrim($zone, '.') . '.';
    $fqdn     = rtrim($hostname, '.') . '.';  // record name must have trailing dot

    $rrsets   = [];
    $actions  = [];
    $anyError = false;

    foreach ($ipsByType as $type => $currentIPs) {
        // Build the records array: all current IPs become the new RRset content
        $records = [];
        foreach (array_keys($currentIPs) as $ip) {
            $records[] = ['content' => $ip, 'disabled' => false];
            $actions[] = ['action' => 'upserted', 'ip' => $ip, 'type' => $type, 'ok' => true, 'error' => ''];
        }

        $rrsets[] = [
            'name'       => $fqdn,
            'type'       => $type,
            'ttl'        => $ttl,
            'changetype' => 'REPLACE',
            'records'    => $records,
        ];
    }

    if (empty($rrsets)) {
        return ['ok' => false, 'message' => 'No RRsets to update.', 'actions' => []];
    }

    $url = $baseUrl . '/api/v1/servers/' . rawurlencode($serverId) . '/zones/' . rawurlencode($zoneId);
    $res = mwddns_pdns_request('PATCH', $url, $apiKey, ['rrsets' => $rrsets]);

    if (!$res['ok']) {
        // Mark all pre-logged actions as failed
        foreach ($actions as &$a) {
            $a['ok']    = false;
            $a['error'] = $res['error'];
        }
        unset($a);
        $anyError = true;
    }

    return [
        'ok'      => !$anyError,
        'message' => $anyError ? 'PowerDNS API call failed: ' . $res['error'] : 'Records updated successfully.',
        'actions' => $actions,
    ];
}

/* =========================================================
 * Internal PowerDNS HTTP API helpers
 * ========================================================= */

/**
 * Execute a PowerDNS REST API request.
 * Returns: ['ok' => bool, 'http' => int, 'data' => array, 'error' => string]
 */
function mwddns_pdns_request(string $method, string $url, string $apiKey, ?array $body = null): array
{
    $headers = [
        'X-API-Key: ' . $apiKey,
        'Content-Type: application/json',
        'Accept: application/json',
    ];

    $timeoutMs = mwddns_request_timeout_ms();
    if ($timeoutMs <= 0) {
        return ['ok' => false, 'http' => 0, 'data' => [], 'error' => 'MWDDNS request deadline exceeded.'];
    }
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_TIMEOUT_MS     => $timeoutMs,
        CURLOPT_CONNECTTIMEOUT_MS => min(5000, $timeoutMs),
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_CUSTOMREQUEST  => strtoupper($method),
    ]);

    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    }

    $raw  = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    unset($ch); // PHP 8 uses CurlHandle objects; curl_close is deprecated in 8.5.

    if ($err) {
        return ['ok' => false, 'http' => 0, 'data' => [], 'error' => $err];
    }

    // PowerDNS returns 204 No Content on a successful PATCH
    $ok   = ($http >= 200 && $http < 300);
    $data = ($raw !== '' && $raw !== false) ? (json_decode($raw, true) ?? []) : [];

    return [
        'ok'    => $ok,
        'http'  => $http,
        'data'  => $data,
        'error' => $ok ? '' : ($data['error'] ?? "HTTP $http"),
    ];
}
