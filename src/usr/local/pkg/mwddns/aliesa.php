<?php
/*
 * mwddns/aliesa.php  –  Alibaba Cloud ESA (Edge Security Acceleration) provider
 *
 * Placed at: /usr/local/pkg/mwddns/aliesa.php
 *
 * Supports provider key:  aliesa
 *
 * API product:    ESA 2024-09-10, RPC style: path "/", operation in x-acs-action,
 *                 every parameter in the query string, empty request body.
 * Authentication: Alibaba Cloud OpenAPI V3 signature (ACS3-HMAC-SHA256).
 * Endpoints:      esa.cn-hangzhou.aliyuncs.com, esa.ap-southeast-1.aliyuncs.com
 *
 * ESA keeps IPv4 and IPv6 addresses together. One "A/AAAA" record holds a
 * comma-separated address list and must contain at least one IPv4 address,
 * so MWDDNS maintains a single A/AAAA record per hostname.
 *
 * Provider contract:
 *   mwddns_aliesa_fields()
 *   mwddns_aliesa_validate()
 *   mwddns_aliesa_update()
 */

define('MWDDNS_ESA_API_VERSION',    '2024-09-10');
define('MWDDNS_ESA_RECORD_TYPE',    'A/AAAA');
define('MWDDNS_ESA_DEFAULT_REGION', 'cn-hangzhou');
define('MWDDNS_ESA_PAGE_SIZE',      500);  // ListRecords maximum
define('MWDDNS_ESA_MAX_PAGES',      10);

/** Public ESA OpenAPI endpoints, keyed by region ID. */
function mwddns_aliesa_endpoints(): array
{
    return [
        'cn-hangzhou'    => 'esa.cn-hangzhou.aliyuncs.com',
        'ap-southeast-1' => 'esa.ap-southeast-1.aliyuncs.com',
    ];
}

/* =========================================================
 * Provider contract
 * ========================================================= */

function mwddns_aliesa_fields(): array
{
    return [
        [
            'key'         => 'access_key_id',
            'label'       => 'AccessKey ID',
            'type'        => 'text',
            'required'    => true,
            'placeholder' => mwddns_t('Alibaba Cloud AccessKey ID'),
            'help'        => mwddns_t('Found in Alibaba Cloud Console → AccessKey Management. Use a RAM sub-account with ESA DNS permissions only.'),
        ],
        [
            'key'         => 'access_key_secret',
            'label'       => 'AccessKey Secret',
            'type'        => 'password',
            'required'    => true,
            'placeholder' => mwddns_t('Alibaba Cloud AccessKey Secret'),
            'help'        => mwddns_t('Keep secret. Stored in plain text in pfSense config.xml.'),
        ],
        [
            'key'         => 'esa_site_id',
            'label'       => mwddns_t('ESA Site ID'),
            'type'        => 'text',
            'required'    => true,
            'placeholder' => mwddns_t('e.g. 123456789'),
            'help'        => mwddns_t('Numeric Site ID from Alibaba Cloud ESA Console → Sites → (select site) → Site ID.'),
        ],
        [
            'key'         => 'esa_region',
            'label'       => mwddns_t('ESA API endpoint'),
            'type'        => 'select',
            'required'    => true,
            'options'     => [
                'cn-hangzhou'    => mwddns_t('Hangzhou') . ' (esa.cn-hangzhou.aliyuncs.com)',
                'ap-southeast-1' => mwddns_t('Singapore') . ' (esa.ap-southeast-1.aliyuncs.com)',
            ],
            'help'        => mwddns_t('ESA OpenAPI endpoint. If the site cannot be found through one endpoint, try the other.'),
        ],
    ];
}

function mwddns_aliesa_validate(array $post, array &$errors): bool
{
    if (trim($post['access_key_id'] ?? '') === '') {
        $errors[] = mwddns_t('Alibaba Cloud AccessKey ID is required.');
    }
    if (trim($post['access_key_secret'] ?? '') === '') {
        $errors[] = mwddns_t('Alibaba Cloud AccessKey Secret is required.');
    }
    if (!preg_match('/^\d+$/', trim($post['esa_site_id'] ?? ''))) {
        $errors[] = mwddns_t('ESA Site ID must be a numeric value.');
    }
    $region = trim($post['esa_region'] ?? '');
    if ($region !== '' && !isset(mwddns_aliesa_endpoints()[$region])) {
        $errors[] = mwddns_t('Select a valid ESA API endpoint.');
    }
    return empty($errors);
}

function mwddns_aliesa_update(array $ipsByType, array $rule): array
{
    $akId   = trim($rule['access_key_id']     ?? '');
    $akSec  = trim($rule['access_key_secret'] ?? '');
    $siteId = trim($rule['esa_site_id']       ?? '');
    $host   = rtrim(strtolower(trim($rule['hostname'] ?? '')), '.');
    $ttl    = max(1, (int)($rule['ttl'] ?? 300));
    $types  = array_keys($ipsByType);

    if ($akId === '' || $akSec === '' || !preg_match('/^\d+$/', $siteId) || $host === '') {
        return ['ok' => false, 'message' => 'Alibaba Cloud ESA credentials, site ID or hostname are missing.', 'actions' => []];
    }
    $endpoint = mwddns_aliesa_endpoint($rule);
    if ($endpoint === null) {
        return ['ok' => false, 'message' => 'Alibaba Cloud ESA endpoint is not valid.', 'actions' => []];
    }
    $api = ['id' => $akId, 'secret' => $akSec, 'host' => $endpoint];

    $fail = static function (string $error, string $action = 'error') use ($types): array {
        $actions = [];
        foreach ($types as $type) {
            $actions[] = ['action' => $action, 'ip' => '', 'type' => $type, 'ok' => false, 'error' => $error];
        }
        return ['ok' => false, 'message' => $error, 'actions' => $actions];
    };

    $records = mwddns_aliesa_fetch_records($api, $siteId, $host);
    if ($records === null) {
        return $fail('Failed to fetch A/AAAA records from Alibaba Cloud ESA.');
    }

    // Existing addresses per family, across every A/AAAA record for the name.
    $existing = ['A' => [], 'AAAA' => []];
    foreach ($records as $rec) {
        $ips = mwddns_aliesa_split_value($rec['Data']['Value'] ?? null);
        if ($ips === null) {
            return $fail('An existing ESA A/AAAA record holds a value that is not an IP address list; records left unchanged.', 'preserved');
        }
        foreach ($ips as $ip) {
            $existing[mwddns_aliesa_family($ip)][$ip] = true;
        }
    }

    // Monitored families take the current WAN addresses. A family that is not
    // in $ipsByType is uncertain this cycle and keeps its existing addresses.
    $desired = [];
    foreach (['A', 'AAAA'] as $type) {
        $desired[$type] = [];
        if (!array_key_exists($type, $ipsByType)) {
            $desired[$type] = $existing[$type];
            continue;
        }
        foreach (array_keys($ipsByType[$type]) as $ip) {
            $ip = mwddns_aliesa_normalize_ip((string)$ip);
            if ($ip !== null && mwddns_aliesa_family($ip) === $type) {
                $desired[$type][$ip] = true;
            }
        }
    }

    $actions = [];
    $report = static function (bool $ok, string $error) use (&$actions, $ipsByType, $existing, $desired): void {
        foreach (['A', 'AAAA'] as $type) {
            if (!array_key_exists($type, $ipsByType)) {
                continue;
            }
            foreach (array_keys($desired[$type]) as $ip) {
                $verb = isset($existing[$type][$ip]) ? 'updated' : 'created';
                $actions[] = ['action' => $verb, 'ip' => $ip, 'type' => $type, 'ok' => $ok, 'error' => $error];
            }
            foreach (array_keys(array_diff_key($existing[$type], $desired[$type])) as $ip) {
                $actions[] = ['action' => 'deleted', 'ip' => $ip, 'type' => $type, 'ok' => $ok, 'error' => $error];
            }
        }
    };

    if (empty($desired['A']) && empty($desired['AAAA'])) {
        // Every address is gone: remove the A/AAAA records for this name.
        $allOK = true;
        $error = '';
        foreach ($records as $rec) {
            $res = mwddns_aliesa_call($api, 'POST', 'DeleteRecord', ['RecordId' => (string)($rec['RecordId'] ?? '')]);
            if (!$res['ok']) {
                $allOK = false;
                $error = $error !== '' ? $error : $res['error'];
            }
        }
        $report($allOK, $error);
        return mwddns_aliesa_result($allOK, $actions);
    }
    if (empty($desired['A'])) {
        $noV4 = 'Alibaba Cloud ESA requires at least one IPv4 address in an A/AAAA record, so IPv6 cannot be published alone.';
        // Deleting the record would also remove any IPv6 addresses in it, so
        // only do so when IPv4 is known to be gone and no uncertain IPv6 is held.
        if (!array_key_exists('A', $ipsByType) ||
            (!array_key_exists('AAAA', $ipsByType) && !empty($existing['AAAA']))) {
            return $fail($noV4 . ' Records left unchanged.', 'preserved');
        }
        // IPv4 is known to be gone. Remove the stale addresses as other
        // providers do, and report the IPv6 addresses as unpublished.
        $allOK = true;
        $error = '';
        foreach ($records as $rec) {
            $res = mwddns_aliesa_call($api, 'POST', 'DeleteRecord', ['RecordId' => (string)($rec['RecordId'] ?? '')]);
            if (!$res['ok']) {
                $allOK = false;
                $error = $error !== '' ? $error : $res['error'];
            }
        }
        foreach (['A', 'AAAA'] as $type) {
            foreach (array_keys($existing[$type]) as $ip) {
                $actions[] = ['action' => 'deleted', 'ip' => $ip, 'type' => $type, 'ok' => $allOK, 'error' => $error];
            }
        }
        foreach (array_keys($desired['AAAA']) as $ip) {
            $actions[] = ['action' => 'error', 'ip' => $ip, 'type' => 'AAAA', 'ok' => false, 'error' => $noV4];
        }
        return ['ok' => false, 'message' => $noV4, 'actions' => $actions];
    }

    $value = implode(',', array_merge(array_keys($desired['A']), array_keys($desired['AAAA'])));
    $data  = json_encode(['Value' => $value], JSON_UNESCAPED_SLASHES);

    if (empty($records)) {
        $res = mwddns_aliesa_call($api, 'POST', 'CreateRecord', [
            'SiteId'     => $siteId,
            'RecordName' => $host,
            'Type'       => MWDDNS_ESA_RECORD_TYPE,
            'Data'       => $data,
            'Ttl'        => $ttl,
            'Proxied'    => 'false',
        ]);
        $report($res['ok'], $res['error']);
        return mwddns_aliesa_result($res['ok'], $actions);
    }

    // Keep the first record and fold any additional A/AAAA records into it.
    $primary = array_shift($records);
    $params  = [
        'RecordId' => (string)($primary['RecordId'] ?? ''),
        'Type'     => MWDDNS_ESA_RECORD_TYPE,
        'Data'     => $data,
        'Ttl'      => $ttl,
    ];
    // Preserve acceleration settings made in the ESA console.
    if (is_bool($primary['Proxied'] ?? null)) {
        $params['Proxied'] = $primary['Proxied'] ? 'true' : 'false';
    }
    if (is_string($primary['BizName'] ?? null) && $primary['BizName'] !== '') {
        $params['BizName'] = $primary['BizName'];
    }
    $current = mwddns_aliesa_split_value($primary['Data']['Value'] ?? null) ?? [];
    $same = empty($records) && (int)($primary['Ttl'] ?? 0) === $ttl &&
        mwddns_aliesa_same_set($current, explode(',', $value));
    $res = $same ? ['ok' => true, 'error' => ''] : mwddns_aliesa_call($api, 'POST', 'UpdateRecord', $params);
    if (!$res['ok']) {
        // Leave any other records in place so no address disappears.
        $report(false, $res['error']);
        return mwddns_aliesa_result(false, $actions);
    }
    $allOK = true;
    $error = '';
    foreach ($records as $rec) {
        $del = mwddns_aliesa_call($api, 'POST', 'DeleteRecord', ['RecordId' => (string)($rec['RecordId'] ?? '')]);
        if (!$del['ok']) {
            $allOK = false;
            $error = $error !== '' ? $error : $del['error'];
        }
    }
    $report($allOK, $allOK ? '' : 'Record updated, but a duplicate A/AAAA record could not be deleted: ' . $error);
    return mwddns_aliesa_result($allOK, $actions);
}

/* =========================================================
 * Record helpers
 * ========================================================= */

function mwddns_aliesa_result(bool $ok, array $actions): array
{
    return [
        'ok'      => $ok,
        'message' => $ok ? 'Records updated successfully.' : 'One or more Alibaba Cloud ESA API calls failed.',
        'actions' => $actions,
    ];
}

/** The endpoint host for a rule; rules saved before the field existed use Hangzhou. */
function mwddns_aliesa_endpoint(array $rule): ?string
{
    $region = trim($rule['esa_region'] ?? '');
    return mwddns_aliesa_endpoints()[$region === '' ? MWDDNS_ESA_DEFAULT_REGION : $region] ?? null;
}

/** 'A' for IPv4, 'AAAA' for IPv6. Callers pass validated addresses only. */
function mwddns_aliesa_family(string $ip): string
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? 'A' : 'AAAA';
}

/**
 * Split an A/AAAA record value ("1.2.3.4,2001:db8::1") into addresses.
 * Returns null if any entry is not an IP address, so it is never rewritten.
 */
function mwddns_aliesa_split_value($value): ?array
{
    if (!is_string($value) || trim($value) === '') {
        return null;
    }
    $ips = [];
    foreach (explode(',', $value) as $part) {
        $ip = mwddns_aliesa_normalize_ip(trim($part));
        if ($ip === null) {
            return null;
        }
        $ips[] = $ip;
    }
    return $ips;
}

/** Canonical text form of an IP address, so "2001:DB8::1" equals "2001:db8::1". */
function mwddns_aliesa_normalize_ip(string $ip): ?string
{
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return null;
    }
    $packed = inet_pton($ip);
    return $packed === false ? null : inet_ntop($packed);
}

function mwddns_aliesa_same_set(array $a, array $b): bool
{
    $a = array_unique($a);
    $b = array_unique($b);
    sort($a);
    sort($b);
    return $a === $b;
}

/**
 * List every A/AAAA record whose name is exactly $host.
 * Returns the records, or null if any page fails or the listing is incomplete.
 */
function mwddns_aliesa_fetch_records(array $api, string $siteId, string $host): ?array
{
    $records = [];
    $seen    = 0;
    for ($page = 1; $page <= MWDDNS_ESA_MAX_PAGES; $page++) {
        $res = mwddns_aliesa_call($api, 'GET', 'ListRecords', [
            'SiteId'          => $siteId,
            'RecordName'      => $host,
            'RecordMatchType' => 'exact',
            'PageNumber'      => $page,
            'PageSize'        => MWDDNS_ESA_PAGE_SIZE,
        ]);
        if (!$res['ok']) {
            return null;
        }
        $batch = $res['data']['Records'] ?? [];
        $total = $res['data']['TotalCount'] ?? null;
        if (!is_array($batch) || !is_numeric($total)) {
            return null;
        }
        $seen += count($batch);
        foreach ($batch as $rec) {
            // Other record types share the name; only A/AAAA records are managed here.
            if (is_array($rec) &&
                strcasecmp((string)($rec['RecordType'] ?? ''), MWDDNS_ESA_RECORD_TYPE) === 0 &&
                strcasecmp(rtrim((string)($rec['RecordName'] ?? ''), '.'), $host) === 0) {
                $records[] = $rec;
            }
        }
        if ($seen >= (int)$total) {
            return $records;
        }
        if (count($batch) === 0) {
            return null;  // Fewer records than TotalCount: the listing is incomplete.
        }
    }
    return null;  // Page limit reached before the end of the listing.
}

/* =========================================================
 * OpenAPI V3 signing and transport
 * ========================================================= */

/**
 * Build signed request headers for an RPC call with an empty body.
 * Implements the ACS3-HMAC-SHA256 algorithm from the Alibaba Cloud OpenAPI V3
 * signature documentation. Returns the canonical query string and headers.
 */
function mwddns_aliesa_v3_sign(
    string $method, string $host, string $action, string $version, array $query,
    string $akId, string $akSec, string $date, string $nonce
): array {
    ksort($query, SORT_STRING);
    $pairs = [];
    foreach ($query as $name => $value) {
        // rawurlencode() is RFC 3986: space as %20, "*" as %2A, "~" unencoded.
        $pairs[] = rawurlencode((string)$name) . '=' . rawurlencode((string)$value);
    }
    $canonicalQuery = implode('&', $pairs);
    $payloadHash    = hash('sha256', '');

    $headers = [
        'host'                  => $host,
        'x-acs-action'          => $action,
        'x-acs-content-sha256'  => $payloadHash,
        'x-acs-date'            => $date,
        'x-acs-signature-nonce' => $nonce,
        'x-acs-version'         => $version,
    ];
    ksort($headers, SORT_STRING);
    $canonicalHeaders = '';
    foreach ($headers as $name => $value) {
        $canonicalHeaders .= $name . ':' . trim($value) . "\n";
    }
    $signedHeaders = implode(';', array_keys($headers));

    $canonicalRequest = implode("\n", [
        strtoupper($method), '/', $canonicalQuery, $canonicalHeaders, $signedHeaders, $payloadHash,
    ]);
    $stringToSign = "ACS3-HMAC-SHA256\n" . hash('sha256', $canonicalRequest);
    $signature    = hash_hmac('sha256', $stringToSign, $akSec);

    $headers['authorization'] = "ACS3-HMAC-SHA256 Credential={$akId}," .
        "SignedHeaders={$signedHeaders},Signature={$signature}";
    return ['query' => $canonicalQuery, 'headers' => $headers];
}

/**
 * Call an ESA RPC operation.
 * Returns: ['ok' => bool, 'http' => int, 'data' => array, 'error' => string]
 */
function mwddns_aliesa_call(array $api, string $method, string $action, array $query): array
{
    $signed = mwddns_aliesa_v3_sign(
        $method, $api['host'], $action, MWDDNS_ESA_API_VERSION, $query,
        $api['id'], $api['secret'], gmdate('Y-m-d\TH:i:s\Z'), bin2hex(random_bytes(16))
    );
    $url = 'https://' . $api['host'] . '/' . ($signed['query'] !== '' ? '?' . $signed['query'] : '');
    $headers = [];
    foreach ($signed['headers'] as $name => $value) {
        $headers[] = $name . ': ' . $value;
    }
    return mwddns_aliesa_http($method, $url, $headers);
}

function mwddns_aliesa_http(string $method, string $url, array $headers): array
{
    $timeoutMs = mwddns_request_timeout_ms();
    if ($timeoutMs <= 0) {
        return ['ok' => false, 'http' => 0, 'data' => [], 'error' => 'MWDDNS request deadline exceeded.'];
    }
    $ch = curl_init($url);
    $options = [
        CURLOPT_RETURNTRANSFER    => true,
        CURLOPT_TIMEOUT_MS        => $timeoutMs,
        CURLOPT_CONNECTTIMEOUT_MS => min(5000, $timeoutMs),
        CURLOPT_FOLLOWLOCATION    => false,
        CURLOPT_SSL_VERIFYHOST    => 2,
        CURLOPT_SSL_VERIFYPEER    => true,
    ];
    if (strtoupper($method) === 'POST') {
        // Empty body, as signed. "Content-Type:" stops curl adding an unsigned default.
        $options[CURLOPT_POST]       = true;
        $options[CURLOPT_POSTFIELDS] = '';
        $headers[] = 'Content-Type:';
    } else {
        $options[CURLOPT_HTTPGET] = true;
    }
    $options[CURLOPT_HTTPHEADER] = $headers;
    curl_setopt_array($ch, $options);

    $raw  = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    unset($ch); // PHP 8 CurlHandle is released when references are dropped.

    if ($err) {
        return ['ok' => false, 'http' => 0, 'data' => [], 'error' => $err];
    }
    $data = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($data)) {
        $data = [];
    }
    $ok = ($http >= 200 && $http < 300) && !isset($data['Code']);
    $error = '';
    if (!$ok) {
        $code  = is_string($data['Code'] ?? null) ? $data['Code'] : '';
        $text  = is_string($data['Message'] ?? null) ? $data['Message'] : '';
        $error = trim($code . ($code !== '' && $text !== '' ? ': ' : '') . $text);
        if ($error === '') {
            $error = "HTTP {$http}";
        }
    }
    return ['ok' => $ok, 'http' => $http, 'data' => $data, 'error' => $error];
}
