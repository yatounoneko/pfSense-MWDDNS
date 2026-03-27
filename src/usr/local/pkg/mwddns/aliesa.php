<?php
/*
 * mwddns/aliesa.php  –  Alibaba Cloud ESA (Edge Security Acceleration) provider
 *
 * Placed at: /usr/local/pkg/mwddns/aliesa.php
 *
 * Supports provider key:  aliesa
 *
 * Authentication: Alibaba Cloud V4 (ACS4-HMAC-SHA256).
 * API product:    ESA
 * API version:    2024-09-10
 * Endpoint:       https://esa.aliyuncs.com  (global, region = cn-hangzhou)
 *
 * Provider contract:
 *   mwddns_aliesa_fields()
 *   mwddns_aliesa_validate()
 *   mwddns_aliesa_update()
 */

define('MWDDNS_ESA_HOST',        'esa.aliyuncs.com');
define('MWDDNS_ESA_BASE_URL',    'https://esa.aliyuncs.com');
define('MWDDNS_ESA_API_VERSION', '2024-09-10');
define('MWDDNS_ESA_REGION',      'cn-hangzhou');   // ESA is a global service; region key is always cn-hangzhou

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
    return empty($errors);
}

function mwddns_aliesa_update(array $ipsByType, array $rule): array
{
    $akId   = trim($rule['access_key_id']     ?? '');
    $akSec  = trim($rule['access_key_secret'] ?? '');
    $siteId = trim($rule['esa_site_id']       ?? '');
    $host   = trim($rule['hostname']          ?? '');
    $ttl    = max(1, (int)($rule['ttl'] ?? 300));

    if ($akId === '' || $akSec === '' || $siteId === '') {
        return ['ok' => false, 'message' => 'Alibaba Cloud ESA credentials or site_id are missing.', 'actions' => []];
    }

    $actions  = [];
    $anyError = false;

    foreach ($ipsByType as $type => $currentIPs) {
        $records = mwddns_aliesa_list_records($akId, $akSec, $siteId, $host, $type);
        if ($records === null) {
            $actions[] = ['action' => 'error', 'ip' => '', 'type' => $type, 'ok' => false,
                          'error' => "Failed to fetch {$type} records from Alibaba Cloud ESA."];
            $anyError = true;
            continue;
        }

        // Map: ip => recordId
        $esaMap = [];
        foreach ($records as $rec) {
            $ip = $rec['Data']['Value'] ?? '';
            if ($ip !== '') {
                $esaMap[$ip] = (string)($rec['RecordId'] ?? '');
            }
        }

        $res = ['ok' => true, 'error' => ''];
        foreach (array_keys($currentIPs) as $ip) {
            if (isset($esaMap[$ip])) {
                $res = mwddns_aliesa_update_record($akId, $akSec, $esaMap[$ip], $host, $type, $ip, $ttl);
                $actions[] = ['action' => 'updated', 'ip' => $ip, 'type' => $type, 'ok' => $res['ok'], 'error' => $res['error']];
                unset($esaMap[$ip]);
            } else {
                $res = mwddns_aliesa_create_record($akId, $akSec, $siteId, $host, $type, $ip, $ttl);
                $actions[] = ['action' => 'created', 'ip' => $ip, 'type' => $type, 'ok' => $res['ok'], 'error' => $res['error']];
            }
            if (!$res['ok']) {
                $anyError = true;
            }
        }

        foreach ($esaMap as $oldIP => $recordId) {
            $res = mwddns_aliesa_delete_record($akId, $akSec, $recordId);
            $actions[] = ['action' => 'deleted', 'ip' => $oldIP, 'type' => $type, 'ok' => $res['ok'], 'error' => $res['error']];
            if (!$res['ok']) {
                $anyError = true;
            }
        }
    }

    return [
        'ok'      => !$anyError,
        'message' => $anyError ? 'One or more Alibaba Cloud ESA API calls failed.' : 'Records updated successfully.',
        'actions' => $actions,
    ];
}

/* =========================================================
 * ESA API helpers  (ACS4 / HMAC-SHA256 V4 signing)
 * ========================================================= */

/**
 * Compute the ACS4-HMAC-SHA256 Authorization header value.
 *
 * @param string $method         HTTP method (GET, POST, PUT, DELETE, PATCH)
 * @param string $path           Request path, e.g. /api/2024-09-10/dns/records
 * @param array  $queryParams    URL query parameters (already sorted or will be sorted here)
 * @param array  $signedHeaders  Assoc: lowercase header name => value (must include host, x-acs-*)
 * @param string $bodyHash       SHA-256 hex hash of the request body
 * @param string $akId           AccessKey ID
 * @param string $akSec          AccessKey Secret
 * @param string $datetime       ISO 8601 compact: YYYYMMDDTHHmmssZ
 */
function mwddns_aliesa_v4_auth(
    string $method,
    string $path,
    array  $queryParams,
    array  $signedHeaders,
    string $bodyHash,
    string $akId,
    string $akSec,
    string $datetime
): string {
    $date    = substr($datetime, 0, 8);
    $region  = MWDDNS_ESA_REGION;
    $product = 'esa';
    $scope   = "{$date}/{$region}/{$product}/aliyun_v4_request";

    // ── Canonical query string ────────────────────────────────────────────────
    ksort($queryParams);
    $cqParts = [];
    foreach ($queryParams as $k => $v) {
        $cqParts[] = rawurlencode((string)$k) . '=' . rawurlencode((string)$v);
    }
    $canonicalQuery = implode('&', $cqParts);

    // ── Canonical headers + signed header names ───────────────────────────────
    ksort($signedHeaders);
    $canonicalHeaders  = '';
    $signedHeaderNames = [];
    foreach ($signedHeaders as $k => $v) {
        $canonicalHeaders .= $k . ':' . trim((string)$v) . "\n";
        $signedHeaderNames[] = $k;
    }
    $signedHeadersStr = implode(';', $signedHeaderNames);

    // ── Canonical request ─────────────────────────────────────────────────────
    $canonicalRequest = implode("\n", [
        strtoupper($method),
        $path,
        $canonicalQuery,
        $canonicalHeaders,
        $signedHeadersStr,
        $bodyHash,
    ]);

    // ── String to sign ────────────────────────────────────────────────────────
    $crHash       = hash('sha256', $canonicalRequest);
    $stringToSign = "ACS4-HMAC-SHA256\n{$datetime}\n{$scope}\n{$crHash}";

    // ── Derived signing key ───────────────────────────────────────────────────
    $kDate    = hash_hmac('sha256', $date,                 'aliyun_v4' . $akSec, true);
    $kRegion  = hash_hmac('sha256', $region,               $kDate,               true);
    $kProduct = hash_hmac('sha256', $product,              $kRegion,             true);
    $kSigning = hash_hmac('sha256', 'aliyun_v4_request',   $kProduct,            true);

    $signature = hash_hmac('sha256', $stringToSign, $kSigning);

    return "ACS4-HMAC-SHA256 Credential={$akId}/{$scope}," .
           "SignedHeaders={$signedHeadersStr}," .
           "Signature={$signature}";
}

/**
 * Execute an ESA REST API call.
 * Returns: ['ok' => bool, 'http' => int, 'data' => array, 'error' => string]
 */
function mwddns_aliesa_request(
    string $method,
    string $path,
    array  $queryParams,
    ?array $body,
    string $akId,
    string $akSec
): array {
    $datetime = gmdate('Ymd\THis\Z');
    $bodyJson = ($body !== null) ? json_encode($body) : '';
    $bodyHash = hash('sha256', $bodyJson);

    $signedHeaders = [
        'host'                 => MWDDNS_ESA_HOST,
        'x-acs-content-sha256' => $bodyHash,
        'x-acs-date'           => $datetime,
        'x-acs-version'        => MWDDNS_ESA_API_VERSION,
    ];

    $auth = mwddns_aliesa_v4_auth(
        $method, $path, $queryParams, $signedHeaders,
        $bodyHash, $akId, $akSec, $datetime
    );

    // Build the full URL with sorted query params
    $url = MWDDNS_ESA_BASE_URL . $path;
    if (!empty($queryParams)) {
        ksort($queryParams);
        $qParts = [];
        foreach ($queryParams as $k => $v) {
            $qParts[] = rawurlencode((string)$k) . '=' . rawurlencode((string)$v);
        }
        $url .= '?' . implode('&', $qParts);
    }

    $httpHeaders = [
        'Authorization: ' . $auth,
        'Content-Type: application/json',
        'Host: '                  . MWDDNS_ESA_HOST,
        'x-acs-content-sha256: '  . $bodyHash,
        'x-acs-date: '            . $datetime,
        'x-acs-version: '         . MWDDNS_ESA_API_VERSION,
    ];

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $httpHeaders,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_CUSTOMREQUEST  => strtoupper($method),
    ]);

    if ($bodyJson !== '') {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $bodyJson);
    }

    $raw  = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($err) {
        return ['ok' => false, 'http' => 0, 'data' => [], 'error' => $err];
    }

    $data = json_decode($raw, true) ?? [];
    $ok   = ($http >= 200 && $http < 300);

    return [
        'ok'    => $ok,
        'http'  => $http,
        'data'  => $data,
        'error' => $ok ? '' : ($data['message'] ?? $data['Message'] ?? "HTTP $http"),
    ];
}

/* =========================================================
 * ESA DNS record operations
 * ========================================================= */

$MWDDNS_ESA_API_PATH = '/api/' . MWDDNS_ESA_API_VERSION . '/dns/records';

/**
 * List A or AAAA records for a site + hostname.
 * Returns array of record objects, or null on error.
 */
function mwddns_aliesa_list_records(
    string $akId, string $akSec,
    string $siteId, string $hostname, string $type = 'A'
): ?array {
    global $MWDDNS_ESA_API_PATH;
    $res = mwddns_aliesa_request('GET', $MWDDNS_ESA_API_PATH, [
        'siteId'     => $siteId,
        'type'       => $type,
        'recordName' => $hostname,
        'pageSize'   => 500,
    ], null, $akId, $akSec);

    if (!$res['ok']) {
        return null;
    }
    // Response: {"RequestId":..., "TotalCount":..., "Records":[...]}
    $raw = $res['data']['Records'] ?? [];
    // Normalise single-record case
    if (isset($raw['RecordId'])) {
        $raw = [$raw];
    }
    return array_values((array)$raw);
}

/** Create a new ESA A or AAAA record. */
function mwddns_aliesa_create_record(
    string $akId, string $akSec,
    string $siteId, string $hostname,
    string $type, string $ip, int $ttl
): array {
    global $MWDDNS_ESA_API_PATH;
    return mwddns_aliesa_request('POST', $MWDDNS_ESA_API_PATH, [], [
        'SiteId'     => (int)$siteId,
        'RecordName' => $hostname,
        'Type'       => $type,
        'Data'       => ['Value' => $ip],
        'Ttl'        => $ttl,
    ], $akId, $akSec);
}

/** Update an existing ESA A or AAAA record. */
function mwddns_aliesa_update_record(
    string $akId, string $akSec,
    string $recordId, string $hostname,
    string $type, string $ip, int $ttl
): array {
    global $MWDDNS_ESA_API_PATH;
    return mwddns_aliesa_request('PUT', $MWDDNS_ESA_API_PATH . '/' . rawurlencode($recordId), [], [
        'RecordName' => $hostname,
        'Type'       => $type,
        'Data'       => ['Value' => $ip],
        'Ttl'        => $ttl,
    ], $akId, $akSec);
}

/** Delete an ESA DNS record. */
function mwddns_aliesa_delete_record(
    string $akId, string $akSec,
    string $recordId
): array {
    global $MWDDNS_ESA_API_PATH;
    return mwddns_aliesa_request('DELETE', $MWDDNS_ESA_API_PATH . '/' . rawurlencode($recordId), [], null, $akId, $akSec);
}
