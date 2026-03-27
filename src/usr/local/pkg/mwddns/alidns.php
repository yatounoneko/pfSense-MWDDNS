<?php
/*
 * mwddns/alidns.php  –  Alibaba Cloud DNS provider for MWDDNS
 *
 * Placed at: /usr/local/pkg/mwddns/alidns.php
 *
 * Supports two provider keys registered in mwddns.inc:
 *   alidns_intl  –  International endpoint (ap-southeast-1)
 *   alidns_cn    –  China mainland endpoint  (default region)
 *
 * Authentication: Alibaba Cloud RPC V1 (HMAC-SHA1).
 * API product:    Alidns (Cloud DNS)
 * API version:    2015-01-09
 *
 * Provider contract functions exposed:
 *   mwddns_alidns_intl_fields()   / mwddns_alidns_cn_fields()
 *   mwddns_alidns_intl_validate() / mwddns_alidns_cn_validate()
 *   mwddns_alidns_intl_update()   / mwddns_alidns_cn_update()
 */

define('MWDDNS_ALIDNS_API_VERSION', '2015-01-09');
// Endpoint map keyed by provider key
define('MWDDNS_ALIDNS_ENDPOINTS', serialize([
    'alidns_intl' => 'https://alidns.ap-southeast-1.aliyuncs.com',
    'alidns_cn'   => 'https://alidns.aliyuncs.com',
]));

/* =========================================================
 * Provider contract – International
 * ========================================================= */

function mwddns_alidns_intl_fields(): array
{
    return mwddns_alidns_fields('alidns_intl');
}

function mwddns_alidns_intl_validate(array $post, array &$errors): bool
{
    return mwddns_alidns_validate_impl($post, $errors);
}

function mwddns_alidns_intl_update(array $ipsByType, array $rule): array
{
    return mwddns_alidns_update_impl($ipsByType, $rule, 'alidns_intl');
}

/* =========================================================
 * Provider contract – China
 * ========================================================= */

function mwddns_alidns_cn_fields(): array
{
    return mwddns_alidns_fields('alidns_cn');
}

function mwddns_alidns_cn_validate(array $post, array &$errors): bool
{
    return mwddns_alidns_validate_impl($post, $errors);
}

function mwddns_alidns_cn_update(array $ipsByType, array $rule): array
{
    return mwddns_alidns_update_impl($ipsByType, $rule, 'alidns_cn');
}

/* =========================================================
 * Shared field definitions
 * ========================================================= */

function mwddns_alidns_fields(string $providerKey): array
{
    $regionNote = ($providerKey === 'alidns_cn')
        ? mwddns_t('Endpoint: China mainland (alidns.aliyuncs.com)')
        : mwddns_t('Endpoint: International / Asia Pacific (alidns.ap-southeast-1.aliyuncs.com)');

    return [
        [
            'key'         => 'access_key_id',
            'label'       => 'AccessKey ID',
            'type'        => 'text',
            'required'    => true,
            'placeholder' => mwddns_t('Alibaba Cloud AccessKey ID'),
            'help'        => mwddns_t('Found in Alibaba Cloud Console → AccessKey Management.') .
                             ' <em>' . $regionNote . '</em>',
        ],
        [
            'key'         => 'access_key_secret',
            'label'       => 'AccessKey Secret',
            'type'        => 'password',
            'required'    => true,
            'placeholder' => mwddns_t('Alibaba Cloud AccessKey Secret'),
            'help'        => mwddns_t('Keep secret. Stored in plain text in pfSense config.xml. Use a RAM sub-account with only DNS permissions.'),
        ],
        [
            'key'         => 'ali_domain',
            'label'       => mwddns_t('Root Domain'),
            'type'        => 'text',
            'required'    => true,
            'placeholder' => mwddns_t('e.g. example.com'),
            'help'        => mwddns_t('The root domain registered in Alibaba Cloud DNS. The subdomain prefix (RR) is derived automatically from the Hostname field.'),
        ],
    ];
}

/* =========================================================
 * Shared validation
 * ========================================================= */

function mwddns_alidns_validate_impl(array $post, array &$errors): bool
{
    if (trim($post['access_key_id'] ?? '') === '') {
        $errors[] = mwddns_t('Alibaba Cloud AccessKey ID is required.');
    }
    if (trim($post['access_key_secret'] ?? '') === '') {
        $errors[] = mwddns_t('Alibaba Cloud AccessKey Secret is required.');
    }
    if (!preg_match('/^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/', trim($post['ali_domain'] ?? ''))) {
        $errors[] = mwddns_t('Root Domain must be a valid domain name (e.g. example.com).');
    }
    return empty($errors);
}

/* =========================================================
 * Shared update implementation
 * ========================================================= */

function mwddns_alidns_update_impl(array $ipsByType, array $rule, string $providerKey): array
{
    $akId    = trim($rule['access_key_id']     ?? '');
    $akSec   = trim($rule['access_key_secret'] ?? '');
    $domain  = trim($rule['ali_domain']        ?? '');
    $host    = trim($rule['hostname']          ?? '');
    $ttl     = max(600, (int)($rule['ttl'] ?? 600));  // AliDNS minimum TTL is 600s

    if ($akId === '' || $akSec === '' || $domain === '') {
        return ['ok' => false, 'message' => 'Alibaba Cloud credentials or domain are missing.', 'actions' => []];
    }

    // Derive the RR (subdomain prefix) from hostname and root domain
    $rr = mwddns_alidns_derive_rr($host, $domain);
    if ($rr === null) {
        return ['ok' => false, 'message' => "Hostname '{$host}' does not belong to domain '{$domain}'.", 'actions' => []];
    }

    $endpoints = unserialize(MWDDNS_ALIDNS_ENDPOINTS);
    $endpoint  = $endpoints[$providerKey];

    $actions  = [];
    $anyError = false;

    foreach ($ipsByType as $type => $currentIPs) {
        $records = mwddns_alidns_list_records($akId, $akSec, $endpoint, $domain, $rr, $type);
        if ($records === null) {
            $actions[] = ['action' => 'error', 'ip' => '', 'type' => $type, 'ok' => false,
                          'error' => "Failed to fetch {$type} records from Alibaba Cloud DNS."];
            $anyError = true;
            continue;
        }

        // Map: ip => recordId
        $aliMap = [];
        foreach ($records as $rec) {
            $aliMap[$rec['Value']] = $rec['RecordId'];
        }

        $res = ['ok' => true, 'error' => ''];
        foreach (array_keys($currentIPs) as $ip) {
            if (isset($aliMap[$ip])) {
                $res = mwddns_alidns_update_record($akId, $akSec, $endpoint, $aliMap[$ip], $rr, $type, $ip, $ttl);
                $actions[] = ['action' => 'updated', 'ip' => $ip, 'type' => $type, 'ok' => $res['ok'], 'error' => $res['error']];
                unset($aliMap[$ip]);
            } else {
                $res = mwddns_alidns_add_record($akId, $akSec, $endpoint, $domain, $rr, $type, $ip, $ttl);
                $actions[] = ['action' => 'created', 'ip' => $ip, 'type' => $type, 'ok' => $res['ok'], 'error' => $res['error']];
            }
            if (!$res['ok']) {
                $anyError = true;
            }
        }

        foreach ($aliMap as $oldIP => $recordId) {
            $res = mwddns_alidns_delete_record($akId, $akSec, $endpoint, $recordId);
            $actions[] = ['action' => 'deleted', 'ip' => $oldIP, 'type' => $type, 'ok' => $res['ok'], 'error' => $res['error']];
            if (!$res['ok']) {
                $anyError = true;
            }
        }
    }

    return [
        'ok'      => !$anyError,
        'message' => $anyError ? 'One or more Alibaba Cloud DNS API calls failed.' : 'Records updated successfully.',
        'actions' => $actions,
    ];
}

/**
 * Derive the DNS RR (subdomain prefix) from a FQDN and root domain.
 * Returns '@' for the apex, or the subdomain label(s), or null if hostname
 * does not end with the root domain.
 *
 * Example: ('home.example.com', 'example.com') → 'home'
 *          ('example.com',      'example.com') → '@'
 */
function mwddns_alidns_derive_rr(string $hostname, string $domain): ?string
{
    $hostname = rtrim(strtolower($hostname), '.');
    $domain   = rtrim(strtolower($domain), '.');

    if ($hostname === $domain) {
        return '@';
    }

    $suffix = '.' . $domain;
    if (str_ends_with($hostname, $suffix)) {
        return substr($hostname, 0, strlen($hostname) - strlen($suffix));
    }

    return null;
}

/* =========================================================
 * Alibaba Cloud DNS API calls (RPC V1 / HMAC-SHA1)
 * ========================================================= */

/**
 * Encode a value using RFC3986 (Alibaba Cloud V1 percentEncode spec).
 * PHP's rawurlencode is RFC3986-compliant for this purpose.
 */
function mwddns_alidns_penc(string $s): string
{
    return rawurlencode($s);
}

/**
 * Sign and execute an Alibaba Cloud RPC V1 API call.
 * Returns: ['ok' => bool, 'http' => int, 'data' => array, 'error' => string]
 */
function mwddns_alidns_call(
    string $akId, string $akSec, string $endpoint,
    string $action, array $params
): array {
    $commonParams = [
        'Action'           => $action,
        'AccessKeyId'      => $akId,
        'Format'           => 'JSON',
        'Version'          => MWDDNS_ALIDNS_API_VERSION,
        'SignatureMethod'   => 'HMAC-SHA1',
        'SignatureVersion'  => '1.0',
        'SignatureNonce'    => bin2hex(random_bytes(16)),
        'Timestamp'        => gmdate('Y-m-d\TH:i:s\Z'),
    ];

    $all = array_merge($commonParams, $params);
    ksort($all);

    // Build canonical query string (RFC3986 encoded)
    $parts = [];
    foreach ($all as $k => $v) {
        $parts[] = mwddns_alidns_penc((string)$k) . '=' . mwddns_alidns_penc((string)$v);
    }
    $canonicalQuery = implode('&', $parts);

    // String to sign: "GET&%2F&<encoded_canonical_query>"
    $stringToSign = 'GET&%2F&' . mwddns_alidns_penc($canonicalQuery);
    $signature    = base64_encode(hash_hmac('sha1', $stringToSign, $akSec . '&', true));
    $all['Signature'] = $signature;

    $url = $endpoint . '/?' . http_build_query($all);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPGET        => true,
    ]);

    $raw  = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($err) {
        return ['ok' => false, 'http' => 0, 'data' => [], 'error' => $err];
    }

    $data = json_decode($raw, true) ?? [];
    $ok   = ($http >= 200 && $http < 300) && !isset($data['Code']);

    return [
        'ok'    => $ok,
        'http'  => $http,
        'data'  => $data,
        'error' => $ok ? '' : ($data['Message'] ?? $data['Code'] ?? "HTTP $http"),
    ];
}

/**
 * List A or AAAA records for a given RR under a domain.
 * Returns array of record objects, or null on error.
 */
function mwddns_alidns_list_records(
    string $akId, string $akSec, string $endpoint,
    string $domain, string $rr, string $type = 'A'
): ?array {
    $res = mwddns_alidns_call($akId, $akSec, $endpoint, 'DescribeDomainRecords', [
        'DomainName'  => $domain,
        'RRKeyWord'   => $rr,
        'TypeKeyWord' => $type,
        'PageSize'    => 500,
    ]);

    if (!$res['ok']) {
        return null;
    }

    // AliDNS collapses a single record into an object, not an array
    $raw = $res['data']['DomainRecords']['Record'] ?? [];
    if (isset($raw['RecordId'])) {
        $raw = [$raw];
    }

    // Filter to only exact RR + type matches (keyword search may return partial matches)
    return array_values(array_filter($raw, static fn($r) => $r['RR'] === $rr && $r['Type'] === $type));
}

/** Add a new A or AAAA record. */
function mwddns_alidns_add_record(
    string $akId, string $akSec, string $endpoint,
    string $domain, string $rr, string $type, string $ip, int $ttl
): array {
    return mwddns_alidns_call($akId, $akSec, $endpoint, 'AddDomainRecord', [
        'DomainName' => $domain,
        'RR'         => $rr,
        'Type'       => $type,
        'Value'      => $ip,
        'TTL'        => $ttl,
    ]);
}

/** Update an existing A or AAAA record by RecordId. */
function mwddns_alidns_update_record(
    string $akId, string $akSec, string $endpoint,
    string $recordId, string $rr, string $type, string $ip, int $ttl
): array {
    return mwddns_alidns_call($akId, $akSec, $endpoint, 'UpdateDomainRecord', [
        'RecordId' => $recordId,
        'RR'       => $rr,
        'Type'     => $type,
        'Value'    => $ip,
        'TTL'      => $ttl,
    ]);
}

/** Delete a DNS record by RecordId. */
function mwddns_alidns_delete_record(
    string $akId, string $akSec, string $endpoint,
    string $recordId
): array {
    return mwddns_alidns_call($akId, $akSec, $endpoint, 'DeleteDomainRecord', [
        'RecordId' => $recordId,
    ]);
}
