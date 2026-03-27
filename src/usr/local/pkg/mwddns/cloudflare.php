<?php
/*
 * mwddns/cloudflare.php  –  Cloudflare DNS provider for MWDDNS
 *
 * Placed at: /usr/local/pkg/mwddns/cloudflare.php
 *
 * Implements the standard MWDDNS provider contract:
 *   mwddns_cloudflare_fields()    – field definitions for the edit UI
 *   mwddns_cloudflare_validate()  – validate provider-specific POST data
 *   mwddns_cloudflare_update()    – sync A/AAAA records with the Cloudflare API
 */

define('MWDDNS_CF_API', 'https://api.cloudflare.com/client/v4');

/* =========================================================
 * Provider contract
 * ========================================================= */

/**
 * Field definitions rendered by mwddns_edit.php.
 * Each element: [key, label, type, required, placeholder, help, cvalue, pattern]
 */
function mwddns_cloudflare_fields(): array
{
    return [
        [
            'key'         => 'token',
            'label'       => 'API Token',
            'type'        => 'password',
            'required'    => true,
            'placeholder' => mwddns_t('Cloudflare API Token with DNS edit permission'),
            'help'        => mwddns_t('Create a token at Cloudflare Dashboard → My Profile → API Tokens with Zone → DNS → Edit permission.') .
                             ' <strong class="text-warning">' .
                             mwddns_t('Tokens are stored in plain text in pfSense\'s config.xml. Restrict the token to only the required zone and permission.') .
                             '</strong>',
        ],
        [
            'key'         => 'zone_id',
            'label'       => 'Zone ID',
            'type'        => 'text',
            'required'    => true,
            'placeholder' => mwddns_t('32-character hex string'),
            'pattern'     => '[0-9a-fA-F]{32}',
            'help'        => mwddns_t('Found in Cloudflare Dashboard → (select domain) → Overview → Zone ID.'),
        ],
        [
            'key'    => 'proxied',
            'label'  => mwddns_t('Cloudflare Proxy (orange cloud)'),
            'type'   => 'checkbox',
            'cvalue' => '1',
            'help'   => mwddns_t('When enabled, traffic is proxied through Cloudflare CDN. TTL is forced to "auto" by Cloudflare.'),
        ],
    ];
}

/**
 * Validate Cloudflare-specific POST fields.
 * Appends error strings to $errors; returns true when clean.
 */
function mwddns_cloudflare_validate(array $post, array &$errors): bool
{
    if (trim($post['token'] ?? '') === '') {
        $errors[] = mwddns_t('Cloudflare API token is required.');
    }
    if (!preg_match('/^[0-9a-f]{32}$/i', trim($post['zone_id'] ?? ''))) {
        $errors[] = mwddns_t('Cloudflare Zone ID must be a 32-character hexadecimal string.');
    }
    return empty($errors);
}

/**
 * Synchronise Cloudflare A and/or AAAA records.
 *
 * $ipsByType  – ['A' => ['1.2.3.4'=>true, …], 'AAAA' => ['::1'=>true, …]]
 * $rule       – saved rule array from config.xml
 *
 * Returns: ['ok' => bool, 'message' => string, 'actions' => [...]]
 */
function mwddns_cloudflare_update(array $ipsByType, array $rule): array
{
    $token   = $rule['token']   ?? '';
    $zone_id = $rule['zone_id'] ?? '';
    $host    = $rule['hostname'] ?? '';
    $ttl     = max(1, (int)($rule['ttl'] ?? 300));
    $proxied = ($rule['proxied'] ?? '0') === '1';

    if ($token === '' || $zone_id === '') {
        return ['ok' => false, 'message' => 'Cloudflare token or zone_id is missing.', 'actions' => []];
    }

    $actions  = [];
    $anyError = false;

    foreach ($ipsByType as $type => $currentIPs) {
        $cfRecords = mwddns_cf_list_records($token, $zone_id, $host, $type);
        if ($cfRecords === null) {
            $actions[] = ['action' => 'error', 'ip' => '', 'ok' => false,
                          'error' => "Failed to fetch {$type} records from Cloudflare."];
            $anyError = true;
            continue;
        }

        $cfMap = [];
        foreach ($cfRecords as $rec) {
            $cfMap[$rec['content']] = $rec['id'];
        }

        $res = ['ok' => true, 'error' => ''];
        foreach (array_keys($currentIPs) as $ip) {
            if (isset($cfMap[$ip])) {
                $res = mwddns_cf_update_record($token, $zone_id, $cfMap[$ip], $host, $type, $ip, $ttl, $proxied);
                $actions[] = ['action' => 'updated', 'ip' => $ip, 'type' => $type, 'ok' => $res['ok'], 'error' => $res['error']];
                unset($cfMap[$ip]);
            } else {
                $res = mwddns_cf_create_record($token, $zone_id, $host, $type, $ip, $ttl, $proxied);
                $actions[] = ['action' => 'created', 'ip' => $ip, 'type' => $type, 'ok' => $res['ok'], 'error' => $res['error']];
            }
            if (!$res['ok']) {
                $anyError = true;
            }
        }

        foreach ($cfMap as $oldIP => $recordId) {
            $res = mwddns_cf_delete_record($token, $zone_id, $recordId);
            $actions[] = ['action' => 'deleted', 'ip' => $oldIP, 'type' => $type, 'ok' => $res['ok'], 'error' => $res['error']];
            if (!$res['ok']) {
                $anyError = true;
            }
        }
    }

    return [
        'ok'      => !$anyError,
        'message' => $anyError ? 'One or more Cloudflare API calls failed.' : 'Records updated successfully.',
        'actions' => $actions,
    ];
}

/**
 * In proxy mode, recursive DNS no longer reflects origin A/AAAA records.
 * Tell UI/widget to match against Cloudflare API records instead.
 */
function mwddns_cloudflare_should_use_api_match(array $rule): bool
{
    return ($rule['proxied'] ?? '0') === '1';
}

/**
 * List configured A/AAAA record IPs from Cloudflare for UI/widget matching.
 * Returns null on API error.
 */
function mwddns_cloudflare_list_records(array $rule, string $type): ?array
{
    if (!in_array($type, ['A', 'AAAA'], true)) {
        return null;
    }

    $token   = trim($rule['token'] ?? '');
    $zone_id = trim($rule['zone_id'] ?? '');
    $host    = trim($rule['hostname'] ?? '');
    if ($token === '' || $zone_id === '' || $host === '') {
        return null;
    }

    $records = mwddns_cf_list_records($token, $zone_id, $host, $type);
    if (!is_array($records)) {
        return null;
    }

    $ips = [];
    foreach ($records as $rec) {
        $ip = $rec['content'] ?? '';
        if (is_string($ip) && $ip !== '') {
            $ips[] = $ip;
        }
    }
    return $ips;
}

/* =========================================================
 * Internal Cloudflare API helpers
 * ========================================================= */

/**
 * Execute a Cloudflare REST API request.
 * Returns: ['ok' => bool, 'http' => int, 'data' => array, 'error' => string]
 */
function mwddns_cf_request(string $method, string $url, string $token, ?array $body = null): array
{
    $headers = [
        'Authorization: Bearer ' . $token,
        'Content-Type: application/json',
    ];

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_CUSTOMREQUEST  => $method,
    ]);

    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    }

    $raw  = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($err) {
        return ['ok' => false, 'http' => 0, 'data' => [], 'error' => $err];
    }

    $data = json_decode($raw, true) ?? [];
    $ok   = ($http >= 200 && $http < 300) && !empty($data['success']);

    return [
        'ok'    => $ok,
        'http'  => $http,
        'data'  => $data,
        'error' => $ok ? '' : ($data['errors'][0]['message'] ?? "HTTP $http"),
    ];
}

/** List all A or AAAA records for $hostname in $zone_id. Returns null on error. */
function mwddns_cf_list_records(string $token, string $zone_id, string $hostname, string $type = 'A'): ?array
{
    $url = MWDDNS_CF_API . '/zones/' . rawurlencode($zone_id) . '/dns_records?' .
           http_build_query(['name' => $hostname, 'type' => $type]);
    $res = mwddns_cf_request('GET', $url, $token);
    return $res['ok'] ? ($res['data']['result'] ?? []) : null;
}

/** Create a new Cloudflare A or AAAA record. */
function mwddns_cf_create_record(
    string $token, string $zone_id, string $hostname,
    string $type, string $ip, int $ttl, bool $proxied
): array {
    $url = MWDDNS_CF_API . '/zones/' . rawurlencode($zone_id) . '/dns_records';
    return mwddns_cf_request('POST', $url, $token, [
        'type'    => $type,
        'name'    => $hostname,
        'content' => $ip,
        'ttl'     => $ttl,
        'proxied' => $proxied,
    ]);
}

/** Update an existing Cloudflare A or AAAA record (full replace via PUT). */
function mwddns_cf_update_record(
    string $token, string $zone_id, string $record_id,
    string $hostname, string $type, string $ip, int $ttl, bool $proxied
): array {
    $url = MWDDNS_CF_API . '/zones/' . rawurlencode($zone_id) .
           '/dns_records/' . rawurlencode($record_id);
    return mwddns_cf_request('PUT', $url, $token, [
        'type'    => $type,
        'name'    => $hostname,
        'content' => $ip,
        'ttl'     => $ttl,
        'proxied' => $proxied,
    ]);
}

/** Delete a Cloudflare DNS record. */
function mwddns_cf_delete_record(string $token, string $zone_id, string $record_id): array
{
    $url = MWDDNS_CF_API . '/zones/' . rawurlencode($zone_id) .
           '/dns_records/' . rawurlencode($record_id);
    return mwddns_cf_request('DELETE', $url, $token);
}
