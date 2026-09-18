#!/usr/local/bin/php -q
<?php
/*
 * Private context for the collector, through an anonymous pipe only.
 * NEVER save or expose stdout: it includes redaction material.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}
ini_set('display_errors', '0');
ini_set('log_errors', '0');
require_once('/etc/inc/globals.inc');
require_once('/etc/inc/functions.inc');
require_once('/etc/inc/config.inc');
require_once('/usr/local/pkg/mwddns.inc');
require_once('/usr/local/pkg/mwddns/debug.inc');

try {
    mwddns_reload_config();
    $runtime = ($argv[1] ?? '') === 'runtime';
    $context = ['wans' => [], 'rules' => [], 'secrets' => [], 'php_version' => PHP_VERSION];
    $gateways = mwddns_gateway_definitions();
    $thresholds = mwddns_get_gateway_thresholds();
    $statuses = $runtime ? mwddns_get_gateway_statuses($thresholds) : [];
    $wanAliases = [];
    foreach (mwddns_debug_wans() as $wan) {
        $key = $wan['key'];
        $wanAliases[$key] = $wan['alias'];
        $names = [$key, $wan['description'], $wan['device']];
        if (function_exists('get_real_interface')) {
            $real = get_real_interface($key);
            if (is_string($real) && $real !== '') {
                $names[] = $real;
            }
        }
        $gwRows = [];
        foreach ($gateways as $name => $gateway) {
            if (($gateway['friendlyiface'] ?? '') !== $key) {
                continue;
            }
            $names[] = $name;
            $limits = $thresholds[$name] ?? $thresholds[''] ?? [];
            $gwRows[] = [
                'family' => ($gateway['ipprotocol'] ?? '') === 'inet6' ? 'AAAA' : 'A',
                'state' => $statuses[$name] ?? 'unknown',
                'disabled' => isset($gateway['disabled']) || isset($gateway['force_down']),
                'unmonitored' => isset($gateway['monitor_disable']),
                'latency_high_ms' => $limits['latencyhigh'] ?? 500,
                'loss_high_percent' => $limits['losshigh'] ?? 20,
            ];
        }
        $context['wans'][] = [
            'alias' => $wan['alias'],
            'names' => array_values(array_unique(array_filter($names, 'strlen'))),
            'enabled' => isset($config['interfaces'][$key]['enable']),
            'ipv4' => $runtime ? mwddns_get_interface_ip($key) : null,
            'ipv6' => $runtime ? mwddns_get_interface_ipv6($key) : null,
            'gateways' => $gwRows,
        ];
    }
    foreach (mwddns_get_rules() as $rule) {
        $interfaces = [];
        foreach (mwddns_rule_interfaces($rule) as $key) {
            if (isset($wanAliases[$key])) {
                $interfaces[] = $wanAliases[$key];
            }
        }
        $context['rules'][] = [
            'alias' => 'RULE_' . (count($context['rules']) + 1),
            'names' => [(string)($rule['name'] ?? ''), (string)($rule['hostname'] ?? '')],
            'provider' => (string)($rule['provider'] ?? 'cloudflare'),
            'families' => mwddns_rule_record_types($rule),
            'wans' => $interfaces,
            'last_updated' => $runtime ? ($rule['last_updated'] ?? '') : '',
            'last_status' => $runtime ? ($rule['last_status'] ?? '') : '',
            'observed_a' => $runtime ? mwddns_cached_observed_ips($rule, 'A') : null,
            'observed_aaaa' => $runtime ? mwddns_cached_observed_ips($rule, 'AAAA') : null,
        ];
    }
    $visit = static function ($node, string $key = '') use (&$visit, &$context): void {
        if (is_array($node)) {
            foreach ($node as $childKey => $child) {
                $visit($child, (string)$childKey);
            }
        } elseif (is_string($node) && strlen($node) >= 4 &&
            preg_match('/password|passwd|token|secret|private.?key|api.?key|access.?key|community|authorization/i', $key)) {
            if (count($context['secrets']) >= 4096 || strlen($node) > 65536) {
                throw new RuntimeException('Redaction context limit.');
            }
            $context['secrets'][] = $node;
        }
    };
    $visit($config);
    $json = json_encode($context, JSON_THROW_ON_ERROR);
    if (strlen($json) > 1024 * 1024) {
        throw new RuntimeException('Redaction context limit.');
    }
    echo $json;
} catch (Throwable $e) {
    // Never print exceptions, stack arguments or partial configuration.
    exit(1);
}
