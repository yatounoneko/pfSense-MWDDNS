#!/usr/local/bin/php -q
<?php
/*
 * mwddns_cron.php  –  Periodic cron runner for Multi-WAN DDNS
 *
 * Placed at: /usr/local/bin/mwddns_cron.php
 * Runs every 5 minutes (installed by mwddns_install_cron()).
 * Accepts an optional interface key argument to limit updates.
 *
 * Loads pfSense bootstrap, then calls mwddns_update_all() to
 * synchronise all configured rules with Cloudflare.
 */

// pfSense PHP bootstrap
require_once('/etc/inc/globals.inc');
require_once('/etc/inc/functions.inc');
require_once('/etc/inc/config.inc');
require_once('/usr/local/pkg/mwddns.inc');

// Load pfSense config
try {
    mwddns_reload_config();
} catch (Throwable $e) {
    mwddns_log($e->getMessage(), LOG_ERR);
    fwrite(STDERR, "MWDDNS: configuration initialization failed; DNS was not changed.\n");
    exit(1);
}
$targetIf = $argv[1] ?? null;

$rules = mwddns_get_rules();
$results = mwddns_update_all($targetIf);
// Keep the per-rule logging below, then report partial failures to the caller.
register_shutdown_function(static function () use ($results): void {
    foreach ($results as $result) {
        if (empty($result['ok'])) {
            exit(1);
        }
    }
});
// Keep the original rule labels even if a later operation reorders configuration.

foreach ($results as $id => $res) {
    $name   = $rules[$id]['name'] ?? "Rule #{$id}";
    $status = $res['ok'] ? 'OK' : 'FAIL';
    $msg    = $res['message'] ?? '';
    mwddns_log("[{$name}] {$status}" . ($msg !== '' ? ": {$msg}" : ''));
}
