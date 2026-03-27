#!/usr/local/bin/php -q
<?php
/*
 * mwddns_cron.php  –  Periodic cron runner for Multi-WAN DDNS
 *
 * Placed at: /usr/local/bin/mwddns_cron.php
 * Runs every 5 minutes (installed by mwddns_install_cron()).
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
$config = parse_config(true);

$results = mwddns_update_all();

foreach ($results as $id => $res) {
    $rules  = mwddns_get_rules();
    $name   = $rules[$id]['name'] ?? "Rule #{$id}";
    $status = $res['ok'] ? 'OK' : 'FAIL';
    $msg    = $res['message'] ?? '';
    syslog(LOG_INFO, "mwddns [{$name}] {$status}: {$msg}");
}
