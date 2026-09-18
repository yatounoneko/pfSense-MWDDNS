#!/usr/local/bin/php
<?php
/* Internal CLI helper. The parent upgrade worker holds the MWDDNS operation lock.
 * Only the MWDDNS subtree/registration is backed up or restored, never all config.
 */
function mwddns_upgrade_config_rows($rows): array
{
    if (!is_array($rows)) { return []; }
    return isset($rows['name']) ? [$rows] : array_values($rows);
}
function mwddns_upgrade_config_package(array $row): bool
{
    return ($row['name'] ?? '') === 'mwddns' || ($row['internal_name'] ?? '') === 'mwddns';
}
function mwddns_upgrade_config_menu(array $row): bool
{
    return ($row['name'] ?? '') === 'Multi-WAN DDNS' && ($row['section'] ?? '') === 'Services';
}
function mwddns_upgrade_config_restore_rows($rows, array $saved, callable $matches): array
{
    $saved = array_values($saved);
    $restored = [];
    $next = 0;
    foreach (mwddns_upgrade_config_rows($rows) as $row) {
        if (!$matches($row)) {
            $restored[] = $row;
        } elseif ($next < count($saved)) {
            // Replace registrations in their existing slots, preserving other rows.
            $restored[] = $saved[$next++];
        }
    }
    // A removed registration has no remaining slot; append any unmatched rows.
    return array_merge($restored, array_slice($saved, $next));
}
function mwddns_upgrade_config_action(string $action, string $id): void
{
    global $config;
    if (!preg_match('/^[a-f0-9]{32}$/D', $id) || !in_array($action, ['backup', 'reset', 'restore'], true)) {
        throw new RuntimeException('INVALID_STATE');
    }
    $directory = '/conf/mwddns-backups/upgrade-' . $id;
    if (is_link('/conf/mwddns-backups') || is_link($directory) || !is_dir($directory)) {
        throw new RuntimeException('UNSAFE_DIRECTORY');
    }
    $path = $directory . '/config.json';
    if (is_link($path)) { throw new RuntimeException('UNSAFE_FILE'); }
    if (!function_exists('config_read_file') || !config_read_file(false, false) ||
        !is_array($config) || empty($config)) {
        throw new RuntimeException('CONFIG_RELOAD_FAILED');
    }
    if ($action === 'backup') {
        $snapshot = [
            'schema' => 'mwddns-config-backup-v1',
            'present' => array_key_exists('mwddns', $config),
            'value' => $config['mwddns'] ?? null,
            'packages' => array_values(array_filter(
                mwddns_upgrade_config_rows($config['installedpackages']['package'] ?? []),
                'mwddns_upgrade_config_package')),
            'menus' => array_values(array_filter(
                mwddns_upgrade_config_rows($config['installedpackages']['menu'] ?? []),
                'mwddns_upgrade_config_menu')),
        ];
        $json = json_encode($snapshot, JSON_THROW_ON_ERROR);
        if (strlen($json) > 8 * 1024 * 1024) { throw new RuntimeException('BACKUP_LIMIT'); }
        $handle = fopen($path, 'x');
        if ($handle === false) { throw new RuntimeException('BACKUP_FAILED'); }
        try {
            chmod($path, 0600);
            if (fwrite($handle, $json) !== strlen($json) || !fflush($handle) || !fsync($handle)) {
                throw new RuntimeException('BACKUP_FAILED');
            }
        } finally {
            fclose($handle);
        }
        return;
    }
    if (!is_file($path) || filesize($path) > 8 * 1024 * 1024) {
        throw new RuntimeException('BACKUP_REQUIRED');
    }
    $snapshot = json_decode((string)file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
    if (($snapshot['schema'] ?? '') !== 'mwddns-config-backup-v1' ||
        !is_bool($snapshot['present'] ?? null) ||
        !is_array($snapshot['packages'] ?? null) || !is_array($snapshot['menus'] ?? null)) {
        throw new RuntimeException('INVALID_STATE');
    }
    if ($action === 'reset') {
        unset($config['mwddns']);
    } else {
        if ($snapshot['present']) { $config['mwddns'] = $snapshot['value']; }
        else { unset($config['mwddns']); }
        $config['installedpackages']['package'] = mwddns_upgrade_config_restore_rows(
            $config['installedpackages']['package'] ?? [], $snapshot['packages'],
            'mwddns_upgrade_config_package');
        $config['installedpackages']['menu'] = mwddns_upgrade_config_restore_rows(
            $config['installedpackages']['menu'] ?? [], $snapshot['menus'],
            'mwddns_upgrade_config_menu');
    }
    // write_config has its own config lock. An outer lock('config') would
    // self-deadlock. Do not disable normal pfSense backup/HA write hooks.
    $saved = write_config('MWDDNS: upgrade ' . $action);
    if ($saved === false || $saved === -1) { throw new RuntimeException('CONFIG_WRITE_FAILED'); }
}

// CLI entry point
if (PHP_SAPI !== 'cli' || !function_exists('posix_geteuid') || posix_geteuid() !== 0 ||
    count($argv) !== 3) {
    exit(2);
}
umask(0077);
try {
    require_once('/etc/inc/globals.inc');
    require_once('/etc/inc/functions.inc');
    require_once('/etc/inc/config.inc');
    mwddns_upgrade_config_action($argv[1], $argv[2]);
    exit(0);
} catch (Throwable $error) {
    // No configuration values, credentials or exception text enter the GUI log.
    fwrite(STDERR, "MWDDNS configuration step failed.\n");
    exit(1);
}
