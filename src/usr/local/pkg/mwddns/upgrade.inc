<?php
define('MWDDNS_UPGRADE_DIR', '/tmp/mwddns-upgrade');
define('MWDDNS_UPGRADE_MAX_ZIP', 8 * 1024 * 1024);

function mwddns_upgrade_allowed(): bool
{
    $name = $_SESSION['Username'] ?? null;
    if (!is_string($name) || $name === '' || !function_exists('isAdminUID')) { return false; }
    if (isAdminUID($name)) { return true; }
    if (!function_exists('getUserEntry') || !function_exists('userHasPrivilege')) { return false; }
    $entry = getUserEntry($name);
    $user = $entry['item'] ?? null;
    return is_array($user) && userHasPrivilege($user, 'page-all') &&
        !userHasPrivilege($user, 'user-config-readonly');
}
function mwddns_upgrade_version(): string
{
    $path = '/usr/local/pkg/mwddns.xml';
    if (is_link($path) || !is_file($path) || filesize($path) > 65536) { return 'unknown'; }
    $xml = (string)file_get_contents($path);
    return preg_match('/<version>(\d+\.\d+\.\d+)<\/version>/', $xml, $match) ? $match[1] : 'unknown';
}
function mwddns_upgrade_directory(): void
{
    $old = umask(0077);
    try {
        if (is_link(MWDDNS_UPGRADE_DIR) ||
            (!is_dir(MWDDNS_UPGRADE_DIR) && !mkdir(MWDDNS_UPGRADE_DIR, 0700)) ||
            fileowner(MWDDNS_UPGRADE_DIR) !== 0 || (fileperms(MWDDNS_UPGRADE_DIR) & 0077) !== 0) {
            throw new RuntimeException('UNSAFE_DIRECTORY');
        }
    } finally { umask($old); }
}
function mwddns_upgrade_path(string $id): string
{
    if (!preg_match('/^[a-f0-9]{32}$/D', $id)) { throw new RuntimeException('INVALID_STATE'); }
    $path = MWDDNS_UPGRADE_DIR . '/job-' . $id;
    if (is_link(MWDDNS_UPGRADE_DIR) || is_link($path)) { throw new RuntimeException('UNSAFE_DIRECTORY'); }
    return $path;
}
function mwddns_upgrade_write(string $path, array $value): void
{
    if (is_link($path) || is_link($path . '.tmp')) { throw new RuntimeException('UNSAFE_FILE'); }
    $old = umask(0077);
    try {
        $raw = json_encode($value, JSON_THROW_ON_ERROR) . "\n";
        if (file_put_contents($path . '.tmp', $raw) !== strlen($raw) || !rename($path . '.tmp', $path)) {
            throw new RuntimeException('STORAGE_FAILED');
        }
    } finally { umask($old); }
}
function mwddns_upgrade_refresh_cache(string $id): void
{
    if (!function_exists('opcache_invalidate')) { return; }
    $root = mwddns_upgrade_path($id);
    $marker = $root . '/opcache.done';
    if (!is_dir($root) || fileowner($root) !== 0 || (fileperms($root) & 0077) !== 0 ||
        is_link($marker) || (file_exists($marker) && !is_file($marker))) { return; }
    $old = umask(0077);
    try { $handle = @fopen($marker, 'c+'); }
    finally { umask($old); }
    if ($handle === false) { return; }
    try {
        if (!flock($handle, LOCK_EX | LOCK_NB) || fread($handle, 4) === 'done') { return; }
        foreach (array_merge(
            ['/usr/local/pkg/mwddns.inc', '/usr/local/www/mwddns.php',
             '/usr/local/www/mwddns_edit.php', '/usr/local/www/mwddns_debug.php',
             '/usr/local/www/mwddns_upgrade.php', '/usr/local/www/widgets/widgets/mwddns.widget.php'],
            glob('/usr/local/pkg/mwddns/*.inc') ?: [], glob('/usr/local/pkg/mwddns/*.php') ?: [],
            glob('/usr/local/pkg/mwddns/locale/*.php') ?: []
        ) as $file) {
            if (function_exists('opcache_is_script_cached') && !opcache_is_script_cached($file)) { continue; }
            if (!@opcache_invalidate($file, true)) { return; }
        }
        rewind($handle);
        fwrite($handle, 'done');
        fflush($handle);
    } finally { fclose($handle); }
}
function mwddns_upgrade_status(string $id): array
{
    $path = mwddns_upgrade_path($id) . '/status.json';
    if (is_link($path) || !is_file($path) || filesize($path) > 65536) { return ['state' => 'missing']; }
    $raw = json_decode((string)file_get_contents($path), true);
    if (!is_array($raw)) { return ['state' => 'missing']; }
    $states = ['checking', 'available', 'current', 'ready', 'queued', 'running', 'complete', 'failed', 'rolled_back', 'recovery_required'];
    $result = ['state' => in_array($raw['state'] ?? '', $states, true) ? $raw['state'] : 'missing',
        'started' => (int)($raw['started'] ?? 0)];
    foreach (['stage', 'error', 'version', 'previous_version', 'sha256', 'backup', 'mode'] as $key) {
        if (is_string($raw[$key] ?? null) && preg_match('/^[a-zA-Z0-9_.-]{1,100}$/D', $raw[$key])) {
            $result[$key] = $raw[$key];
        }
    }
    if (in_array($result['state'], ['checking', 'queued', 'running'], true) && time() - $result['started'] > 900) {
        $result['state'] = 'interrupted';
    } elseif ($result['state'] === 'available' && time() - $result['started'] >= 3600) {
        $result['state'] = 'expired';
    } elseif ($result['state'] === 'ready' && time() - $result['started'] >= 86400) {
        $result['state'] = 'expired';
    }
    if ($result['state'] === 'complete') { mwddns_upgrade_refresh_cache($id); }
    return $result;
}
function mwddns_upgrade_jobs(): array
{
    if (is_link(MWDDNS_UPGRADE_DIR)) { return []; }
    $jobs = [];
    foreach (glob(MWDDNS_UPGRADE_DIR . '/job-*', GLOB_ONLYDIR) ?: [] as $path) {
        $id = substr(basename($path), 4);
        if (!is_link($path) && preg_match('/^[a-f0-9]{32}$/D', $id)) { $jobs[$id] = mwddns_upgrade_status($id); }
    }
    uasort($jobs, static fn(array $a, array $b): int => ($b['started'] ?? 0) <=> ($a['started'] ?? 0));
    return $jobs;
}
function mwddns_upgrade_record_start_failure(string $action, string $path): void
{
    if (!in_array($action, ['inspect', 'install', 'check', 'download'], true)) { return; }
    $lockPath = $path . '/worker.lock';
    if (is_link($lockPath)) { return; }
    $old = umask(0077);
    try { $lock = fopen($lockPath, 'c'); }
    finally { umask($old); }
    if ($lock === false) { return; }
    try {
        // A failed launcher may still have started a worker. Never overwrite it.
        if (!flock($lock, LOCK_EX | LOCK_NB)) { return; }
        $statusPath = $path . '/status.json';
        if (is_link($statusPath) || !is_file($statusPath) || filesize($statusPath) > 65536) { return; }
        // Read the persisted state, without the GUI's age-based status mapping.
        $status = json_decode((string)file_get_contents($statusPath), true);
        $expected = $action === 'install' ? 'queued' : 'checking';
        if (!is_array($status) || ($status['state'] ?? '') !== $expected) { return; }
        $status['state'] = 'failed';
        $status['stage'] = 'failed';
        $status['error'] = 'START_FAILED';
        mwddns_upgrade_write($statusPath, $status);
    } finally { fclose($lock); }
}
function mwddns_upgrade_spawn(string $action, string $id): void
{
    if (!in_array($action, ['inspect', 'install', 'discard', 'check', 'download'], true)) { throw new RuntimeException('INVALID_STATE'); }
    $path = mwddns_upgrade_path($id);
    try {
        if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }
        $process = proc_open([
            '/usr/sbin/daemon', '-f', '-p', $path . '/worker.pid',
            '/usr/local/bin/python3.11', '-B', '/usr/local/bin/mwddns_upgrade.py', $action, $id,
        ], [
            0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w'],
        ], $pipes);
        if (!is_resource($process) || proc_close($process) !== 0) { throw new RuntimeException('START_FAILED'); }
    } catch (Throwable $error) {
        try { mwddns_upgrade_record_start_failure($action, $path); }
        catch (Throwable $ignored) { /* Keep launcher/storage details out of the public error. */ }
        throw new RuntimeException('START_FAILED');
    }
}
function mwddns_upgrade_action(string $action, array $post, array $files): string
{
    if (!mwddns_upgrade_allowed()) { throw new RuntimeException('FORBIDDEN'); }
    mwddns_upgrade_directory();
    $lockPath = MWDDNS_UPGRADE_DIR . '/admission.lock';
    if (is_link($lockPath)) { throw new RuntimeException('UNSAFE_FILE'); }
    $old = umask(0077);
    $lock = fopen($lockPath, 'c');
    umask($old);
    if ($lock === false) { throw new RuntimeException('STORAGE_FAILED'); }
    try {
        if (!flock($lock, LOCK_EX | LOCK_NB)) { throw new RuntimeException('BUSY'); }
        if ($action === 'check') {
            if (count(mwddns_upgrade_jobs()) >= 4) { throw new RuntimeException('JOB_LIMIT'); }
            $id = bin2hex(random_bytes(16));
            $path = mwddns_upgrade_path($id);
            if (!mkdir($path, 0700)) { throw new RuntimeException('STORAGE_FAILED'); }
            try {
                mwddns_upgrade_write($path . '/status.json', [
                    'state' => 'checking', 'stage' => 'checking_release', 'started' => time(),
                ]);
            } catch (Throwable $error) {
                foreach (['status.json.tmp', 'status.json'] as $name) {
                    if (is_file($path . '/' . $name)) { @unlink($path . '/' . $name); }
                }
                @rmdir($path);
                throw $error;
            }
            mwddns_upgrade_spawn('check', $id);
            return $id;
        }
        if ($action === 'upload') {
            $file = $files['package'] ?? [];
            if (!is_array($file) || ($file['error'] ?? -1) !== UPLOAD_ERR_OK ||
                !is_string($file['tmp_name'] ?? null) || !is_uploaded_file($file['tmp_name']) ||
                filesize($file['tmp_name']) > MWDDNS_UPGRADE_MAX_ZIP || filesize($file['tmp_name']) < 1) {
                throw new RuntimeException('UPLOAD_FAILED');
            }
            // One provisional slot preserves all three old jobs until ZIP validation.
            if (count(mwddns_upgrade_jobs()) >= 4) { throw new RuntimeException('JOB_LIMIT'); }
            if (disk_free_space(MWDDNS_UPGRADE_DIR) < MWDDNS_UPGRADE_MAX_ZIP * 2) { throw new RuntimeException('DISK_SPACE'); }
            $id = bin2hex(random_bytes(16));
            $path = mwddns_upgrade_path($id);
            if (!mkdir($path, 0700)) { throw new RuntimeException('UPLOAD_FAILED'); }
            try {
                if (!move_uploaded_file($file['tmp_name'], $path . '/upload.zip')) {
                    throw new RuntimeException('UPLOAD_FAILED');
                }
                chmod($path . '/upload.zip', 0600);
                mwddns_upgrade_write($path . '/status.json', ['state' => 'checking', 'stage' => 'checking', 'started' => time()]);
            } catch (Throwable $error) {
                // Only this new job exists here; no worker has been launched.
                // Remove known temporary files without traversing any directory.
                foreach (['status.json.tmp', 'status.json', 'upload.zip'] as $name) {
                    $temporary = $path . '/' . $name;
                    if (is_file($temporary) || is_link($temporary)) { @unlink($temporary); }
                }
                @rmdir($path);
                throw $error;
            }
            // A launch failure may still have started a worker. Keep its job.
            mwddns_upgrade_spawn('inspect', $id);
            return $id;
        }
        if (!is_string($post['job'] ?? null)) { throw new RuntimeException('INVALID_STATE'); }
        $id = $post['job'];
        $path = mwddns_upgrade_path($id);
        $status = mwddns_upgrade_status($id);
        if ($action === 'download') {
            if ($status['state'] !== 'available') { throw new RuntimeException('INVALID_STATE'); }
            if (disk_free_space(MWDDNS_UPGRADE_DIR) < MWDDNS_UPGRADE_MAX_ZIP * 2) { throw new RuntimeException('DISK_SPACE'); }
            $status['state'] = 'checking';
            $status['stage'] = 'downloading';
            $status['started'] = time();
            mwddns_upgrade_write($path . '/status.json', $status);
            mwddns_upgrade_spawn('download', $id);
            return $id;
        }
        if ($action === 'discard') {
            if (in_array($status['state'], ['checking', 'queued', 'running'], true)) { throw new RuntimeException('BUSY'); }
            mwddns_upgrade_spawn('discard', $id);
            return '';
        }
        if ($action !== 'install' || $status['state'] !== 'ready' ||
            !is_string($post['mode'] ?? null) || !in_array($post['mode'], ['preserve', 'reset'], true) ||
            ($post['trusted'] ?? '') !== 'yes') { throw new RuntimeException('CONFIRMATION_REQUIRED'); }
        $confirmation = is_string($post['confirmation'] ?? null) ? $post['confirmation'] : '';
        if ($post['mode'] === 'reset' && $confirmation !== 'CLEAR MWDDNS') { throw new RuntimeException('CONFIRMATION_REQUIRED'); }
        if (mwddns_upgrade_version() === 'unknown' ||
            version_compare($status['version'] ?? '0', mwddns_upgrade_version(), '<=')) {
            throw new RuntimeException('VERSION_NOT_NEWER');
        }
        mwddns_upgrade_write($path . '/request.json', ['mode' => $post['mode'], 'trusted' => true, 'confirmation' => $confirmation]);
        $status['state'] = 'queued';
        $status['stage'] = 'queued';
        mwddns_upgrade_write($path . '/status.json', $status);
        mwddns_upgrade_spawn('install', $id);
        return $id;
    } finally { flock($lock, LOCK_UN); fclose($lock); }
}
