<?php
##|+PRIV
##|*IDENT=page-services-mwddns-upgrade
##|*NAME=Services: Multi-WAN DDNS: Plugin upgrade
##|*DESCR=Upload and install a trusted MWDDNS release; full administrator required.
##|*MATCH=mwddns_upgrade.php*
##|-PRIV
require_once('guiconfig.inc');
require_once('/usr/local/pkg/mwddns.inc');
require_once('/usr/local/pkg/mwddns/upgrade.inc');
if (!mwddns_upgrade_allowed()) {
    http_response_code(403);
    exit(htmlspecialchars(mwddns_t('Full administrator access is required.'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'));
}
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
function mwddns_upgrade_h(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function mwddns_upgrade_label(string $text): string { return mwddns_upgrade_h(mwddns_t($text)); }
$job = is_string($_GET['job'] ?? null) && preg_match('/^[a-f0-9]{32}$/D', $_GET['job']) ? $_GET['job'] : '';
if (isset($_GET['status'])) {
    header('Content-Type: application/json; charset=utf-8');
    try {
        if (!is_string($_GET['status'])) { throw new RuntimeException('INVALID_STATE'); }
        echo json_encode(mwddns_upgrade_status($_GET['status']), JSON_THROW_ON_ERROR);
    } catch (Throwable $error) { http_response_code(400); echo '{"state":"missing"}'; }
    exit;
}
$error = '';
$errorLabels = [
    'BUSY' => 'Another operation is running. Wait for it to finish and upload again.',
    'VERSION_NOT_NEWER' => 'Same-version installation and downgrades are not allowed.',
    'MANIFEST_REQUIRED' => 'Use a versioned release ZIP with an upgrade manifest, not a source-code ZIP.',
    'HASH_MISMATCH' => 'Package contents do not match the release manifest.',
    'ZIP_INVALID' => 'Invalid or unsupported release ZIP.',
    'VERSION_INVALID' => 'Package version information is invalid or inconsistent.',
    'ARCHIVE_LIMIT' => 'The archive exceeds safety limits or contains unsupported entries.',
    'DISK_SPACE' => 'Insufficient space. No upgrade was started.',
    'JOB_LIMIT' => 'Upload slots are full and no old upload can be safely removed. Wait for active jobs or review retained uploads.',
    'CLEANUP_FAILED' => 'An old upload could not be safely removed. Review retained uploads and retry. Persistent backups were not removed.',
    'UPLOAD_FAILED' => 'Upload failed. Check the ZIP size and the WebGUI upload limit.',
    'CONFIRMATION_REQUIRED' => 'Confirm the trusted source and the selected upgrade mode.',
    'EXPIRED' => 'This upload has expired. Upload the ZIP again.',
    'RECOVERY_REQUIRED' => 'Automatic recovery could not finish. Keep the backup and use manual recovery.',
    'INSTALL_FAILED' => 'Installation failed; the previous MWDDNS files and data were restored.',
    'RELEASE_INVALID' => 'GitHub returned invalid release information. No installation was started.',
    'ASSET_INVALID' => 'The release has no unique supported upgrade ZIP with a GitHub SHA256 digest.',
    'RELEASE_CHANGED' => 'The release changed after checking. Check the latest version again.',
    'RELEASE_EXPIRED' => 'The version check expired. Check the latest version again.',
    'REMOTE_UNAVAILABLE' => 'GitHub is unavailable or TLS verification failed. Retry later or upload a release ZIP manually.',
    'NETWORK_TIMEOUT' => 'The GitHub request timed out. No installation was started.',
    'RATE_LIMIT' => 'GitHub refused the request or its rate limit was reached. Retry later.',
    'NO_RELEASE' => 'No published release was found.',
    'DOWNLOAD_LIMIT' => 'The release download exceeds the allowed size.',

];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (!is_string($_POST['mwddns_csrf_token'] ?? null) || !mwddns_csrf_validate($_POST['mwddns_csrf_token'])) {
            throw new RuntimeException('CONFIRMATION_REQUIRED');
        }
        $action = $_POST['action'] ?? '';
        if (!is_string($action) || !in_array($action, ['upload', 'install', 'discard', 'check', 'download'], true)) {
            throw new RuntimeException('INVALID_STATE');
        }
        $job = mwddns_upgrade_action($action, $_POST, $_FILES);
        header('Location: /mwddns_upgrade.php' . ($job !== '' ? '?job=' . $job : ''), true, 303);
        exit;
    } catch (Throwable $exception) {
        $error = $errorLabels[$exception->getMessage()] ?? 'Upgrade operation failed. Check the current stage and retained backup.';
    }
}
$status = $job !== '' ? mwddns_upgrade_status($job) : ['state' => 'none'];
$labels = [
    'none' => 'Upload a release to begin.', 'checking' => 'Checking the uploaded ZIP...',
    'ready' => 'Package checked. Choose the upgrade mode and confirm.',
    'available' => 'A newer stable release is available.',
    'current' => 'No newer stable release is available.',

    'queued' => 'Queued', 'running' => 'Upgrade in progress. Do not reboot.',
    'complete' => 'Upgrade complete.', 'failed' => 'Upgrade failed.',
    'rolled_back' => 'Upgrade failed; previous MWDDNS files and data restored.',
    'recovery_required' => 'Manual recovery required.', 'missing' => 'Upload unavailable.',
    'expired' => 'Upload expired.', 'interrupted' => 'Upgrade interrupted or status is stale. Check before retrying.',
];
$stageLabels = [
    'checking' => 'Checking the uploaded ZIP...', 'ready' => 'Package ready',
    'checking_release' => 'Checking GitHub for the latest stable release...',
    'downloading' => 'Downloading and verifying the release...',
    'available' => 'A newer stable release is available.',
    'current' => 'No newer stable release is available.',

    'queued' => 'Waiting to start', 'backing_up' => 'Creating private backup',
    'installing' => 'Installing plugin files', 'resetting' => 'Clearing plugin data',
    'rolling_back' => 'Restoring previous version', 'complete' => 'Upgrade complete.',
    'rolled_back' => 'Upgrade failed; previous MWDDNS files and data restored.',
    'failed' => 'Upgrade failed.', 'recovery_required' => 'Manual recovery required.',
];
$pgtitle = [mwddns_t('Services'), mwddns_t('Multi-WAN DDNS'), mwddns_t('Plugin upgrade')];
$pglinks = ['', '/mwddns.php', '/mwddns_upgrade.php'];
include('head.inc');
?>
<body>
<?php include('fbegin.inc'); ?>
<?= mwddns_gui_styles() ?>
<style>
#mwddns-upgrade { width:100%; max-width:none; margin:0; padding:10px 20px 36px; }
#mwddns-upgrade .panel { margin-bottom:22px; border-radius:0; }
#mwddns-upgrade .panel-heading { padding:14px 22px; }
#mwddns-upgrade .panel-body { padding:22px; }
#mwddns-upgrade p, #mwddns-upgrade label { line-height:1.65; }
#mwddns-upgrade .alert { margin:0 0 18px; padding:16px 18px; }
#mwddns-upgrade .upgrade-actions { display:flex; flex-wrap:wrap; gap:10px; margin-top:20px; }
#mwddns-upgrade .upgrade-choice { display:block; padding:10px 0; font-weight:normal; }
#mwddns-upgrade input[type="radio"], #mwddns-upgrade input[type="checkbox"] { position:static; margin-right:8px; }
#mwddns-upgrade .upgrade-confirm { max-width:28em; margin:10px 0 18px; }
#mwddns-upgrade code { overflow-wrap:anywhere; }
#mwddns-upgrade .mwddns-upgrade-dialog {
    position:fixed; inset:0; width:calc(100% - 32px); max-width:36em;
    max-height:calc(100vh - 32px); margin:auto; padding:0; overflow:auto; color:inherit;
}
#mwddns-upgrade .mwddns-upgrade-dialog:not([open]) { display:none; }
#mwddns-upgrade .mwddns-upgrade-dialog::backdrop { background:rgba(0,0,0,.55); }
#mwddns-upgrade .mwddns-upgrade-dialog .upgrade-actions {
    justify-content:flex-end; margin:0; padding:16px 22px;
}
@media(max-width:767px) { #mwddns-upgrade { padding:4px 10px 24px; } #mwddns-upgrade .panel-body { padding:16px; } }
</style>
<section class="page-content-main mwddns-page"><div id="mwddns-upgrade" class="container-fluid">
<?php if ($error !== ''): ?><div class="alert alert-danger"><?= mwddns_upgrade_label($error) ?></div><?php endif; ?>
<div class="panel panel-default">
<div class="panel-heading"><h2 class="panel-title"><?= mwddns_upgrade_label('Plugin upgrade') ?></h2></div>
<div class="panel-body">
    <p><?= mwddns_upgrade_label('Installed version') ?>: <strong><?= mwddns_upgrade_h(mwddns_upgrade_version()) ?></strong></p>
    <div class="alert alert-warning"><?= mwddns_upgrade_label('Only upload releases from a source you trust. The installer runs as root. SHA256 checks detect changed files; they do not authenticate the publisher.') ?></div>
    <p><?= mwddns_upgrade_label('Uploads and working files use /tmp and may disappear on reboot. They are not permanent backups.') ?></p>
    <p><?= mwddns_upgrade_label('Keep up to 3 retained jobs plus 1 provisional check or upload. Only a validated newer ZIP can remove the oldest idle job. Failed checks preserve previous jobs; discard an unwanted provisional job to free its slot. Persistent backups are kept.') ?></p>
    <p><?= mwddns_upgrade_label('Before installation, MWDDNS data and files are backed up under /conf/mwddns-backups. Backups contain credentials, remain after reset, and must not be shared.') ?></p>
    <p><?= mwddns_upgrade_label('Do not reboot or change other pfSense configuration during installation. Only MWDDNS is paused; power loss may require manual recovery.') ?></p>
    <form method="post" enctype="multipart/form-data" action="/mwddns_upgrade.php">
        <?= mwddns_csrf_input() ?>
        <input type="hidden" name="MAX_FILE_SIZE" value="<?= MWDDNS_UPGRADE_MAX_ZIP ?>">
        <label for="upgrade-package"><?= mwddns_upgrade_label('Release ZIP (maximum 8 MiB)') ?></label>
        <input id="upgrade-package" name="package" type="file" accept=".zip,application/zip" required>
        <p class="help-block"><?= mwddns_upgrade_label('Use the versioned release ZIP. Same versions, older versions and source-code ZIPs are rejected. The WebGUI may impose a lower upload limit.') ?></p>
        <div class="upgrade-actions">
            <button class="btn btn-primary" name="action" value="upload"><?= mwddns_upgrade_label('Upload and check') ?></button>
            <a class="btn btn-default" href="/mwddns.php"><?= mwddns_upgrade_label('Back to rules') ?></a>
        </div>
    </form>
</div></div>
<div class="panel panel-default">
<div class="panel-heading"><h2 class="panel-title"><?= mwddns_upgrade_label('GitHub releases') ?></h2></div>
<div class="panel-body">
    <p><?= mwddns_upgrade_label('Check the latest stable release from yatounoneko/pfSense-MWDDNS. No scheduled checks or automatic installation are enabled.') ?></p>
    <p class="help-block"><?= mwddns_upgrade_label('Checking and downloading contact GitHub over verified HTTPS. No configuration, logs or credentials are uploaded. Direct Internet access is required; environment proxies are not used.') ?></p>
    <form method="post" action="/mwddns_upgrade.php">
        <?= mwddns_csrf_input() ?>
        <button class="btn btn-default" name="action" value="check"><i class="fa-solid fa-arrows-rotate" aria-hidden="true"></i> <?= mwddns_upgrade_label('Check latest version') ?></button>
        <a class="btn btn-default" href="https://github.com/yatounoneko/pfSense-MWDDNS/releases/latest" target="_blank" rel="noopener noreferrer"><?= mwddns_upgrade_label('Open latest release') ?></a>
    </form>
<?php if (in_array($status['state'], ['available', 'current'], true) && preg_match('/^\\d+\\.\\d+\\.\\d+$/D', $status['version'] ?? '')): ?>
    <p style="margin-top:16px"><?= mwddns_upgrade_label('Latest checked version') ?>:
        <strong><?= mwddns_upgrade_h($status['version']) ?></strong></p>
    <p><?= mwddns_upgrade_label($labels[$status['state']]) ?></p>
<?php if ($status['state'] === 'available'): ?>
    <form method="post" action="/mwddns_upgrade.php">
        <?= mwddns_csrf_input() ?><input type="hidden" name="job" value="<?= $job ?>">
        <button class="btn btn-primary" name="action" value="download"><i class="fa-solid fa-download" aria-hidden="true"></i> <?= mwddns_upgrade_label('Download and check this release') ?></button>
    </form>
    <p class="help-block"><?= mwddns_upgrade_label('Downloading does not install anything. After verification, choose whether to preserve data and confirm the upgrade below.') ?></p>
<?php endif; ?>
<?php endif; ?>
</div></div>
<div class="panel panel-default">
<div class="panel-heading"><h2 class="panel-title"><?= mwddns_upgrade_label('Upgrade status') ?></h2></div>
<div class="panel-body">
    <p role="status"><strong><?= mwddns_upgrade_label($labels[$status['state']] ?? 'Upload unavailable.') ?></strong></p>
<?php if (isset($status['stage'])): ?>
    <p><?= mwddns_upgrade_label('Stage') ?>: <?= mwddns_upgrade_label($stageLabels[$status['stage']] ?? 'Unknown stage') ?>
        <small><code><?= mwddns_upgrade_h($status['stage']) ?></code></small></p>
<?php endif; ?>
<?php if (isset($status['error'])): ?>
    <div class="alert alert-warning"><?= mwddns_upgrade_label($errorLabels[$status['error']] ?? 'Upgrade operation failed. Check the current stage and retained backup.') ?>
    <code><?= mwddns_upgrade_h($status['error']) ?></code></div>
<?php endif; ?>
<?php if (isset($status['version'])): ?>
    <p><?= mwddns_upgrade_label('Uploaded version') ?>: <strong><?= mwddns_upgrade_h($status['version']) ?></strong></p>
<?php endif; ?>
<?php if (isset($status['sha256'])): ?>
    <p>SHA256: <code><?= mwddns_upgrade_h($status['sha256']) ?></code></p>
<?php endif; ?>
<?php if (isset($status['backup'])): ?>
    <p><?= mwddns_upgrade_label('Private backup') ?>: <code>/conf/mwddns-backups/<?= mwddns_upgrade_h($status['backup']) ?></code></p>
<?php endif; ?>
<?php if ($status['state'] === 'ready'): ?>
    <div id="mwddns-upgrade-choice-error" class="alert alert-danger" role="alert" hidden></div>
    <form id="mwddns-upgrade-install-form" method="post" action="/mwddns_upgrade.php" novalidate>
        <?= mwddns_csrf_input() ?><input type="hidden" name="job" value="<?= $job ?>">
        <input type="hidden" name="action" value="install">
        <label class="upgrade-choice"><input type="radio" name="mode" value="preserve" checked>
            <?= mwddns_upgrade_label('Keep all MWDDNS data (default)') ?></label>
        <label class="upgrade-choice"><input type="radio" name="mode" value="reset">
            <?= mwddns_upgrade_label('Back up, then clear all MWDDNS rules, credentials, preferences and runtime data') ?></label>
        <label for="upgrade-confirm"><?= mwddns_upgrade_label('For reset mode, type CLEAR MWDDNS. Other pfSense settings are not cleared.') ?></label>
        <input class="form-control upgrade-confirm" id="upgrade-confirm" name="confirmation" autocomplete="off" spellcheck="false">
        <label class="upgrade-choice"><input type="checkbox" name="trusted" value="yes" required>
            <?= mwddns_upgrade_label('I trust this package and authorize its installer to run as root.') ?></label>
        <div class="upgrade-actions"><button id="mwddns-upgrade-open-confirm" type="submit" class="btn btn-danger no-confirm"><?= mwddns_upgrade_label('Upgrade now') ?></button></div>
    </form>
    <dialog id="mwddns-upgrade-confirm-dialog" class="panel panel-default modal-content mwddns-upgrade-dialog"
            aria-labelledby="mwddns-upgrade-confirm-title" aria-describedby="mwddns-upgrade-confirm-mode">
        <div class="panel-heading"><h2 id="mwddns-upgrade-confirm-title" class="panel-title"><?= mwddns_upgrade_label('Confirm upgrade') ?></h2></div>
        <div class="panel-body">
            <p><?= mwddns_upgrade_label('Uploaded version') ?>: <strong><?= mwddns_upgrade_h($status['version'] ?? '') ?></strong></p>
            <p id="mwddns-upgrade-confirm-mode"></p>
            <p><?= mwddns_upgrade_label('No changes are made until you confirm.') ?></p>
            <p><?= mwddns_upgrade_label('Do not reboot or change other pfSense configuration during installation. Only MWDDNS is paused; power loss may require manual recovery.') ?></p>
        </div>
        <div class="panel-footer upgrade-actions">
            <button id="mwddns-upgrade-cancel" type="button" class="btn btn-default" autofocus><?= mwddns_upgrade_label('Cancel') ?></button>
            <button id="mwddns-upgrade-confirm-submit" type="button" class="btn btn-danger no-confirm"><?= mwddns_upgrade_label('Upgrade now') ?></button>
        </div>
    </dialog>
<?php endif; ?>
<?php if ($job !== ''): ?>
    <div class="upgrade-actions">
        <a class="btn btn-default" href="/mwddns_upgrade.php?job=<?= $job ?>"><?= mwddns_upgrade_label('Refresh status') ?></a>
<?php if (!in_array($status['state'], ['checking', 'queued', 'running'], true)): ?>
        <form method="post" action="/mwddns_upgrade.php">
            <?= mwddns_csrf_input() ?><input type="hidden" name="job" value="<?= $job ?>">
            <button class="btn btn-default" name="action" value="discard"><?= mwddns_upgrade_label('Discard temporary upload (keep backup)') ?></button>
        </form>
<?php endif; ?>
    </div>
<?php endif; ?>
</div></div>
<div class="panel panel-default">
<div class="panel-heading"><h2 class="panel-title"><?= mwddns_upgrade_label('Recent uploads') ?></h2></div>
<div class="panel-body"><ul>
<?php foreach (mwddns_upgrade_jobs() as $id => $row): ?>
    <li><a href="/mwddns_upgrade.php?job=<?= $id ?>"><?= mwddns_upgrade_h(
        date('Y-m-d H:i:s', $row['started'] ?? 0) . ' / ' . ($row['version'] ?? '?')) ?></a>
        <?= mwddns_upgrade_label($labels[$row['state']] ?? 'Upload unavailable.') ?></li>
<?php endforeach; ?>
</ul></div></div>
</div></section>
<script>
(function () {
    var form = document.getElementById('mwddns-upgrade-install-form');
    var dialog = document.getElementById('mwddns-upgrade-confirm-dialog');
    if (!form || !dialog) { return; }
    var trigger = document.getElementById('mwddns-upgrade-open-confirm');
    var cancel = document.getElementById('mwddns-upgrade-cancel');
    var submit = document.getElementById('mwddns-upgrade-confirm-submit');
    var error = document.getElementById('mwddns-upgrade-choice-error');
    var pendingMode = null;
    var labels = <?= json_encode([
        'trusted' => mwddns_t('Please confirm that you trust this package.'),
        'mode' => mwddns_t('Choose an upgrade mode.'),
        'clear' => mwddns_t('To clear plugin data, enter CLEAR MWDDNS exactly.'),
        'changed' => mwddns_t('Upgrade choices changed. Review and confirm again.'),
        'preserve' => mwddns_t('Confirm upgrade while keeping all MWDDNS data.'),
        'reset' => mwddns_t('Confirm upgrade after backing up and clearing all MWDDNS data.'),
    ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    function showError(message, control) {
        error.textContent = message;
        error.hidden = false;
        if (control) { control.focus(); }
    }
    function validate() {
        var mode = form.querySelector('input[name="mode"]:checked');
        if (!mode || (mode.value !== 'preserve' && mode.value !== 'reset')) {
            showError(labels.mode, trigger);
            return null;
        }
        if (!form.elements.trusted.checked) {
            showError(labels.trusted, form.elements.trusted);
            return null;
        }
        if (mode.value === 'reset' && form.elements.confirmation.value !== 'CLEAR MWDDNS') {
            showError(labels.clear, form.elements.confirmation);
            return null;
        }
        error.hidden = true;
        return mode.value;
    }
    function closeDialog() {
        if (typeof dialog.close === 'function') {
            dialog.close();
        } else {
            dialog.removeAttribute('open');
            trigger.focus();
        }
        pendingMode = null;
    }
    form.addEventListener('submit', function (event) {
        event.preventDefault();
        var mode = validate();
        if (!mode || dialog.hasAttribute('open')) { return; }
        pendingMode = mode;
        document.getElementById('mwddns-upgrade-confirm-mode').textContent = labels[mode];
        if (typeof dialog.showModal === 'function') {
            dialog.showModal();
        } else {
            dialog.setAttribute('open', '');
        }
        cancel.focus();
    });
    cancel.addEventListener('click', closeDialog);
    dialog.addEventListener('close', function () {
        pendingMode = null;
        if (!trigger.disabled) { trigger.focus(); }
    });
    submit.addEventListener('click', function () {
        var expected = pendingMode;
        closeDialog();
        var mode = validate();
        if (!mode) { return; }
        if (mode !== expected) {
            showError(labels.changed, trigger);
            return;
        }
        trigger.disabled = true;
        submit.disabled = true;
        // The hidden action survives disabled buttons. Authorization, CSRF,
        // version checks and the exact reset phrase are rechecked by the server.
        HTMLFormElement.prototype.submit.call(form);
    });
}());
</script>
<?php if (in_array($status['state'], ['checking', 'queued', 'running'], true)): ?>
<script>
(function () {
    var count = 0;
    var job = <?= json_encode($job, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    function poll() {
        if (++count > 180) { return; }
        fetch('/mwddns_upgrade.php?status=' + job, {credentials:'same-origin', cache:'no-store'})
            .then(function (r) { if (!r.ok) { throw new Error('status'); } return r.json(); })
            .then(function (r) {
                if (r.state === 'checking' || r.state === 'queued' || r.state === 'running') {
                    window.setTimeout(poll, 3000);
                } else { window.location.replace('/mwddns_upgrade.php?job=' + job); }
            })
            .catch(function () { window.setTimeout(poll, 5000); });
    }
    window.setTimeout(poll, 2000);
}());
</script>
<?php endif; ?>
<?php include('foot.inc'); ?>
