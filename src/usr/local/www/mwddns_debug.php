<?php
##|+PRIV
##|*IDENT=page-services-mwddns-debug
##|*NAME=Services: Multi-WAN DDNS: Debug information
##|*DESCR=Collect and download sanitized Multi-WAN DDNS diagnostics.
##|*MATCH=mwddns_debug.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/mwddns.inc');
require_once('/usr/local/pkg/mwddns/debug.inc');

function mwddns_debug_h(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function mwddns_debug_label(string $text): string
{
    return mwddns_debug_h(mwddns_t($text));
}
function mwddns_debug_time(string $timestamp): string
{
    $escaped = mwddns_debug_h($timestamp);
    return '<time class="mwddns-debug-timestamp" datetime="' . $escaped .
        '" title="' . $escaped . '">' . $escaped . '</time>';
}

$error = '';
$settings = mwddns_debug_settings();
$job = is_string($_GET['job'] ?? null) && preg_match('/^[a-f0-9]{32}$/D', $_GET['job'])
    ? $_GET['job'] : '';

// Authentication/authorization above also applies to polling and downloads.
if (isset($_GET['status'])) {
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    try {
        if (!is_string($_GET['status'])) {
            throw new RuntimeException('Invalid debug report.');
        }
        echo json_encode(mwddns_debug_status($_GET['status']), JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        http_response_code(400);
        echo '{"state":"missing"}';
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (!is_string($_POST['mwddns_csrf_token'] ?? null) ||
            !mwddns_csrf_validate($_POST['mwddns_csrf_token'])) {
            throw new RuntimeException('Invalid request token. Please reload the page and try again.');
        }
        $action = $_POST['action'] ?? '';
        if (!is_string($action) || !in_array($action, ['save', 'collect', 'download', 'diagnostics', 'delete'], true)) {
            throw new RuntimeException('Invalid debug settings.');
        }
        if ($action === 'save' || $action === 'collect') {
            $settings = mwddns_debug_save($_POST);
            if (session_status() === PHP_SESSION_ACTIVE) {
                session_write_close();
            }
            if ($action === 'collect') {
                $job = mwddns_debug_start($settings);
                header('Location: /mwddns_debug.php?job=' . $job, true, 303);
            } else {
                header('Location: /mwddns_debug.php?saved=1', true, 303);
            }
            exit;
        }
        if (!is_string($_POST['job'] ?? null)) {
            throw new RuntimeException('Invalid debug report.');
        }
        $job = $_POST['job'];
        if ($action === 'delete') {
            mwddns_debug_remove($job);
            header('Location: /mwddns_debug.php', true, 303);
            exit;
        }
        if ($action === 'diagnostics') {
            $diagnostic = mwddns_debug_diagnostic_report($job);
            $downloadName = 'mwddns-debug-diagnostics-' .
                date('Y-m-d_H-i-s', strtotime($diagnostic['generated_at'])) . '.json';
            $json = json_encode($diagnostic, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n";
            if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }
            header('Content-Type: application/json; charset=utf-8');
            header('Content-Disposition: attachment; filename="' . $downloadName . '"');
            header('X-Content-Type-Options: nosniff');
            header('Cache-Control: no-store');
            echo $json;
            exit;
        }
        $path = mwddns_debug_report_path($job);
        // The collector uses this same job timestamp for report.generated_at.
        // Do not substitute the download time: an existing report is immutable.
        $generated = mwddns_debug_status($job)['started'];
        if ($generated < 1) {
            throw new RuntimeException('Invalid debug report.');
        }
        $downloadName = 'mwddns-debug-' . date('Y-m-d_H-i-s', $generated) . '.json';
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $downloadName . '"');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');
        readfile($path);
        exit;
    } catch (Throwable $e) {
        $allowedErrors = [
            'Invalid debug settings.', 'Invalid debug report.',
            'Debug storage is unavailable.', 'Debug collector could not be started.',
            'Debug collection is already running.', 'Debug report is unavailable or expired.',
            'Invalid request token. Please reload the page and try again.',
            'Configuration changed. Reload the page before saving.',
            'Configuration could not be saved. No DNS update was started.',
            'Another MWDDNS operation is running. Please retry later.',
        ];
        $error = in_array($e->getMessage(), $allowedErrors, true)
            ? $e->getMessage() : 'Debug operation failed.';
        if (!preg_match('/^[a-f0-9]{32}$/D', $job)) {
            $job = '';
        }
    }
}

$status = $job !== '' ? mwddns_debug_status($job) : ['state' => 'none'];
$recentReports = mwddns_debug_jobs();
$preview = '';
$previewLimited = false;
$sourceSummary = [];
if ($status['state'] === 'complete') {
    try {
        $path = mwddns_debug_report_path($job);
        $reportJson = file_get_contents($path, false, null, 0, MWDDNS_DEBUG_MAX_REPORT + 1);
        if (!is_string($reportJson) || strlen($reportJson) > MWDDNS_DEBUG_MAX_REPORT) {
            throw new RuntimeException('Debug report is unavailable or expired.');
        }
        $previewLimited = strlen($reportJson) > 131072;
        $preview = substr($reportJson, 0, 131072);
        $sourceSummary = mwddns_debug_summary($reportJson);
        unset($reportJson);
    } catch (Throwable $e) {
        $status = ['state' => 'missing'];
    }
}
$stateLabels = [
    'none' => 'No report selected.', 'queued' => 'Queued', 'running' => 'Collecting',
    'complete' => 'Report ready', 'failed' => 'Collection failed. Open the diagnostics for the recorded reason.',
    'expired' => 'Report expired.', 'missing' => 'Report unavailable.',
];
$diagnosticLabels = mwddns_debug_diagnostic_labels();
$diagnosticFields = [
    'stage' => 'Last collector stage', 'error_code' => 'Recorded failure reason',
    'elapsed_seconds' => 'Elapsed seconds at checkpoint',
    'cpu_seconds' => 'Collector CPU seconds at checkpoint', 'requested_days' => 'Requested days',
];
$sourceProgressFields = ['source', 'file_index', 'record_index', 'record_bytes',
    'source_bytes_scanned', 'matched_events', 'candidate_event_groups'];
$diagnosticTimes = ['checkpoint_at' => 'Last checkpoint time'];
if ($status['state'] === 'complete') {
    $diagnosticFields += [
        'total_sources' => 'Sources included', 'total_files_scanned' => 'Total files scanned',
        'total_bytes_scanned' => 'Total bytes scanned', 'total_matched_events' => 'Total matched events',
        'total_retained_events' => 'Total retained events', 'total_dropped_events' => 'Total dropped events',
        'total_event_groups' => 'Total event groups',
    ];
} else {
    $diagnosticFields += [
        'source' => 'Last collector source', 'file_index' => 'Rotation scan index',
        'record_index' => 'Record scan index', 'record_bytes' => 'Last record bytes',
        'source_bytes_scanned' => 'Source bytes scanned', 'matched_events' => 'Source matched events',
        'candidate_event_groups' => 'Source candidate groups', 'collector_line' => 'Collector code line',
    ];
    $diagnosticTimes['record_epoch'] = 'Last record timestamp';
}
$diagnosticTranslations = [];
foreach ($diagnosticLabels as $key => $values) {
    foreach ($values as $code => $label) { $diagnosticTranslations[$key][$code] = mwddns_t($label); }
}
$pgtitle = [mwddns_t('Services'), mwddns_t('Multi-WAN DDNS'), mwddns_t('Debug information')];
$pglinks = ['', '/mwddns.php', '/mwddns_debug.php'];
include('head.inc');
?>
<body>
<?php include('fbegin.inc'); ?>
<?= mwddns_gui_styles() ?>
<style>
/* Scope every override: pfSense themes may remove Bootstrap panel padding. */
#mwddns-debug {
    --mwddns-debug-border: rgba(127, 127, 127, .32);
    --mwddns-debug-tint: rgba(127, 127, 127, .07);
    width: 100%;
    max-width: none;
    margin: 0;
    padding: 8px 20px 36px;
    box-sizing: border-box;
}
#mwddns-debug .panel {
    margin-bottom: 22px;
    border-radius: 0;
    border: 1px solid var(--mwddns-debug-border);
}
#mwddns-debug .panel > .panel-heading {
    padding: 14px 22px;
    border-radius: 0;
}
#mwddns-debug .panel > .panel-body {
    padding: 22px;
    min-width: 0;
}
#mwddns-debug .panel-title { line-height: 1.45; }
#mwddns-debug p { line-height: 1.65; margin: 0 0 14px; }
#mwddns-debug .alert { margin: 0 0 20px; padding: 16px 18px; line-height: 1.65; }
#mwddns-debug .mwddns-debug-fields {
    display: grid;
    grid-template-columns: minmax(0, .8fr) minmax(0, 1.2fr);
    gap: 20px;
    margin: 24px 0 18px;
}
#mwddns-debug .mwddns-debug-field {
    min-width: 0;
    margin: 0;
    padding: 18px;
    border: 1px solid var(--mwddns-debug-border);
    border-radius: 0;
    background: var(--mwddns-debug-tint);
}
#mwddns-debug .mwddns-debug-field > label,
#mwddns-debug .mwddns-debug-field-title {
    display: block;
    margin: 0 0 12px;
    font-weight: 600;
}
#mwddns-debug #debug-days { width: 100%; max-width: 12em; margin: 0 0 12px; }
#mwddns-debug .help-block { margin: 10px 0 0; line-height: 1.65; }
#mwddns-debug .mwddns-debug-source {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 8px 0;
    margin: 0;
    line-height: 1.6;
    font-weight: normal;
    cursor: pointer;
}
#mwddns-debug .mwddns-debug-source input[type="checkbox"] {
    position: static;
    float: none;
    flex: 0 0 auto;
    margin: 5px 0 0;
}
#mwddns-debug .mwddns-debug-actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    margin: 20px 0 0;
    padding: 18px 0 0;
    border-top: 1px solid var(--mwddns-debug-border);
}
#mwddns-debug .mwddns-debug-actions .btn { margin: 0; white-space: normal; }
#mwddns-debug .mwddns-debug-actions form { display: contents; }
#mwddns-debug .mwddns-debug-status { font-size: 1.1em; font-weight: 600; }
#mwddns-debug .mwddns-debug-result-notes { margin-top: 20px; }
#mwddns-debug details > summary { cursor: pointer; }
#mwddns-debug details > summary .panel-title { display: inline; margin-left: 6px; }
#mwddns-debug details:not([open]) > .panel-heading { border-bottom: 0; border-radius: 0; }
#mwddns-debug summary:focus-visible { outline: 2px solid currentColor; outline-offset: 3px; }
#mwddns-debug .table-responsive {
    margin: 18px 0 0;
    border: 1px solid var(--mwddns-debug-border);
    border-radius: 0;
}
#mwddns-debug table { margin: 0; width: 100%; }
#mwddns-debug table > thead > tr > th,
#mwddns-debug table > tbody > tr > td { padding: 12px 14px; overflow-wrap: anywhere; }
#mwddns-debug .mwddns-debug-history .table-responsive { overflow-x: auto; }
#mwddns-debug .mwddns-debug-history table { min-width: 52rem; }
#mwddns-debug .mwddns-debug-history th { white-space: nowrap; }
#mwddns-debug .mwddns-debug-history time { display: inline-block; white-space: nowrap; }
#mwddns-debug .mwddns-debug-history td { vertical-align: middle; }
#mwddns-debug .mwddns-debug-history-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
}
#mwddns-debug .mwddns-debug-history-actions form { margin: 0; }
#mwddns-debug .mwddns-debug-history-actions .btn { white-space: nowrap; }
#mwddns-debug .mwddns-debug-preview { margin: 24px 0 0; }
#mwddns-debug .mwddns-debug-preview-title { margin: 0 0 12px; font-size: 1em; font-weight: 600; }
#mwddns-debug .mwddns-debug-summary { margin-top: 22px; }
#mwddns-debug .mwddns-debug-summary .table-responsive {
    max-width: 100%;
    overflow-x: auto;
    overscroll-behavior-x: contain;
}
#mwddns-debug .mwddns-debug-summary table { min-width: 86rem; table-layout: auto; }
#mwddns-debug .mwddns-debug-summary th { font-size: .9em; white-space: nowrap; }
#mwddns-debug .mwddns-debug-summary td {
    font-size: .9em;
    vertical-align: top;
    overflow-wrap: normal;
    word-break: normal;
}
#mwddns-debug .mwddns-debug-summary th:nth-child(1),
#mwddns-debug .mwddns-debug-summary td:nth-child(1) { min-width: 11ch; white-space: nowrap; }
#mwddns-debug .mwddns-debug-summary th:nth-child(2),
#mwddns-debug .mwddns-debug-summary td:nth-child(2) { min-width: 11em; }
#mwddns-debug .mwddns-debug-summary th:nth-child(3),
#mwddns-debug .mwddns-debug-summary td:nth-child(3) {
    min-width: 26ch;
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
}
#mwddns-debug .mwddns-debug-summary th:nth-child(4),
#mwddns-debug .mwddns-debug-summary td:nth-child(4) { min-width: 15em; }
#mwddns-debug .mwddns-debug-summary th:nth-child(5),
#mwddns-debug .mwddns-debug-summary td:nth-child(5) { min-width: 10em; }
#mwddns-debug .mwddns-debug-summary th:nth-child(6),
#mwddns-debug .mwddns-debug-summary td:nth-child(6) { min-width: 13em; }
#mwddns-debug .mwddns-debug-summary th:nth-child(7),
#mwddns-debug .mwddns-debug-summary td:nth-child(7) { min-width: 22em; }
#mwddns-debug .mwddns-debug-summary code,
#mwddns-debug .mwddns-debug-number {
    display: inline-block;
    white-space: nowrap;
    overflow-wrap: normal;
    word-break: normal;
    font-variant-numeric: tabular-nums;
}
#mwddns-debug .mwddns-debug-detail { display: block; margin-top: 7px; line-height: 1.6; }
#mwddns-debug .mwddns-debug-warning + .mwddns-debug-warning { margin-top: 12px; }
#mwddns-debug .mwddns-debug-checkpoint {
    display: grid;
    grid-template-columns: minmax(12em, 1fr) minmax(0, 2fr);
    gap: 10px 20px;
    padding: 16px;
    border: 1px solid var(--mwddns-debug-border);
    margin: 16px 0;
}
#mwddns-debug .mwddns-debug-checkpoint dt { text-align: left; }
#mwddns-debug .mwddns-debug-checkpoint dd {
    margin: 0;
    overflow-wrap: anywhere;
    font-variant-numeric: tabular-nums;
}
#mwddns-debug pre {
    max-height: 36em;
    overflow: auto;
    margin: 0;
    padding: 18px;
    border: 1px solid var(--mwddns-debug-border);
    border-radius: 0;
    background: var(--mwddns-debug-tint);
    color: inherit;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    word-break: break-word;
    line-height: 1.55;
    tab-size: 2;
}
@media (max-width: 767px) {
    #mwddns-debug { padding: 4px 10px 24px; }
    #mwddns-debug .panel { margin-bottom: 16px; }
    #mwddns-debug .panel > .panel-heading { padding: 12px 16px; }
    #mwddns-debug .panel > .panel-body { padding: 16px; }
    #mwddns-debug .mwddns-debug-fields { grid-template-columns: minmax(0, 1fr); gap: 14px; }
    #mwddns-debug .mwddns-debug-field { padding: 14px; }
    #mwddns-debug .mwddns-debug-checkpoint { grid-template-columns: minmax(0, 1fr); gap: 6px; }
    #mwddns-debug .mwddns-debug-checkpoint dd { margin-bottom: 10px; }
    #mwddns-debug .mwddns-debug-actions .btn { flex: 1 1 auto; }
    #mwddns-debug .alert, #mwddns-debug pre { padding: 14px; }
}
</style>
<section class="page-content-main mwddns-page">
<div id="mwddns-debug" class="container-fluid">
<?php if ($error !== ''): ?>
    <div class="alert alert-danger"><?= mwddns_debug_label($error) ?></div>
<?php elseif (isset($_GET['saved'])): ?>
    <div class="alert alert-success"><?= mwddns_debug_label('Debug settings saved.') ?></div>
<?php endif; ?>
<div class="panel panel-default">
    <div class="panel-heading"><h2 class="panel-title"><?= mwddns_debug_label('Debug information') ?></h2></div>
    <div class="panel-body">
        <p><?= mwddns_debug_label('Collect existing logs only. No DNS update, service restart or upload is performed.') ?></p>
        <div class="alert alert-info">
            <?= mwddns_debug_label('Strict privacy: raw messages, credentials, names and configuration are not exported. The report keeps event codes, timestamps, metrics and consistent WAN/IP aliases. Unknown text is omitted.') ?>
        </div>
        <form method="post" action="/mwddns_debug.php">
            <?= mwddns_csrf_input() ?>
            <input type="hidden" name="revision" value="<?= mwddns_debug_h(mwddns_debug_revision($settings)) ?>">
            <div class="mwddns-debug-fields">
            <div class="mwddns-debug-field">
                <label for="debug-days"><?= mwddns_debug_label('Recent days to collect') ?></label>
                <input id="debug-days" class="form-control" type="number"
                       name="days" min="1" max="14" required value="<?= (int)$settings['days'] ?>">
                <p class="help-block"><?= mwddns_debug_label('Default: 3 days. Range: 1-14 days. Rotation or disabled logging may leave gaps.') ?></p>
            </div>
            <div class="mwddns-debug-field" role="group" aria-labelledby="debug-sources-heading">
                <p id="debug-sources-heading" class="mwddns-debug-field-title"><?= mwddns_debug_label('Collection sources') ?></p>
<?php foreach ([
    'network' => 'WAN, DHCP client, gateway, PPP and routing events',
    'web' => 'PHP and WebGUI error events',
    'runtime' => 'Current service, interface and update-state snapshot',
] as $key => $label): ?>
            <label class="mwddns-debug-source">
                <input type="checkbox" name="<?= $key ?>" value="yes" <?= $settings[$key] ? 'checked' : '' ?>>
                <span><?= mwddns_debug_label($label) ?></span>
            </label>
<?php endforeach; ?>
            </div>
            </div>
            <p class="help-block"><?= mwddns_debug_label('MWDDNS system events are always included. Collection runs in the background with time and size limits.') ?></p>
            <div class="mwddns-debug-actions">
            <button class="btn btn-primary" type="submit" name="action" value="collect">
                <i class="fa fa-bug" aria-hidden="true"></i> <?= mwddns_debug_label('Save and collect') ?>
            </button>
            <button class="btn btn-default" type="submit" name="action" value="save"><?= mwddns_debug_label('Save') ?></button>
            <a href="/mwddns.php" class="btn btn-default"><?= mwddns_debug_label('Back to rules') ?></a>
            </div>
        </form>
    </div>
</div>
<details class="panel panel-default">
    <summary class="panel-heading"><span class="panel-title"><?= mwddns_debug_label('Private WAN alias reference') ?></span></summary>
    <div class="panel-body">
        <p><?= mwddns_debug_label('This table is shown only here and is NOT in the report. Do not include it in screenshots. Aliases follow the current configuration; collect again after changing interfaces.') ?></p>
        <div class="table-responsive"><table class="table table-condensed">
            <thead><tr><th><?= mwddns_debug_label('Report alias') ?></th><th><?= mwddns_debug_label('Interfaces') ?></th><th><?= mwddns_debug_label('Name') ?></th></tr></thead>
            <tbody>
<?php foreach (mwddns_debug_wans() as $wan): ?>
                <tr><td><code><?= mwddns_debug_h($wan['alias']) ?></code></td>
                    <td><?= mwddns_debug_h($wan['key'] . ' / ' . $wan['device']) ?></td>
                    <td><?= mwddns_debug_h($wan['description']) ?></td></tr>
<?php endforeach; ?>
            </tbody>
        </table></div>
    </div>
</details>
<div class="panel panel-default mwddns-debug-history">
    <div class="panel-heading"><h2 class="panel-title" id="debug-history-heading"><?= mwddns_debug_label('Recent Debug reports') ?></h2></div>
    <div class="panel-body">
<?php if (!$recentReports): ?>
        <p><?= mwddns_debug_label('No Debug reports retained.') ?></p>
<?php else: ?>
        <div class="table-responsive" tabindex="0" role="region" aria-labelledby="debug-history-heading">
        <table class="table table-condensed">
            <thead><tr>
                <th scope="col"><?= mwddns_debug_label('Report time') ?></th>
                <th scope="col"><?= mwddns_debug_label('Status') ?></th>
                <th scope="col"><?= mwddns_debug_label('Actions') ?></th>
            </tr></thead>
            <tbody>
<?php foreach ($recentReports as $reportId => $reportStatus): ?>
                <tr<?= $reportId === $job ? ' class="active"' : '' ?>>
                    <td><?= $reportStatus['started'] > 0 ? mwddns_debug_time(date(DATE_ATOM, $reportStatus['started'])) : mwddns_debug_label('Not observed') ?></td>
                    <td>
                        <?= mwddns_debug_label($stateLabels[$reportStatus['state']] ?? 'Report unavailable.') ?>
<?php if ($reportStatus['state'] === 'complete' && $reportStatus['partial'] === true): ?>
                        <small class="help-block text-warning"><?= mwddns_debug_label('Contains gaps or collection limits.') ?></small>
<?php endif; ?>
                    </td>
                    <td><div class="mwddns-debug-history-actions">
                        <a class="btn btn-default btn-sm" href="/mwddns_debug.php?job=<?= mwddns_debug_h($reportId) ?>"><?= mwddns_debug_label('Open report') ?></a>
<?php if (in_array($reportStatus['state'], ['complete', 'failed'], true)): ?>
                        <form method="post" action="/mwddns_debug.php">
                            <?= mwddns_csrf_input() ?>
                            <input type="hidden" name="job" value="<?= mwddns_debug_h($reportId) ?>">
                            <button type="submit" class="btn btn-success btn-sm" name="action" value="<?= $reportStatus['state'] === 'complete' ? 'download' : 'diagnostics' ?>"><?= mwddns_debug_label($reportStatus['state'] === 'complete' ? 'Download sanitized report' : 'Download failure diagnostics') ?></button>
                        </form>
<?php endif; ?>
                    </div></td>
                </tr>
<?php endforeach; ?>
            </tbody>
        </table></div>
<?php endif; ?>
    </div>
</div>
<div class="panel panel-default">
    <div class="panel-heading"><h2 class="panel-title"><?= mwddns_debug_label('Collection result') ?></h2></div>
    <div class="panel-body">
        <p class="mwddns-debug-status" role="status"><?= mwddns_debug_label($stateLabels[$status['state']]) ?></p>
        <p class="help-block"><?= mwddns_debug_label('Reports expire after 24 hours. At most 3 are retained; expired files are removed on the next collection. Use the recent reports list to reopen retained reports.') ?></p>
<?php if ($status['state'] === 'complete'): ?>
        <?php if (($status['partial'] ?? null) === true): ?>
        <div class="alert alert-warning"><?= mwddns_debug_label('Report collected with gaps or limits. Review source warnings; missing events do not prove the system was healthy.') ?></div>
        <?php endif; ?>
<?php endif; ?>
<?php if ($job !== '' && in_array($status['state'], ['queued', 'running', 'complete', 'failed'], true)): ?>
        <h3 class="mwddns-debug-preview-title"><?= mwddns_debug_label('Collector diagnostics') ?></h3>
        <p class="help-block"><?= mwddns_debug_label('Measurements describe the last recorded checkpoint, not page waiting time. Older jobs may have no measurements.') ?></p>
<?php if ($status['state'] === 'failed'): ?>
        <div class="alert alert-warning"><?= mwddns_debug_label('A last stage or stale status is a diagnostic lead, not proof of the root cause. Download the sanitized failure diagnostics before retrying.') ?></div>
<?php endif; ?>
<?php if ($status['state'] === 'complete'): ?>
        <p class="help-block"><?= mwddns_debug_label('Completed totals cover all included sources. Dropped events count scanned matches only, not unread or missing logs. Older jobs may not contain totals.') ?></p>
<?php endif; ?>
        <dl class="mwddns-debug-checkpoint">
<?php foreach ($diagnosticFields as $key => $label):
    $value = $status['diagnostics'][$key] ?? null;
    if (in_array($key, $sourceProgressFields, true) &&
        ($status['diagnostics']['source'] ?? 'none') === 'none') {
        $display = mwddns_t('Not applicable');
    } elseif ($key === 'collector_line' && $value === 0) {
        $display = mwddns_t('Not reported');
    } elseif (isset($diagnosticLabels[$key]) && is_string($value)) {
        $display = mwddns_t($diagnosticLabels[$key][$value] ?? 'Not reported');
    } elseif ($key === 'source') {
        $display = is_string($value) && $value !== 'none' ? $value : mwddns_t('Not reported');
    } elseif (is_int($value) || is_float($value)) {
        $display = in_array($key, ['elapsed_seconds', 'cpu_seconds'], true)
            ? number_format($value, 3, '.', '') : (string)$value;
    } else {
        $display = mwddns_t('Not reported');
    }
?>
            <dt><?= mwddns_debug_label($label) ?></dt>
            <dd data-debug-field="<?= mwddns_debug_h($key) ?>"><?= mwddns_debug_h($display) ?></dd>
<?php endforeach; ?>
<?php foreach ($diagnosticTimes as $key => $label): ?>
            <dt><?= mwddns_debug_label($label) ?></dt>
            <dd data-debug-time="<?= $key ?>"><?= ($status['diagnostics'][$key] ?? 0) > 0 ? mwddns_debug_time(date(DATE_ATOM, $status['diagnostics'][$key])) : mwddns_debug_label($key === 'record_epoch' && ($status['diagnostics']['source'] ?? 'none') === 'none' ? 'Not applicable' : 'Not reported') ?></dd>
<?php endforeach; ?>
        </dl>
<?php endif; ?>
<?php if ($job !== ''): ?>
        <div class="mwddns-debug-actions">
<?php if (in_array($status['state'], ['complete', 'failed'], true)): ?>
        <form method="post" action="/mwddns_debug.php">
            <?= mwddns_csrf_input() ?>
            <input type="hidden" name="job" value="<?= $job ?>">
<?php if ($status['state'] === 'complete'): ?>
            <button class="btn btn-success btn-sm" name="action" value="download"><?= mwddns_debug_label('Download sanitized report') ?></button>
<?php endif; ?>
            <button class="btn btn-default btn-sm" name="action" value="diagnostics"><?= mwddns_debug_label($status['state'] === 'failed' ? 'Download failure diagnostics' : 'Download collector diagnostics') ?></button>
            <button class="btn btn-default btn-sm" name="action" value="delete"><?= mwddns_debug_label('Delete report') ?></button>
        </form>
<?php endif; ?>
        <a class="btn btn-default btn-sm" href="/mwddns_debug.php?job=<?= $job ?>"><?= mwddns_debug_label('Refresh status') ?></a>
        </div>
<?php endif; ?>
<?php if ($status['state'] === 'complete'): ?>
        <div class="mwddns-debug-summary">
        <h3 class="mwddns-debug-preview-title" id="debug-summary-heading"><?= mwddns_debug_label('Source coverage and counts') ?></h3>
        <p id="mwddns-debug-time-note" class="help-block" hidden><?= mwddns_debug_label('Times follow your browser locale and time zone. The report retains original ISO timestamps.') ?><span id="mwddns-debug-time-zone"></span></p>
<?php if ($sourceSummary): ?>
        <div class="table-responsive" tabindex="0" role="region" aria-labelledby="debug-summary-heading">
        <table class="table table-condensed">
            <thead><tr>
<?php foreach (['Source', 'Coverage', 'Observed log range', 'Matched / retained / dropped', 'Groups', 'Collection limits', 'Warnings'] as $label): ?>
                <th scope="col"><?= mwddns_debug_label($label) ?></th>
<?php endforeach; ?>
            </tr></thead><tbody>
<?php foreach ($sourceSummary as $row): ?>
            <tr>
                <td><code><?= mwddns_debug_h($row['source']) ?></code></td>
                <td><?= mwddns_debug_label($row['coverage']) ?></td>
                <td><?= $row['oldest'] !== '' ? mwddns_debug_time($row['oldest']) : mwddns_debug_label('Not observed') ?><br><?= $row['newest'] !== '' ? mwddns_debug_time($row['newest']) : '' ?></td>
                <td><span class="mwddns-debug-number"><?= (int)$row['matched'] ?> / <?= (int)$row['retained'] ?> / <?= (int)$row['dropped'] ?></span>
<?php if ($row['drop_stages_available']): ?>
                    <small class="mwddns-debug-detail"><?= mwddns_debug_label('Dropped at candidate / allocation / report-size stage') ?>:<br><span class="mwddns-debug-number"><?= (int)$row['candidate_dropped'] ?> / <?= (int)$row['allocation_dropped'] ?> / <?= (int)$row['size_dropped'] ?></span></small>
<?php endif; ?>
                </td>
                <td><?= (int)$row['groups'] ?>
                    <small class="mwddns-debug-detail"><?= mwddns_debug_label('Candidate group capacity') ?>: <?= (int)$row['candidate_limit'] ?></small>
                </td>
                <td<?= $row['limited'] ? ' class="text-warning"' : '' ?>><?= mwddns_debug_label($row['limited'] ? 'Limits reached' : 'None reported') ?>
<?php if ($row['seconds_used'] !== null && $row['seconds_allocated'] !== null): ?>
                    <small class="mwddns-debug-detail"><?= mwddns_debug_label('Scan seconds used / allocated') ?>:<br><span class="mwddns-debug-number"><?= number_format($row['seconds_used'], 2, '.', '') ?> / <?= number_format($row['seconds_allocated'], 2, '.', '') ?></span></small>
<?php endif; ?>
                </td>
                <td><?php if ($row['warnings']): ?>
<?php foreach ($row['warnings'] as $warningIndex => $warning): ?>
                    <div class="mwddns-debug-warning"><?= mwddns_debug_label($row['warning_labels'][$warningIndex]) ?><br><code><?= mwddns_debug_h($warning) ?></code></div>
<?php endforeach; ?>
                <?php else: ?><?= mwddns_debug_label('None reported') ?><?php endif; ?></td>
            </tr>
<?php endforeach; ?>
            </tbody></table></div>
        <p class="help-block"><?= mwddns_debug_label('Counts are occurrences; groups may contain repeats. Coverage describes scanned logs. Collection limits are shown separately.') ?></p>
<?php else: ?>
        <p class="help-block"><?= mwddns_debug_label('Source summary unavailable.') ?></p>
<?php endif; ?>
        </div>
        <div class="mwddns-debug-result-notes">
        <p class="help-block"><?= mwddns_debug_label('Check source warnings and coverage before interpreting an empty result as healthy. No report can reconstruct logs that were never recorded.') ?></p>
        <p class="help-block"><?= mwddns_debug_label('Unused scan time and candidate capacity are shared within total limits. Every remaining source keeps a reservation. Read-byte limits remain separate.') ?></p>
        <p class="help-block"><?= mwddns_debug_label('Event-code counts overlap when a record has multiple codes. DHCPREQUEST histograms count scanned requests even when event groups are dropped.') ?></p>
        <p class="help-block"><?= mwddns_debug_label('Dropped counts include scanned events only; unread records cannot be counted. New reports show observed timestamps within the requested window, not proof of continuous coverage.') ?></p>
        </div>
        <div class="mwddns-debug-preview">
        <h3 class="mwddns-debug-preview-title"><?= mwddns_debug_label('Report preview') ?></h3>
        <?php if ($previewLimited): ?><p class="text-warning"><?= mwddns_debug_label('Preview shortened. Download contains the full collected report.') ?></p><?php endif; ?>
        <pre tabindex="0"><?= mwddns_debug_h($preview) ?></pre>
        </div>
<?php endif; ?>
    </div>
</div>
</div>
</section>
<script>
(function () {
    var timestamps = document.querySelectorAll('#mwddns-debug time.mwddns-debug-timestamp');
    if (!timestamps.length || typeof Intl === 'undefined' ||
            typeof Intl.DateTimeFormat !== 'function') {
        return;
    }
    try {
        var locales = navigator.languages && navigator.languages.length
            ? navigator.languages : (navigator.language || undefined);
        var formatter = new Intl.DateTimeFormat(locales, {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            timeZoneName: 'short'
        });
        Array.prototype.forEach.call(timestamps, function (element) {
            var date = new Date(element.getAttribute('datetime'));
            if (!isNaN(date.getTime())) {
                element.textContent = formatter.format(date);
            }
        });
        var zone = document.getElementById('mwddns-debug-time-zone');
        var timeZone = formatter.resolvedOptions().timeZone;
        if (zone && timeZone) {
            zone.textContent = ' (' + timeZone + ')';
        }
        var note = document.getElementById('mwddns-debug-time-note');
        if (note) { note.hidden = false; }
    } catch (error) {
        // Keep the original ISO timestamps if locale formatting is unavailable.
    }
}());
</script>
<?php if (in_array($status['state'], ['queued', 'running'], true)): ?>
<script>
(function () {
    var attempts = 0;
    var job = <?= json_encode($job, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var labels = <?= json_encode($diagnosticTranslations, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var unavailable = <?= json_encode(mwddns_t('Not reported'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var notApplicable = <?= json_encode(mwddns_t('Not applicable'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var sourceFields = <?= json_encode($sourceProgressFields, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    function updateProgress(data) {
        Array.prototype.forEach.call(document.querySelectorAll('[data-debug-field]'), function (element) {
            var key = element.getAttribute('data-debug-field');
            var value = data[key];
            var display = unavailable;
            if (sourceFields.indexOf(key) !== -1 && (!data.source || data.source === 'none')) {
                display = notApplicable;
            } else if (key === 'collector_line' && value === 0) {
                display = unavailable;
            } else if (labels[key] && typeof value === 'string') {
                display = labels[key][value] || unavailable;
            } else if (key === 'source' && typeof value === 'string' && value !== 'none') {
                display = value;
            } else if (typeof value === 'number' && isFinite(value)) {
                display = key === 'elapsed_seconds' || key === 'cpu_seconds' ? value.toFixed(3) : String(value);
            }
            element.textContent = display;
        });
        Array.prototype.forEach.call(document.querySelectorAll('[data-debug-time]'), function (element) {
            var key = element.getAttribute('data-debug-time');
            if (key === 'record_epoch' && (!data.source || data.source === 'none')) {
                element.textContent = notApplicable;
                return;
            }
            var value = data[key];
            var date = typeof value === 'number' && value > 0 ? new Date(value * 1000) : null;
            element.textContent = date && !isNaN(date.getTime())
                ? date.toLocaleString(navigator.languages && navigator.languages.length ? navigator.languages : navigator.language)
                : unavailable;
        });
    }
    function poll() {
        if (++attempts > 45) { return; }
        fetch('/mwddns_debug.php?status=' + job, {credentials: 'same-origin', cache: 'no-store'})
            .then(function (response) {
                if (!response.ok) { throw new Error('status'); }
                return response.json();
            })
            .then(function (result) {
                updateProgress(result.diagnostics || {});
                if (result.state === 'queued' || result.state === 'running') {
                    window.setTimeout(poll, 3000);
                } else {
                    window.location.replace('/mwddns_debug.php?job=' + job);
                }
            })
            .catch(function () { /* Manual refresh remains available. */ });
    }
    window.setTimeout(poll, 3000);
}());
</script>
<?php endif; ?>
<?php include('foot.inc'); ?>
