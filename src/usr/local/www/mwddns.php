<?php
/*
 * mwddns.php  –  Multi-WAN DDNS portal / rules list
 *
 * Placed at: /usr/local/www/mwddns.php
 *
 * Shows every configured rule with:
 *   • Custom name
 *   • Provider
 *   • Hostname
 *   • Per-interface name + current IP
 *     – Green  : DNS lookup of hostname returns this IP  (in sync)
 *     – Red    : DNS lookup does NOT return this IP      (out of sync)
 *   • Last-updated timestamp
 *   • Edit / Delete actions
 */

require_once('guiconfig.inc');
require_once('/usr/local/pkg/mwddns.inc');

$actionError = '';
// ── Handle delete action (POST + CSRF) ───────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['act'] ?? '') === 'del' && isset($_POST['id'])) {
    $token = (string)($_POST['mwddns_csrf_token'] ?? '');
    if (!mwddns_csrf_validate($token)) {
        header('Location: /mwddns.php');
        exit;
    }
    try {
        if (!is_string($_POST['id']) || !ctype_digit($_POST['id']) ||
            !is_string($_POST['mwddns_revision'] ?? null)) {
            throw new RuntimeException('Invalid form data.');
        }
        mwddns_delete_rule((int)$_POST['id'], $_POST['mwddns_revision']);
        header('Location: /mwddns.php?msg=deleted');
        exit;
    } catch (Throwable $e) {
        $actionError = mwddns_t($e instanceof RuntimeException
            ? $e->getMessage()
            : 'Configuration could not be saved. No DNS update was started.');
    }
}

// ── Load data ─────────────────────────────────────────────────────────────────
$rules   = mwddns_get_rules();
$message = '';
$msgtype = 'info';

if (isset($_GET['msg'])) {
    switch ($_GET['msg']) {
        case 'saved':
            $message = mwddns_t('Rule saved successfully.');
            $msgtype = 'success';
            break;
        case 'deleted':
            $message = mwddns_t('Rule deleted.');
            $msgtype = 'success';
            break;
        case 'copy_unavailable':
            $message = mwddns_t('The source rule changed or no longer exists. Reload the rules list and copy it again.');
            $msgtype = 'warning';
            break;
        case 'updated':
            $message = mwddns_t('DNS records updated successfully.');
            $msgtype = 'success';
            break;
        case 'update_error':
            $message = mwddns_t('DNS update completed with errors. Check individual rule status.');
            $msgtype = 'danger';
            break;
    }
}

if ($actionError !== '') {
    $message = $actionError;
    $msgtype = 'danger';
}
$formRevision = mwddns_rules_revision($rules);

$pgtitle = [mwddns_t('Services'), mwddns_t('Multi-WAN DDNS')];
$pglinks = ['', '/mwddns.php'];

include('head.inc');
?>
<body>
<?php include('fbegin.inc'); ?>
<?= mwddns_gui_styles() ?>

<section class="page-content-main mwddns-page">
<div class="container-fluid">
<div class="row">

<?php if ($message): ?>
<div class="col-xs-12">
    <div class="alert alert-<?= htmlspecialchars($msgtype) ?>" role="alert">
        <?= htmlspecialchars($message) ?>
    </div>
</div>
<?php endif; ?>

<section class="col-xs-12">
<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title"><?= mwddns_t('Multi-WAN DDNS Rules') ?></h2>
    </div>
    <div class="panel-body">
        <div class="table-responsive">
            <table class="table table-striped table-hover table-condensed">
                <thead>
                    <tr>
                        <th><?= mwddns_t('Name') ?></th>
                        <th><?= mwddns_t('Provider') ?></th>
                        <th><?= mwddns_t('Hostname') ?></th>
                        <th><?= mwddns_t('Interfaces / Current IPs') ?></th>
                        <th><?= mwddns_t('Last Updated') ?></th>
                        <th><?= mwddns_t('Status') ?></th>
                        <th><?= mwddns_t('Actions') ?></th>
                    </tr>
                </thead>
                <tbody>
<?php if (empty($rules)): ?>
                    <tr>
                        <td colspan="7" class="text-center text-muted">
                            <?= mwddns_t('No rules configured. Click') ?>
                            <a href="/mwddns_edit.php"><?= mwddns_t('Add') ?></a>
                            <?= mwddns_t('to create one.') ?>
                        </td>
                    </tr>
<?php else: ?>
<?php foreach ($rules as $id => $rule):
        $ipsInfo  = mwddns_get_rule_ips($rule);
        $types    = mwddns_rule_record_types($rule);
        // Provider-aware status lookup:
        // proxy-enabled providers can use API record listing instead of public DNS.
        $dnsIPv4  = in_array('A',    $types, true) ? mwddns_cached_observed_ips($rule, 'A')    : [];
        $dnsIPv6  = in_array('AAAA', $types, true) ? mwddns_cached_observed_ips($rule, 'AAAA') : [];
        $provName = mwddns_provider_name($rule['provider'] ?? 'cloudflare');
?>
                    <tr>
                        <!-- Name -->
                        <td><?= htmlspecialchars($rule['name'] ?? '') ?></td>

                        <!-- Provider -->
                        <td>
                            <span style="display:inline-flex;align-items:center;gap:6px;white-space:nowrap">
                                <span class="label label-info"><?= htmlspecialchars($provName) ?></span>
<?php if (($rule['provider'] ?? 'cloudflare') === 'cloudflare' && ($rule['proxied'] ?? '0') === '1'): ?>
                                <span style="display:inline-flex;align-items:center;color:#F6821F"
                                      title="<?= htmlspecialchars(mwddns_t('Cloudflare Proxy (orange cloud)'), ENT_QUOTES, 'UTF-8') ?>">
                                    <svg aria-hidden="true" focusable="false" viewBox="0 0 64 40"
                                         width="24" height="15" fill="currentColor" style="display:block;flex-shrink:0">
                                        <path d="M52.5 38c-1.7 0-12.5-.1-23-.2-10.2-.1-20.8-.2-22.4-.2a6.5 6.5 0 0 1-.8-12.9c0-.15 0-.3 0-.46a7.7 7.7 0 0 1 12.1-6.33A15.8 15.8 0 0 1 49.25 21.65 8.5 8.5 0 1 1 52.5 38Z"></path>
                                    </svg>
                                    <span class="sr-only"><?= htmlspecialchars(mwddns_t('Cloudflare Proxy (orange cloud)'), ENT_QUOTES, 'UTF-8') ?></span>
                                </span>
<?php endif; ?>
                            </span>
                        </td>

                        <!-- Hostname -->
                        <td><code><?= htmlspecialchars($rule['hostname'] ?? '') ?></code></td>

                        <!-- Interfaces / IPs -->
                        <td>
<?php foreach ($ipsInfo as $info): ?>
                            <div>
                                <strong><?= htmlspecialchars($info['desc']) ?>
                                    <small class="text-muted">(<?= htmlspecialchars($info['ifname']) ?>)</small>:
                                </strong>
<?php if (in_array('A', $types, true)): ?>
<?php   if ($info['ipv4'] !== null): $known = $dnsIPv4 !== null; $inSync = $known && in_array($info['ipv4'], $dnsIPv4, true); ?>
                                <span class="<?= !$known ? 'text-muted' : ($inSync ? 'text-success' : 'text-danger') ?>"
                                      title="A: <?= !$known ? mwddns_t('Status pending or stale.') : ($inSync
                                          ? mwddns_t('DNS record matches this IP')
                                          : mwddns_t('DNS record does NOT contain this IP')) ?>">
                                    <?= htmlspecialchars($info['ipv4']) ?>
                                    <small class="text-muted">A</small>
                                    <i class="fa fa-<?= !$known ? 'question-circle' : ($inSync ? 'check' : 'exclamation-triangle') ?>"></i>
                                </span>
<?php   else: ?>
                                <span class="text-muted"><?= mwddns_t('No IPv4') ?></span>
<?php   endif; ?>
<?php endif; ?>
<?php if (in_array('AAAA', $types, true)): ?>
<?php   if ($info['ipv6'] !== null): $known = $dnsIPv6 !== null; $inSync = $known && in_array($info['ipv6'], $dnsIPv6, true); ?>
                                <span class="<?= !$known ? 'text-muted' : ($inSync ? 'text-success' : 'text-danger') ?>"
                                      title="AAAA: <?= !$known ? mwddns_t('Status pending or stale.') : ($inSync
                                          ? mwddns_t('DNS record matches this IP')
                                          : mwddns_t('DNS record does NOT contain this IP')) ?>">
                                    <?= htmlspecialchars($info['ipv6']) ?>
                                    <small class="text-muted">AAAA</small>
                                    <i class="fa fa-<?= !$known ? 'question-circle' : ($inSync ? 'check' : 'exclamation-triangle') ?>"></i>
                                </span>
<?php   else: ?>
                                <span class="text-muted"><?= mwddns_t('No IPv6') ?></span>
<?php   endif; ?>
<?php endif; ?>
                            </div>
<?php endforeach; ?>
                        </td>

                        <!-- Last updated -->
                        <td><?= htmlspecialchars($rule['last_updated'] ?? mwddns_t('Never')) ?></td>

                        <!-- Last status -->
                        <td>
<?php $status = $rule['last_status'] ?? ''; ?>
<?php if ($status === 'OK'): ?>
                            <span class="label label-success">OK</span>
<?php elseif ($status === 'Error'): ?>
                            <span class="label label-danger"><?= mwddns_t('Error') ?></span>
<?php else: ?>
                            <span class="label label-default">–</span>
<?php endif; ?>
                        </td>

                        <!-- Actions -->
                        <td>
                            <div class="mwddns-rule-actions">
                                <a class="mwddns-rule-copy"
                                   title="<?= htmlspecialchars(mwddns_t('Copy Rule'), ENT_QUOTES, 'UTF-8') ?>"
                                   aria-label="<?= htmlspecialchars(mwddns_t('Copy Rule'), ENT_QUOTES, 'UTF-8') ?>"
                                   href="/mwddns_edit.php?clone=<?= (int)$id ?>&amp;revision=<?= htmlspecialchars($formRevision, ENT_QUOTES, 'UTF-8') ?>">
                                    <i class="fa-regular fa-clone" aria-hidden="true"></i>
                                </a>
                                <a class="mwddns-rule-edit"
                                   title="<?= htmlspecialchars(mwddns_t('Edit'), ENT_QUOTES, 'UTF-8') ?>"
                                   aria-label="<?= htmlspecialchars(mwddns_t('Edit'), ENT_QUOTES, 'UTF-8') ?>"
                                   href="/mwddns_edit.php?id=<?= (int)$id ?>">
                                    <i class="fa-solid fa-pencil" aria-hidden="true"></i>
                                </a>
                                <form method="post" action="/mwddns.php" class="mwddns-rule-delete-form">
                                    <?= mwddns_csrf_input() ?>
                                    <input type="hidden" name="mwddns_revision" value="<?= htmlspecialchars($formRevision) ?>">
                                    <input type="hidden" name="act" value="del">
                                    <input type="hidden" name="id" value="<?= (int)$id ?>">
                                    <button type="submit" class="mwddns-delete-rule"
                                            title="<?= htmlspecialchars(mwddns_t('Delete'), ENT_QUOTES, 'UTF-8') ?>"
                                            aria-label="<?= htmlspecialchars(mwddns_t('Delete'), ENT_QUOTES, 'UTF-8') ?>"
                                            data-confirm="<?= htmlspecialchars(mwddns_t('Delete this rule?'), ENT_QUOTES, 'UTF-8') ?>"
                                            onclick="return window.confirm(this.getAttribute('data-confirm'))">
                                        <i class="fa-solid fa-trash-can no-confirm" aria-hidden="true"></i>
                                    </button>
                                </form>
                            </div>
                        </td>
                    </tr>
<?php endforeach; ?>
<?php endif; ?>
                </tbody>
            </table>
        </div><!-- table-responsive -->
    </div><!-- panel-body -->
</div><!-- panel -->

<nav class="action-buttons">
    <a href="/mwddns_upgrade.php" class="btn btn-default btn-sm">
        <i class="fa fa-upload icon-embed-btn"></i>
        <?= mwddns_t('Plugin upgrade') ?>
    </a>
    <a href="/mwddns_debug.php" class="btn btn-default btn-sm">
        <i class="fa fa-bug icon-embed-btn"></i>
        <?= mwddns_t('Debug information') ?>
    </a>
    <a href="/mwddns_edit.php" class="btn btn-success btn-sm">
        <i class="fa fa-plus icon-embed-btn"></i>
        <?= mwddns_t('Add') ?>
    </a>
</nav>
</section><!-- col -->

</div><!-- row -->
</div><!-- container -->
</section><!-- page-content-main -->

<?php include('foot.inc'); ?>
