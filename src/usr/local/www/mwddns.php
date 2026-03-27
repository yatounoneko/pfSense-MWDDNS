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

// ── Handle delete action (POST + CSRF) ───────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['act'] ?? '') === 'del' && isset($_POST['id'])) {
    $token = (string)($_POST['mwddns_csrf_token'] ?? '');
    if (!mwddns_csrf_validate($token)) {
        header('Location: /mwddns.php');
        exit;
    }
    $id = (int)$_POST['id'];
    mwddns_delete_rule($id);
    header('Location: /mwddns.php?msg=deleted');
    exit;
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

$pgtitle = [mwddns_t('Services'), mwddns_t('Multi-WAN DDNS')];
$pglinks = ['', '/mwddns.php'];

include('head.inc');
?>
<body>
<?php include('fbegin.inc'); ?>

<section class="page-content-main">
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
        $dnsIPv4  = in_array('A',    $types, true) ? mwddns_rule_record_observed_ips($rule, 'A')    : [];
        $dnsIPv6  = in_array('AAAA', $types, true) ? mwddns_rule_record_observed_ips($rule, 'AAAA') : [];
        $provName = mwddns_provider_name($rule['provider'] ?? 'cloudflare');
?>
                    <tr>
                        <!-- Name -->
                        <td><?= htmlspecialchars($rule['name'] ?? '') ?></td>

                        <!-- Provider -->
                        <td><span class="label label-info"><?= htmlspecialchars($provName) ?></span></td>

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
<?php   if ($info['ipv4'] !== null): $inSync = in_array($info['ipv4'], $dnsIPv4, true); ?>
                                <span class="<?= $inSync ? 'text-success' : 'text-danger' ?>"
                                      title="A: <?= $inSync
                                          ? mwddns_t('DNS record matches this IP')
                                          : mwddns_t('DNS record does NOT contain this IP') ?>">
                                    <?= htmlspecialchars($info['ipv4']) ?>
                                    <small class="text-muted">A</small>
                                    <i class="fa fa-<?= $inSync ? 'check' : 'exclamation-triangle' ?>"></i>
                                </span>
<?php   else: ?>
                                <span class="text-muted"><?= mwddns_t('No IPv4') ?></span>
<?php   endif; ?>
<?php endif; ?>
<?php if (in_array('AAAA', $types, true)): ?>
<?php   if ($info['ipv6'] !== null): $inSync = in_array($info['ipv6'], $dnsIPv6, true); ?>
                                <span class="<?= $inSync ? 'text-success' : 'text-danger' ?>"
                                      title="AAAA: <?= $inSync
                                          ? mwddns_t('DNS record matches this IP')
                                          : mwddns_t('DNS record does NOT contain this IP') ?>">
                                    <?= htmlspecialchars($info['ipv6']) ?>
                                    <small class="text-muted">AAAA</small>
                                    <i class="fa fa-<?= $inSync ? 'check' : 'exclamation-triangle' ?>"></i>
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
                            <a class="fa fa-pencil"
                               title="<?= mwddns_t('Edit') ?>"
                               href="/mwddns_edit.php?id=<?= (int)$id ?>"></a>
                            &nbsp;
                            <form method="post" action="/mwddns.php" style="display:inline">
                                <?= mwddns_csrf_input() ?>
                                <input type="hidden" name="act" value="del">
                                <input type="hidden" name="id" value="<?= (int)$id ?>">
                                <button type="submit" class="fa fa-trash btn btn-link p-0"
                                        title="<?= mwddns_t('Delete') ?>"
                                        aria-label="<?= mwddns_t('Delete') ?>"
                                        onclick="return confirm('<?= mwddns_t('Delete this rule?') ?>')"
                                        style="vertical-align:baseline"></button>
                            </form>
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
