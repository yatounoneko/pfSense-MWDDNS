<?php
/*
 * mwddns.widget.php  –  Dashboard widget for Multi-WAN DDNS
 *
 * Placed at: /usr/local/www/widgets/widgets/mwddns.widget.php
 *
 * Displays a compact summary of all MWDDNS rules:
 *   • Rule name
 *   • Hostname
 *   • Per-interface name, IPv4 (A) and IPv6 (AAAA) addresses
 *     – Green  : DNS resolves to this IP (in sync)
 *     – Red    : DNS does NOT contain this IP (out of sync)
 *   • Last-update timestamp
 */

require_once('/usr/local/pkg/mwddns.inc');

$rules = mwddns_get_rules();
?>
<div id="mwddns-widget-body">
<table class="table table-striped table-hover table-condensed">
    <thead>
        <tr>
            <th><?= mwddns_t('Name') ?></th>
            <th><?= mwddns_t('Hostname') ?></th>
            <th><?= mwddns_t('Interface / IP') ?></th>
            <th><?= mwddns_t('Updated') ?></th>
        </tr>
    </thead>
    <tbody>
<?php if (empty($rules)): ?>
        <tr>
            <td colspan="4" class="text-center text-muted">
                <?= mwddns_t('No MWDDNS rules configured.') ?>
                <a href="/mwddns_edit.php"><?= mwddns_t('Add one') ?></a>.
            </td>
        </tr>
<?php else: ?>
<?php foreach ($rules as $rule):
    $ipsInfo = mwddns_get_rule_ips($rule);
    $types   = mwddns_rule_record_types($rule);
    $dnsIPv4 = in_array('A',    $types, true) ? mwddns_rule_record_observed_ips($rule, 'A')    : [];
    $dnsIPv6 = in_array('AAAA', $types, true) ? mwddns_rule_record_observed_ips($rule, 'AAAA') : [];
?>
        <tr>
            <td>
                <a href="/mwddns.php" title="<?= mwddns_t('Manage rules') ?>">
                    <?= htmlspecialchars($rule['name'] ?? '') ?>
                </a>
            </td>
            <td><code><?= htmlspecialchars($rule['hostname'] ?? '') ?></code></td>
            <td>
<?php foreach ($ipsInfo as $info): ?>
                <div>
                    <small class="text-muted"><?= htmlspecialchars($info['desc']) ?>:</small>
<?php if (in_array('A', $types, true)): ?>
<?php   if ($info['ipv4'] !== null): $inSync = in_array($info['ipv4'], $dnsIPv4, true); ?>
                    <span class="<?= $inSync ? 'text-success' : 'text-danger' ?>"
                          title="A – <?= $inSync ? mwddns_t('In sync') : mwddns_t('Out of sync') ?>">
                        <?= htmlspecialchars($info['ipv4']) ?>
                        <i class="fa fa-<?= $inSync ? 'check-circle' : 'exclamation-circle' ?>"></i>
                    </span>
<?php   else: ?>
                    <span class="text-muted"><?= mwddns_t('No IPv4') ?></span>
<?php   endif; ?>
<?php endif; ?>
<?php if (in_array('AAAA', $types, true)): ?>
<?php   if ($info['ipv6'] !== null): $inSync = in_array($info['ipv6'], $dnsIPv6, true); ?>
                    <span class="<?= $inSync ? 'text-success' : 'text-danger' ?>"
                          title="AAAA – <?= $inSync ? mwddns_t('In sync') : mwddns_t('Out of sync') ?>">
                        <?= htmlspecialchars($info['ipv6']) ?>
                        <i class="fa fa-<?= $inSync ? 'check-circle' : 'exclamation-circle' ?>"></i>
                    </span>
<?php   else: ?>
                    <span class="text-muted"><?= mwddns_t('No IPv6') ?></span>
<?php   endif; ?>
<?php endif; ?>
                </div>
<?php endforeach; ?>
            </td>
            <td>
                <small><?= htmlspecialchars($rule['last_updated'] ?? '–') ?></small>
<?php $status = $rule['last_status'] ?? ''; ?>
<?php if ($status === 'OK'): ?>
                <span class="label label-success" style="font-size:9px">OK</span>
<?php elseif ($status === 'Error'): ?>
                <span class="label label-danger" style="font-size:9px"><?= mwddns_t('Err') ?></span>
<?php endif; ?>
            </td>
        </tr>
<?php endforeach; ?>
<?php endif; ?>
    </tbody>
</table>

<div class="text-right" style="margin-top:4px">
    <a href="/mwddns.php" class="btn btn-xs btn-default">
        <i class="fa fa-cog"></i> <?= mwddns_t('Manage Rules') ?>
    </a>
</div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    var widgetBody = document.getElementById('mwddns-widget-body');
    if (!widgetBody) {
        return;
    }
    var widgetTitle = <?= json_encode(mwddns_t('Multi-WAN DDNS')) ?>;
    var panelContainer = widgetBody.closest('.panel');
    if (!panelContainer) {
        return;
    }
    var panelTitle = panelContainer.querySelector('.panel-title');
    if (!panelTitle) {
        return;
    }
    var titleLink = document.createElement('a');
    titleLink.href = '/mwddns.php';

    var existingNodes = Array.from(panelTitle.childNodes);
    panelTitle.textContent = '';

    if (existingNodes.length) {
        var fragment = document.createDocumentFragment();
        existingNodes.forEach(function(node) {
            fragment.appendChild(node);
        });
        titleLink.appendChild(fragment);
    } else {
        titleLink.textContent = widgetTitle;
    }

    panelTitle.appendChild(titleLink);
});
</script>
