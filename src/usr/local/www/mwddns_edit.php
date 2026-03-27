<?php
/*
 * mwddns_edit.php  –  Add / Edit a Multi-WAN DDNS rule
 *
 * Placed at: /usr/local/www/mwddns_edit.php
 *
 * Features:
 *   • Provider dropdown – selects which DNS provider to use.
 *   • Provider-specific field panels shown/hidden by JavaScript.
 *   • Common fields: Name, Hostname, TTL, Interfaces.
 *   • "Force Update" button triggers an immediate sync and shows per-action results.
 *   • Save / Cancel buttons.
 */

require_once('guiconfig.inc');
require_once('/usr/local/pkg/mwddns.inc');

// Load all providers and their files so field/validate functions are available
$allProviders = mwddns_get_providers();
foreach ($allProviders as $pKey => $pInfo) {
    mwddns_load_provider($pKey);
}

// ── Load existing rule when editing ──────────────────────────────────────────
$id       = isset($_GET['id']) ? (int)$_GET['id'] : null;
$editMode = ($id !== null);
$rule     = $editMode ? mwddns_get_rule($id) : null;

if ($editMode && $rule === null) {
    header('Location: /mwddns.php');
    exit;
}

// ── Default field values ──────────────────────────────────────────────────────
$provider     = $rule['provider']      ?? 'cloudflare';
$name         = $rule['name']          ?? '';
$hostname     = $rule['hostname']      ?? '';
$ttl          = $rule['ttl']           ?? '300';
$interfaces   = mwddns_rule_interfaces($rule ?? []);
$recordTypes  = mwddns_rule_record_types($rule ?? []);

// ── Collect all available pfSense interfaces ──────────────────────────────────
$ifaceList = get_configured_interface_list();

// ── Input errors ──────────────────────────────────────────────────────────────
$errors = [];

// ── Force-update action ───────────────────────────────────────────────────────
$forceResult = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['act'] ?? '') === 'force_update') {
    $token = (string)($_POST['mwddns_csrf_token'] ?? '');
    if (!mwddns_csrf_validate($token)) {
        $errors[] = mwddns_t('Invalid request token. Please reload the page and try again.');
    }
    if (empty($errors) && $editMode && $rule !== null) {
        $forceResult = mwddns_update_rule($rule);
        $allRules = mwddns_get_rules();
        $allRules[$id]['last_updated'] = date('Y-m-d H:i:s');
        $allRules[$id]['last_status']  = $forceResult['ok'] ? 'OK' : 'Error';
        mwddns_save_rules($allRules);
        $rule = mwddns_get_rule($id);
    }
}

// ── Save action ───────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['act'] ?? '') === 'save') {
    $token = (string)($_POST['mwddns_csrf_token'] ?? '');
    if (!mwddns_csrf_validate($token)) {
        $errors[] = mwddns_t('Invalid request token. Please reload the page and try again.');
    }
    $provider    = $_POST['provider']  ?? 'cloudflare';
    $name        = trim($_POST['name']     ?? '');
    $hostname    = trim($_POST['hostname'] ?? '');
    $ttl         = trim($_POST['ttl']      ?? '300');
    $interfaces  = array_filter((array)($_POST['interfaces'] ?? []));
    $recordTypes = array_values(array_filter((array)($_POST['record_types'] ?? [])));

    // Common validation
    if ($name === '') {
        $errors[] = mwddns_t('Rule name is required.');
    }
    if (!preg_match('/^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/', $hostname)) {
        $errors[] = mwddns_t('Hostname must be a valid fully-qualified domain name.');
    }
    $ttlInt = (int)$ttl;
    if ($ttlInt !== 1 && ($ttlInt < 60 || $ttlInt > 86400)) {
        $errors[] = mwddns_t('TTL must be 1 (auto) or between 60 and 86400 seconds.');
    }
    if (empty($interfaces)) {
        $errors[] = mwddns_t('At least one interface must be selected.');
    }
    if (empty($recordTypes)) {
        $errors[] = mwddns_t('At least one record type (A or AAAA) must be selected.');
    }
    $validTypes = array_filter($recordTypes, fn($t) => in_array($t, ['A', 'AAAA'], true));
    if (count($validTypes) !== count($recordTypes)) {
        $errors[] = mwddns_t('Invalid record type selected.');
    }
    if (!isset($allProviders[$provider])) {
        $errors[] = mwddns_t('Invalid DNS provider selected.');
    }

    // Provider-specific validation
    $validateFn = "mwddns_{$provider}_validate";
    if (function_exists($validateFn)) {
        $validateFn($_POST, $errors);
    }

    if (empty($errors)) {
        $allRules = mwddns_get_rules();

        // Collect all provider-specific field values from every provider
        $entry = [
            'provider'     => $provider,
            'name'         => $name,
            'hostname'     => $hostname,
            'ttl'          => $ttl,
            'interfaces'   => implode(' ', $interfaces),
            'record_types' => implode(' ', $validTypes),
        ];
        foreach ($allProviders as $pKey => $pInfo) {
            $fieldsFn = "mwddns_{$pKey}_fields";
            if (!function_exists($fieldsFn)) {
                continue;
            }
            foreach ($fieldsFn() as $field) {
                $fKey = $field['key'];
                if ($field['type'] === 'checkbox') {
                    $entry[$fKey] = (($_POST[$fKey] ?? '') === ($field['cvalue'] ?? '1')) ? $field['cvalue'] : '0';
                } else {
                    $entry[$fKey] = trim($_POST[$fKey] ?? '');
                }
            }
        }

        // Preserve last-run metadata when editing
        if ($editMode && isset($allRules[$id])) {
            $entry['last_updated'] = $allRules[$id]['last_updated'] ?? '';
            $entry['last_status']  = $allRules[$id]['last_status']  ?? '';
        }

        if ($editMode) {
            $allRules[$id] = $entry;
        } else {
            $allRules[] = $entry;
        }

        mwddns_save_rules($allRules);
        header('Location: /mwddns.php?msg=saved');
        exit;
    }
    // Fall through to re-render the form with errors.
}

// ── Page setup ────────────────────────────────────────────────────────────────
$pgtitle = [
    mwddns_t('Services'),
    mwddns_t('Multi-WAN DDNS'),
    $editMode ? mwddns_t('Edit Rule') : mwddns_t('Add Rule'),
];
$pglinks = ['', '/mwddns.php', '@self'];

include('head.inc');
?>
<body>
<?php include('fbegin.inc'); ?>

<section class="page-content-main">
<div class="container-fluid">
<div class="row">
<section class="col-xs-12">

<?php if (!empty($errors)): ?>
<div class="alert alert-danger" role="alert">
    <ul class="mb-0">
        <?php foreach ($errors as $err): ?>
        <li><?= htmlspecialchars($err) ?></li>
        <?php endforeach; ?>
    </ul>
</div>
<?php endif; ?>

<?php if ($forceResult !== null): ?>
<div class="alert alert-<?= $forceResult['ok'] ? 'success' : 'danger' ?>" role="alert">
    <strong><?= $forceResult['ok'] ? mwddns_t('Update succeeded') : mwddns_t('Update failed') ?>:</strong>
    <?= htmlspecialchars($forceResult['message']) ?>
    <?php if (!empty($forceResult['actions'])): ?>
    <ul class="mt-1 mb-0">
        <?php foreach ($forceResult['actions'] as $a): ?>
        <li>
            <span class="<?= $a['ok'] ? 'text-success' : 'text-danger' ?>">
                <?= htmlspecialchars(strtoupper($a['action'])) ?>
            </span>
            <?= htmlspecialchars($a['ip']) ?>
            <?php if (!$a['ok']): ?> – <?= htmlspecialchars($a['error']) ?><?php endif; ?>
        </li>
        <?php endforeach; ?>
    </ul>
    <?php endif; ?>
</div>
<?php endif; ?>

<!-- ── Main form ──────────────────────────────────────────────────────────── -->
<form method="post" action="/mwddns_edit.php<?= $editMode ? '?id=' . (int)$id : '' ?>"
      class="form-horizontal">
    <?= mwddns_csrf_input() ?>
    <input type="hidden" name="act" value="save">

    <!-- ── Panel 1: Common settings ─────────────────────────────────────── -->
    <div class="panel panel-default">
        <div class="panel-heading">
            <h2 class="panel-title"><?= mwddns_t('Common Settings') ?></h2>
        </div>
        <div class="panel-body">

            <!-- Rule Name -->
            <div class="form-group">
                <label class="col-sm-2 control-label" for="name">
                    <?= mwddns_t('Rule Name') ?> <span class="text-danger">*</span>
                </label>
                <div class="col-sm-10">
                    <input type="text" class="form-control" id="name" name="name"
                           value="<?= htmlspecialchars($name) ?>"
                           placeholder="<?= mwddns_t('e.g. Home WAN DDNS') ?>" required>
                    <span class="help-block"><?= mwddns_t('A descriptive label for this rule.') ?></span>
                </div>
            </div>

            <!-- Hostname -->
            <div class="form-group">
                <label class="col-sm-2 control-label" for="hostname">
                    <?= mwddns_t('Hostname') ?> <span class="text-danger">*</span>
                </label>
                <div class="col-sm-10">
                    <input type="text" class="form-control" id="hostname" name="hostname"
                           value="<?= htmlspecialchars($hostname) ?>"
                           placeholder="<?= mwddns_t('e.g. home.example.com') ?>" required>
                    <span class="help-block">
                        <?= mwddns_t('Fully-qualified domain name (FQDN) to update.') ?>
                    </span>
                </div>
            </div>

            <!-- TTL -->
            <div class="form-group">
                <label class="col-sm-2 control-label" for="ttl">
                    <?= mwddns_t('TTL (seconds)') ?> <span class="text-danger">*</span>
                </label>
                <div class="col-sm-10">
                    <input type="number" class="form-control" id="ttl" name="ttl"
                           value="<?= htmlspecialchars($ttl) ?>"
                           min="1" max="86400" required>
                    <span class="help-block">
                        <?= mwddns_t('Use 1 for automatic TTL. Range: 60–86400 s. Alibaba Cloud DNS minimum is 600 s.') ?>
                    </span>
                </div>
            </div>

            <!-- Interfaces -->
            <div class="form-group">
                <label class="col-sm-2 control-label" for="interfaces">
                    <?= mwddns_t('Interfaces') ?> <span class="text-danger">*</span>
                </label>
                <div class="col-sm-10">
                    <select class="form-control" id="interfaces" name="interfaces[]"
                            multiple size="<?= max(4, min(10, count($ifaceList))) ?>">
                        <?php foreach ($ifaceList as $ifkey => $ifreal): ?>
                        <?php $desc = mwddns_get_interface_desc($ifkey); ?>
                        <option value="<?= htmlspecialchars($ifkey) ?>"
                            <?= in_array($ifkey, $interfaces, true) ? 'selected' : '' ?>>
                            <?= htmlspecialchars($desc) ?> (<?= htmlspecialchars($ifkey) ?>)
                        </option>
                        <?php endforeach; ?>
                    </select>
                    <span class="help-block">
                        <?= mwddns_t('Hold Ctrl (Windows/Linux) or ⌘ (Mac) to select multiple interfaces. Each interface IP will be kept as a DNS record.') ?>
                    </span>
                </div>
            </div>

            <!-- Record Types -->
            <div class="form-group">
                <label class="col-sm-2 control-label">
                    <?= mwddns_t('Record Types') ?> <span class="text-danger">*</span>
                </label>
                <div class="col-sm-10">
                    <div class="checkbox-inline" style="margin-right:20px">
                        <label>
                            <input type="checkbox" name="record_types[]" value="A"
                                   <?= in_array('A', $recordTypes, true) ? 'checked' : '' ?>>
                            <?= mwddns_t('A (IPv4)') ?>
                        </label>
                    </div>
                    <div class="checkbox-inline">
                        <label>
                            <input type="checkbox" name="record_types[]" value="AAAA"
                                   <?= in_array('AAAA', $recordTypes, true) ? 'checked' : '' ?>>
                            <?= mwddns_t('AAAA (IPv6)') ?>
                        </label>
                    </div>
                    <span class="help-block">
                        <?= mwddns_t('Select which DNS record types to keep in sync. A = IPv4, AAAA = IPv6. You may select both for dual-stack hosts.') ?>
                        <?= mwddns_t('Interfaces without an address of the selected type are silently skipped.') ?>
                    </span>
                </div>
            </div>

        </div><!-- panel-body -->
    </div><!-- Panel 1 -->

    <!-- ── Panel 2: DNS Provider ─────────────────────────────────────────── -->
    <div class="panel panel-default">
        <div class="panel-heading">
            <h2 class="panel-title"><?= mwddns_t('DNS Provider') ?></h2>
        </div>
        <div class="panel-body">

            <!-- Provider selector -->
            <div class="form-group">
                <label class="col-sm-2 control-label" for="provider">
                    <?= mwddns_t('Provider') ?> <span class="text-danger">*</span>
                </label>
                <div class="col-sm-10">
                    <select class="form-control" id="provider" name="provider">
                        <?php foreach ($allProviders as $pKey => $pInfo): ?>
                        <option value="<?= htmlspecialchars($pKey) ?>"
                            <?= ($provider === $pKey) ? 'selected' : '' ?>>
                            <?= htmlspecialchars($pInfo['name']) ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                    <span class="help-block">
                        <?= mwddns_t('Select the DNS provider that hosts this hostname.') ?>
                    </span>
                </div>
            </div>

            <!-- Per-provider field sections (toggled by JS) -->
            <?php foreach ($allProviders as $pKey => $pInfo):
                $fieldsFn = "mwddns_{$pKey}_fields";
                if (!function_exists($fieldsFn)) {
                    continue;
                }
                $pFields  = $fieldsFn();
                $isActive = ($provider === $pKey);
            ?>
            <div data-provider-section="<?= htmlspecialchars($pKey) ?>"
                 style="<?= $isActive ? '' : 'display:none' ?>">
                <hr style="margin:8px 0 16px 0">
                <h4 class="text-muted" style="margin:0 0 12px 16px">
                    <?= htmlspecialchars($pInfo['name']) ?> <?= mwddns_t('Configuration') ?>
                </h4>
                <?php foreach ($pFields as $field):
                    $fKey  = $field['key'];
                    $fVal  = $rule[$fKey] ?? '';
                    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                        if ($field['type'] === 'checkbox') {
                            $fVal = $_POST[$fKey] ?? '';
                        } elseif (array_key_exists($fKey, $_POST)) {
                            $fVal = $_POST[$fKey];
                        }
                    }
                ?>

                <div class="form-group">
                    <label class="col-sm-2 control-label" for="f_<?= htmlspecialchars($fKey) ?>">
                        <?= htmlspecialchars($field['label']) ?>
                        <?php if (!empty($field['required'])): ?>
                        <span class="text-danger">*</span>
                        <?php endif; ?>
                    </label>
                    <div class="col-sm-10">

                        <?php if ($field['type'] === 'checkbox'): ?>
                        <div class="checkbox">
                            <label>
                                <input type="checkbox"
                                       id="f_<?= htmlspecialchars($fKey) ?>"
                                       name="<?= htmlspecialchars($fKey) ?>"
                                       value="<?= htmlspecialchars($field['cvalue'] ?? '1') ?>"
                                       <?= ($fVal === ($field['cvalue'] ?? '1')) ? 'checked' : '' ?>>
                                <?= htmlspecialchars($field['label']) ?>
                            </label>
                        </div>

                        <?php else: ?>
                        <input type="<?= htmlspecialchars($field['type']) ?>"
                               class="form-control"
                               id="f_<?= htmlspecialchars($fKey) ?>"
                               name="<?= htmlspecialchars($fKey) ?>"
                               value="<?= htmlspecialchars($fVal) ?>"
                               <?php if (!empty($field['placeholder'])): ?>
                               placeholder="<?= htmlspecialchars($field['placeholder']) ?>"
                               <?php endif; ?>
                               <?php if (!empty($field['pattern'])): ?>
                               pattern="<?= htmlspecialchars($field['pattern']) ?>"
                               <?php endif; ?>
                               <?= !empty($field['required']) ? 'data-required-field="1"' : '' ?>
                               <?= (!empty($field['required']) && $isActive) ? ' required' : '' ?>>
                        <?php endif; ?>

                        <?php if (!empty($field['help'])): ?>
                        <span class="help-block"><?= $field['help'] ?></span>
                        <?php endif; ?>
                    </div>
                </div>

                <?php endforeach; // fields ?>
            </div><!-- provider section -->
            <?php endforeach; // providers ?>

        </div><!-- panel-body -->
    </div><!-- Panel 2 -->

    <!-- ── Buttons ─────────────────────────────────────────────────────────── -->
    <nav class="action-buttons">
        <button type="submit" class="btn btn-primary btn-sm" name="act" value="save">
            <i class="fa fa-save icon-embed-btn"></i>
            <?= mwddns_t('Save') ?>
        </button>

        <?php if ($editMode): ?>
        <button type="submit" class="btn btn-warning btn-sm"
                name="act" value="force_update"
                formaction="/mwddns_edit.php?id=<?= (int)$id ?>"
                title="<?= mwddns_t('Immediately push current interface IPs to the DNS provider') ?>">
            <i class="fa fa-refresh icon-embed-btn"></i>
            <?= mwddns_t('Force Update') ?>
        </button>
        <?php endif; ?>

        <a href="/mwddns.php" class="btn btn-default btn-sm">
            <i class="fa fa-times icon-embed-btn"></i>
            <?= mwddns_t('Cancel') ?>
        </a>
    </nav>
</form>

</section>
</div>
</div>
</section>

<script>
(function () {
    var sel = document.getElementById('provider');

    function switchProvider(key) {
        document.querySelectorAll('[data-provider-section]').forEach(function (el) {
            var active = el.getAttribute('data-provider-section') === key;
            el.style.display = active ? '' : 'none';
            // Adjust HTML5 required on inputs so browser validation only
            // fires for the visible provider section.
            el.querySelectorAll('input[type=text], input[type=password], input[type=number], input[type=url], input[type=email], select, textarea').forEach(function (inp) {
                inp.required = active && inp.hasAttribute('data-required-field');
            });
        });
    }

    // Mark originally-required inputs so we can restore required after switch.
    document.querySelectorAll('[data-provider-section] input[required]:not([type=checkbox]), [data-provider-section] select[required], [data-provider-section] textarea[required]').forEach(function (inp) {
        inp.setAttribute('data-required-field', '1');
    });

    sel.addEventListener('change', function () { switchProvider(this.value); });
    switchProvider(sel.value);
}());
</script>

<?php include('foot.inc'); ?>
