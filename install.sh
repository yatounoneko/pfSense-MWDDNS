#!/bin/sh
# install.sh – Manual installation helper for pfSense-MWDDNS
#
# Run this script from the repository root on a pfSense 2.7/2.8 firewall
# (or copy files to the correct paths manually).
#
# Usage:
#   sh install.sh                            Install (or reinstall) the plugin
#   sh install.sh --uninstall                Remove files and cron; KEEP config.xml data
#   sh install.sh --uninstall --purge-config Remove files, cron AND config.xml data
#                                            (interactive confirmation required)
#   sh install.sh --help                     Show this help text
#
# Examples:
#   sh install.sh
#   sh install.sh --uninstall
#   sh install.sh --uninstall --purge-config

set -e

SRC="$(cd "$(dirname "$0")/src" && pwd)"

PKG_INC="/usr/local/pkg/mwddns.inc"
PKG_XML="/usr/local/pkg/mwddns.xml"
WWW_MAIN="/usr/local/www/mwddns.php"
WWW_EDIT="/usr/local/www/mwddns_edit.php"
WWW_WIDGET="/usr/local/www/widgets/widgets/mwddns.widget.php"
CRON_SCRIPT="/usr/local/bin/mwddns_cron.php"
RC_NEWWAN="/usr/local/etc/rc.newwanip.d/mwddns.sh"
RC_GW_ALARM="/usr/local/etc/rc.gateway_alarm.d/mwddns.sh"
RC_LINKUP="/usr/local/etc/rc.linkup.d/mwddns.sh"
PKG_VERSION="1.0.2"

# ---------------------------------------------------------------------------
# usage: print help text and exit
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
install.sh – Manual installation helper for pfSense-MWDDNS

USAGE
  sh install.sh                            Install (or reinstall) the plugin
  sh install.sh --uninstall                Remove files/cron; preserve config.xml data
  sh install.sh --uninstall --purge-config Remove files/cron AND config.xml data
                                           (interactive confirmation required)
  sh install.sh --help | -h                Show this help text

OPTIONS
  --uninstall       Uninstall the plugin.  Config data in config.xml is kept
                    unless --purge-config is also given.
  --purge-config    Only valid together with --uninstall.  Permanently deletes
                    all MWDDNS settings from pfSense config.xml via the pfSense
                    PHP config API.  Requires interactive confirmation (Y/N).
  --help, -h        Display this help text and exit.

EXAMPLES
  # Install
  sh install.sh

  # Uninstall but keep settings
  sh install.sh --uninstall

  # Uninstall and wipe settings (will ask for confirmation)
  sh install.sh --uninstall --purge-config
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# install_files: copy plugin to pfSense target paths and register cron
# ---------------------------------------------------------------------------
install_files() {
    echo "==> Installing Multi-WAN DDNS plugin..."

    install -m 0644 "${SRC}/usr/local/pkg/mwddns.inc" "${PKG_INC}"
    install -m 0644 "${SRC}/usr/local/pkg/mwddns.xml" "${PKG_XML}"

    # Provider modules
    mkdir -p /usr/local/pkg/mwddns
    install -m 0644 "${SRC}/usr/local/pkg/mwddns/cloudflare.php" /usr/local/pkg/mwddns/cloudflare.php
    install -m 0644 "${SRC}/usr/local/pkg/mwddns/alidns.php"     /usr/local/pkg/mwddns/alidns.php
    install -m 0644 "${SRC}/usr/local/pkg/mwddns/aliesa.php"      /usr/local/pkg/mwddns/aliesa.php
    install -m 0644 "${SRC}/usr/local/pkg/mwddns/powerdns.php"    /usr/local/pkg/mwddns/powerdns.php

    # GUI locale files (Simplified Chinese / Traditional Chinese)
    mkdir -p /usr/local/pkg/mwddns/locale
    install -m 0644 "${SRC}/usr/local/pkg/mwddns/locale/zh_CN.php" /usr/local/pkg/mwddns/locale/zh_CN.php
    install -m 0644 "${SRC}/usr/local/pkg/mwddns/locale/zh_HK.php" /usr/local/pkg/mwddns/locale/zh_HK.php

    install -m 0644 "${SRC}/usr/local/www/mwddns.php" "${WWW_MAIN}"
    install -m 0644 "${SRC}/usr/local/www/mwddns_edit.php" "${WWW_EDIT}"
    install -m 0755 "${SRC}/usr/local/bin/mwddns_cron.php" "${CRON_SCRIPT}"

    # Hook into interface IP change events
    mkdir -p /usr/local/etc/rc.newwanip.d
    install -m 0755 "${SRC}/usr/local/etc/rc.newwanip.d/mwddns.sh" "${RC_NEWWAN}"
    # Hook into gateway alarm events (dpinger status changes)
    mkdir -p /usr/local/etc/rc.gateway_alarm.d
    install -m 0755 "${SRC}/usr/local/etc/rc.gateway_alarm.d/mwddns.sh" "${RC_GW_ALARM}"
    # Hook into link up/down events (captures IP loss immediately)
    mkdir -p /usr/local/etc/rc.linkup.d
    install -m 0755 "${SRC}/usr/local/etc/rc.linkup.d/mwddns.sh" "${RC_LINKUP}"

    # Ensure widget directory exists
    mkdir -p /usr/local/www/widgets/widgets
    install -m 0644 \
        "${SRC}/usr/local/www/widgets/widgets/mwddns.widget.php" \
        "${WWW_WIDGET}"

    # Register cron job via pfSense PHP bootstrap
    /usr/local/bin/php -r "
        require_once('/etc/inc/globals.inc');
        require_once('/etc/inc/functions.inc');
        require_once('/etc/inc/config.inc');
        require_once('/usr/local/pkg/mwddns.inc');
        \$config = parse_config(true);
        mwddns_install_cron();
        echo 'Cron job registered.' . PHP_EOL;
    "

    # Register/fix package in installedpackages so pfSense menu can render Services entry
    /usr/local/bin/php -r "
        require_once('/etc/inc/globals.inc');
        require_once('/etc/inc/functions.inc');
        require_once('/etc/inc/config.inc');
        global \$config;
        \$config = parse_config(true);
        \$pkgDescr = 'Multi-WAN DDNS';

        \$packages = \$config['installedpackages']['package'] ?? [];
        if (isset(\$packages['name'])) {
            \$packages = [\$packages];
        } elseif (!is_array(\$packages)) {
            \$packages = [];
        }

        \$menus = \$config['installedpackages']['menu'] ?? [];
        if (isset(\$menus['name']) && isset(\$menus['section'])) {
            \$menus = [\$menus];
        } elseif (!is_array(\$menus)) {
            \$menus = [];
        }

        \$changed = false;
        \$found = false;
        foreach (array_keys(\$packages) as \$idx) {
            \$pkg = \$packages[\$idx];
            if ((\$pkg['name'] ?? '') === 'mwddns' || (\$pkg['internal_name'] ?? '') === 'mwddns') {
                \$found = true;
                if ((\$pkg['name'] ?? '') !== 'mwddns') {
                    \$packages[\$idx]['name'] = 'mwddns';
                    \$changed = true;
                }
                if ((\$pkg['internal_name'] ?? '') !== 'mwddns') {
                    \$packages[\$idx]['internal_name'] = 'mwddns';
                    \$changed = true;
                }
                if ((\$pkg['xml'] ?? '') !== 'mwddns.xml') {
                    \$packages[\$idx]['xml'] = 'mwddns.xml';
                    \$changed = true;
                }
                if ((\$pkg['configurationfile'] ?? '') !== 'mwddns.xml') {
                    \$packages[\$idx]['configurationfile'] = 'mwddns.xml';
                    \$changed = true;
                }
                if ((\$pkg['descr'] ?? '') === '') {
                    \$packages[\$idx]['descr'] = \$pkgDescr;
                    \$changed = true;
                }
                if ((\$pkg['version'] ?? '') !== '${PKG_VERSION}') {
                    \$packages[\$idx]['version'] = '${PKG_VERSION}';
                    \$changed = true;
                }
                break;
            }
        }

        if (!\$found) {
            \$packages[] = [
                'name'          => 'mwddns',
                'internal_name' => 'mwddns',
                'xml'           => 'mwddns.xml',
                'configurationfile' => 'mwddns.xml',
                'version'       => '${PKG_VERSION}',
                'descr'         => \$pkgDescr,
            ];
            \$changed = true;
        }

        \$menuFound = false;
        foreach (array_keys(\$menus) as \$idx) {
            \$menu = \$menus[\$idx];
            if ((\$menu['name'] ?? '') === 'Multi-WAN DDNS' && (\$menu['section'] ?? '') === 'Services') {
                \$menuFound = true;
                if ((\$menu['name'] ?? '') !== 'Multi-WAN DDNS') {
                    \$menus[\$idx]['name'] = 'Multi-WAN DDNS';
                    \$changed = true;
                }
                if ((\$menu['tooltiptext'] ?? '') !== 'Multi-WAN Dynamic DNS (Cloudflare / Alibaba Cloud DNS / Alibaba Cloud ESA / PowerDNS)') {
                    \$menus[\$idx]['tooltiptext'] = 'Multi-WAN Dynamic DNS (Cloudflare / Alibaba Cloud DNS / Alibaba Cloud ESA / PowerDNS)';
                    \$changed = true;
                }
                if ((\$menu['section'] ?? '') !== 'Services') {
                    \$menus[\$idx]['section'] = 'Services';
                    \$changed = true;
                }
                if ((\$menu['configfile'] ?? '') !== 'mwddns.xml') {
                    \$menus[\$idx]['configfile'] = 'mwddns.xml';
                    \$changed = true;
                }
                if ((\$menu['url'] ?? '') !== '/mwddns.php') {
                    \$menus[\$idx]['url'] = '/mwddns.php';
                    \$changed = true;
                }
                break;
            }
        }

        if (!\$menuFound) {
            \$menus[] = [
                'name'       => 'Multi-WAN DDNS',
                'tooltiptext' => 'Multi-WAN Dynamic DNS (Cloudflare / Alibaba Cloud DNS / Alibaba Cloud ESA / PowerDNS)',
                'section'    => 'Services',
                'configfile' => 'mwddns.xml',
                'url'        => '/mwddns.php',
            ];
            \$changed = true;
        }

        if (\$changed) {
            \$config['installedpackages']['package'] = array_values(\$packages);
            \$config['installedpackages']['menu'] = array_values(\$menus);
            write_config('MWDDNS: register/fix package and menu for Services');
            echo (\$found ? 'Package registration updated.' : 'Package registration added.') . PHP_EOL;
            echo (\$menuFound ? 'Menu registration updated.' : 'Menu registration added.') . PHP_EOL;
        } else {
            echo 'Package/menu registration already valid.' . PHP_EOL;
        }
    " 2>/dev/null || true

    echo "==> Installation complete."
    echo "    Navigate to Services > Multi-WAN DDNS in the pfSense web UI."
}

# ---------------------------------------------------------------------------
# purge_config: delete the mwddns section from pfSense config.xml using the
#               official PHP config API (parse_config / write_config).
#               Must NOT use sed/awk to edit config.xml directly.
# ---------------------------------------------------------------------------
purge_config() {
    echo "    Removing MWDDNS configuration from config.xml..."
    /usr/local/bin/php -r "
        require_once('/etc/inc/globals.inc');
        require_once('/etc/inc/functions.inc');
        require_once('/etc/inc/config.inc');
        global \$config;
        \$config = parse_config(true);
        if (isset(\$config['mwddns'])) {
            unset(\$config['mwddns']);
            write_config('MWDDNS: configuration purged by uninstall');
            echo 'MWDDNS configuration removed from config.xml.' . PHP_EOL;
        } else {
            echo 'No MWDDNS configuration found in config.xml (nothing to purge).' . PHP_EOL;
        }
    " 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# uninstall_files: remove plugin files and cron.
#   $1 = 1  → also purge config (caller must have already confirmed)
#   $1 = 0  → keep config (default)
# ---------------------------------------------------------------------------
uninstall_files() {
    _do_purge="${1:-0}"

    echo "==> Removing Multi-WAN DDNS plugin..."

    # Step 1 – remove cron job
    /usr/local/bin/php -r "
        require_once('/etc/inc/globals.inc');
        require_once('/etc/inc/functions.inc');
        require_once('/etc/inc/config.inc');
        require_once('/usr/local/pkg/mwddns.inc');
        \$config = parse_config(true);
        mwddns_remove_cron();
        echo 'Cron job removed.' . PHP_EOL;
    " 2>/dev/null || true

    # Step 2 – purge config if requested and confirmed
    if [ "${_do_purge}" = "1" ]; then
        purge_config
    fi

    # Step 2.5 – unregister package from installedpackages menu list
    /usr/local/bin/php -r "
        require_once('/etc/inc/globals.inc');
        require_once('/etc/inc/functions.inc');
        require_once('/etc/inc/config.inc');
        global \$config;
        \$config = parse_config(true);

        \$packages = \$config['installedpackages']['package'] ?? [];
        if (isset(\$packages['name'])) {
            \$packages = [\$packages];
        } elseif (!is_array(\$packages)) {
            \$packages = [];
        }

        \$menus = \$config['installedpackages']['menu'] ?? [];
        if (isset(\$menus['name']) && isset(\$menus['section'])) {
            \$menus = [\$menus];
        } elseif (!is_array(\$menus)) {
            \$menus = [];
        }

        \$changed = false;
        \$filtered = [];
        foreach (\$packages as \$pkg) {
            if ((\$pkg['name'] ?? '') === 'mwddns' || (\$pkg['internal_name'] ?? '') === 'mwddns') {
                \$changed = true;
                continue;
            }
            \$filtered[] = \$pkg;
        }

        \$menuFiltered = [];
        \$menuChanged = false;
        foreach (\$menus as \$menu) {
            if ((\$menu['name'] ?? '') === 'Multi-WAN DDNS' && (\$menu['section'] ?? '') === 'Services') {
                \$menuChanged = true;
                continue;
            }
            \$menuFiltered[] = \$menu;
        }

        if (\$changed) {
            \$config['installedpackages']['package'] = array_values(\$filtered);
            \$config['installedpackages']['menu'] = array_values(\$menuFiltered);
            write_config('MWDDNS: unregister package and menu from Services');
            echo 'Package registration removed.' . PHP_EOL;
            echo (\$menuChanged ? 'Menu registration removed.' : 'Menu registration not found.') . PHP_EOL;
        } else {
            echo 'Package registration not found.' . PHP_EOL;
            if (\$menuChanged) {
                \$config['installedpackages']['menu'] = array_values(\$menuFiltered);
                write_config('MWDDNS: remove orphan menu registration');
                echo 'Menu registration removed.' . PHP_EOL;
            } else {
                echo 'Menu registration not found.' . PHP_EOL;
            }
        }
    " 2>/dev/null || true

    # Step 3 – delete plugin files and provider directory
    rm -f "${PKG_INC}" "${PKG_XML}" "${WWW_MAIN}" "${WWW_EDIT}" \
          "${WWW_WIDGET}" "${CRON_SCRIPT}" "${RC_NEWWAN}" "${RC_GW_ALARM}" "${RC_LINKUP}"
    rm -rf /usr/local/pkg/mwddns

    if [ "${_do_purge}" = "1" ]; then
        echo "==> Removal complete. Config data has been purged from config.xml."
    else
        echo "==> Removal complete. Config data in config.xml is preserved."
    fi
}

# ---------------------------------------------------------------------------
# confirm_purge: interactive Y/N prompt.
# Returns 0 (true) if the user confirms, 1 (false) otherwise.
# In non-interactive environments (no tty on stdin) the purge is skipped.
# ---------------------------------------------------------------------------
confirm_purge() {
    # Non-interactive guard: if stdin is not a terminal, skip purge
    if ! [ -t 0 ]; then
        echo "    Warning: non-interactive mode detected, skip purge-config."
        return 1
    fi

    printf '\n'
    printf '  !!! WARNING !!!\n'
    printf '  This action will PERMANENTLY DELETE all MWDDNS settings from\n'
    printf '  pfSense config.xml and CANNOT be undone.\n'
    printf '\n'
    printf '  此動作將永久刪除 MWDDNS 設定，是否繼續？ [y/N] '
    read -r _answer

    case "${_answer}" in
        [Yy])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
_do_uninstall=0
_do_purge=0

for _arg in "$@"; do
    case "${_arg}" in
        --uninstall|-u)
            _do_uninstall=1
            ;;
        --purge-config)
            _do_purge=1
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "Error: unknown option '${_arg}'" >&2
            echo "Run 'sh install.sh --help' for usage information." >&2
            exit 1
            ;;
    esac
done

# --purge-config is only valid together with --uninstall
if [ "${_do_purge}" = "1" ] && [ "${_do_uninstall}" = "0" ]; then
    echo "Error: --purge-config can only be used together with --uninstall." >&2
    echo "  Usage: sh install.sh --uninstall --purge-config" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
if [ "${_do_uninstall}" = "1" ]; then
    if [ "${_do_purge}" = "1" ]; then
        if confirm_purge; then
            uninstall_files 1
        else
            echo "    Purge cancelled. Proceeding with standard uninstall (config preserved)."
            uninstall_files 0
        fi
    else
        uninstall_files 0
    fi
else
    install_files
fi
