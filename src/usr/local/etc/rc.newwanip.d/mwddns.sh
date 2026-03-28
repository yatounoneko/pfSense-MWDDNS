#!/bin/sh
# mwddns.sh - Trigger MWDDNS sync on interface IP changes (rc.newwanip hook)

CMD="/usr/local/bin/mwddns_cron.php"
IFACE="${interface:-${1:-}}"

if [ -x "${CMD}" ]; then
    if [ -n "${IFACE}" ]; then
        "${CMD}" "${IFACE}"
    else
        "${CMD}"
    fi
fi

exit 0
