#!/bin/sh
# mwddns gateway alarm hook – trigger immediate sync on gateway state changes

CMD="/usr/local/bin/mwddns_cron.php"
IFACE="${1:-}"

if [ -x "${CMD}" ]; then
    if [ -n "${IFACE}" ]; then
        "${CMD}" "${IFACE}"
    else
        "${CMD}"
    fi
fi

exit 0
