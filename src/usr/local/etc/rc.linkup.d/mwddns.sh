#!/bin/sh
# mwddns link event hook – trigger sync when interface link goes up/down (e.g. IP lost)

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
