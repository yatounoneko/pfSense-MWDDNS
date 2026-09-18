#!/usr/local/bin/python3.11
"""Bounded, offline, strict-privacy export of existing pfSense diagnostics.

No raw messages, names, configuration or redaction dictionaries are written.
Unrecognized event details are deliberately omitted, not guessed to be safe.
"""
import bz2
import datetime as dt
import gzip
import heapq
import ipaddress
import json
import lzma
import math
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import quote

BASE = Path("/var/run/mwddns/debug")
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_REPORT = 6 * 1024 * 1024
MAX_EVENTS = 5000
MIN_SOURCE_EVENTS = 256
MAX_SOURCE_EVENTS = 2000
DHCP_BUCKET_SECONDS = 300
MAX_DHCP_BUCKETS = 14 * 86400 // DHCP_BUCKET_SECONDS + 1
MAX_LINE = 16384
SOURCE_SECONDS = 6
AGGREGATION_SECONDS = 3600
MONTHS = {name: index + 1 for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"))}
PROCESSES = {
    "php", "php-fpm", "python3.11", "daemon", "cron", "dpinger",
    "dhclient", "dhcp6c", "mwddns_watcher", "nginx", "ppp", "kernel",
}
PROVIDERS = {"cloudflare", "alidns_intl", "alidns_cn", "aliesa", "powerdns"}
FUNCTIONS = {
    "parse_config", "config_read_file", "write_config", "curl_close",
    "get_interface_ip", "get_interface_ipv6", "get_dpinger_status",
    "return_gateways_array", "mwddns_collect_ips_for_rule",
    "mwddns_update_all", "mwddns_update_rule", "mwddns_reload_config",
}
FILES = {
    "mwddns.inc", "mwddns_cron.php", "mwddns_gateway_watcher.py",
    "mwddns.php", "mwddns_edit.php", "mwddns_debug.php", "debug.inc",
    "cloudflare.php", "alidns.php", "aliesa.php", "powerdns.php",
}
EVENT_PATTERNS = {
    "DNS_PRESERVED": r"records? preserved|preserv(?:e|ing).*records?",
    "ADDRESS_UNAVAILABLE": r"interface address is unavailable|no (?:ipv4|ipv6)",
    "MONITOR_UNKNOWN": r"monitoring is unknown|gateway mapping is unknown",
    "UPDATE_START": r"\bupdating\b",
    "UPDATE_OK": r"\bupdate\b.*\bOK\b|\]\s+OK\b",
    "UPDATE_FAIL": r"\bFAIL\b|update failed|update not started",
    "WATCHER_STARTED": r"watcher started",
    "GATEWAY_CHANGE": r"state.*chang|gateway.*(?:alarm|down|online)",
    "ROUTING_STATES_CLEARED": r"killed policy routing states",
    "DHCP_DISCOVER": r"\bDHCPDISCOVER\b",
    "DHCP_REQUEST": r"\bDHCPREQUEST\b",
    "DHCP_ACK": r"\bDHCPACK\b",
    "DHCP_NAK": r"\bDHCPNA(?:C)?K\b",
    "DHCP_OFFER": r"\bDHCPOFFER\b",
    "DHCP_BOUND": r"\bbound to\b",
    "DHCP_RENEW": r"\brenew(?:al|ing|ed)?\b",
    "DHCP_REBIND": r"\brebind(?:ing)?\b",
    "DHCP_NO_OFFER": r"\bno DHCPOFFERS received\b",
    "DHCP_NO_LEASE": r"\bno working leases\b",
    "DHCP_ADDRESS_REMOVED": r"\bmy address\b.*\bwas deleted\b",
    "LEASE_EXPIRED": r"\blease(?:\s+(?:has|had))?\s+expired\b",
    "LINK_DOWN": r"\blink state(?: changed to|\s+(?:up|down)\s*->)\s*down\b|\blink(?: is)? down\b",
    "LINK_UP": r"\blink state(?: changed to|\s+(?:up|down)\s*->)\s*up\b|\blink(?: is)? up\b",
    "INTERFACE_DOWN": r"\binterface\s+\S+\s+is down\b",
    "NEW_WAN_ADDRESS": r"rc\.newwanip|newwanipv6",
    "INTERFACE_RECONFIGURE": r"rc\.linkup|rc\.newwanip|interface.*reconfig",
    "UNDEFINED_FUNCTION": r"undefined function",
    "PHP_FATAL": r"fatal error|uncaught (?:error|exception|typeerror)|ERROR PHP ERROR: Type: 1,",
    "DEPRECATED": r"\bdeprecated\b",
    "UPSTREAM_ERROR": r"upstream.*(?:fail|error|timed out|closed)|connect\(\) failed",
    "HTTP_5XX": r"\bHTTP[/ :=0-9.]*\s5\d\d\b|\"\s+5\d\d\s",
    "TIMEOUT": r"timed? ?out|timeout",
    "MEMORY_ERROR": r"out of memory|cannot allocate memory|memory size.*exhausted",
    "PROCESS_CRASH": r"segfault|segmentation fault|signal 11|core dumped",
    "PROCESS_EXIT": r"exiting on signal|child .* exited",
    "SOCKET_ERROR": r"sendto error|socket.*(?:error|fail)",
    "PERMISSION_DENIED": r"permission denied",
    "WORKER_LIMIT": r"max_children|server reached",
}
EVENT_PATTERNS = {key: re.compile(value, re.I) for key, value in EVENT_PATTERNS.items()}
SENSITIVE = re.compile(
    r"authorization|cookie|token|password|passwd|secret|credential|private.?key|"
    r"api.?key|access.?key|PHPSESSID|session.?id|\bbearer\b|"
    r"\b(?:key|auth|signature)\s*[:=]|BEGIN .*PRIVATE KEY", re.I)
NETWORK = re.compile(
    r"dhclient|dhcp6c|dpinger|gateway|rc\.newwanip|rc\.linkup|"
    r"link state|interface.*(?:address|reconfig)|ppp", re.I)
PLUGIN = re.compile(r"mwddns|multi.wan ddns", re.I)
WEB = re.compile(
    r"php-fpm|PHP (?:Fatal|Warning|Deprecated)|ERROR PHP|"
    r"nginx|upstream|segfault|segmentation fault|out of memory|cannot allocate memory", re.I)
V4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
V6 = re.compile(r"(?<![\w:])[0-9a-fA-F]*:[0-9a-fA-F:.]+(?:%[\w.-]+)?(?![\w:])")
MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
BSD = re.compile(r"^(?:<\d+>)?([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d:\d\d:\d\d)\s+\S+\s+(.*)$")
ISO = re.compile(r"^(?:<\d+>\d+\s+)?(\d{4}-\d\d-\d\dT\S+)\s+(.*)$")
PHP_DATE = re.compile(r"^\[(\d{2})-([A-Z][a-z]{2})-(\d{4}) (\d\d:\d\d:\d\d)(?: ([^\]]+))?\]\s*(.*)$")
NGINX_DATE = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)\s+(.*)$")


def stamp(epoch):
    return dt.datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="seconds")


def atomic(path, value):
    temporary = path.with_name(path.name + ".tmp")
    if path.is_symlink() or temporary.is_symlink():
        raise ValueError("Unsafe output")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=True, indent=2)
        handle.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def small_file(path, limit):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Unavailable input")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Input limit")
    return data


def number(value, maximum=1000000):
    try:
        value = float(value)
        return value if math.isfinite(value) and 0 <= value <= maximum else None
    except (TypeError, ValueError):
        return None


def enum(value, allowed, fallback="unknown"):
    return value if isinstance(value, str) and value in allowed else fallback


def timestamp(line, reference, now):
    """Return timestamp and payload, never an unvalidated date string."""
    match = BSD.match(line)
    if match and match[1] in MONTHS:
        anchor = dt.datetime.fromtimestamp(min(reference, now + 300))
        candidates = []
        for year in (anchor.year - 1, anchor.year, anchor.year + 1):
            try:
                value = dt.datetime.strptime(
                    f"{year}-{MONTHS[match[1]]:02d}-{int(match[2]):02d} {match[3]}",
                    "%Y-%m-%d %H:%M:%S").timestamp()
                if value <= min(reference, now + 300) + 86400:
                    candidates.append(value)
            except ValueError:
                pass
        if candidates:
            return min(candidates, key=lambda value: abs(value - reference)), match[4]
    match = ISO.match(line)
    if match:
        try:
            return dt.datetime.fromisoformat(match[1].replace("Z", "+00:00")).timestamp(), match[2]
        except ValueError:
            pass
    match = PHP_DATE.match(line)
    if match and match[2] in MONTHS:
        try:
            value = dt.datetime.strptime(
                f"{match[3]}-{MONTHS[match[2]]:02d}-{match[1]} {match[4]}",
                "%Y-%m-%d %H:%M:%S")
            if match[5]:
                from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
                try:
                    value = value.replace(tzinfo=ZoneInfo(match[5]))
                except (ZoneInfoNotFoundError, ValueError):
                    if match[5] in ("UTC", "GMT"):
                        value = value.replace(tzinfo=dt.timezone.utc)
                    else:
                        return None, ""
            return value.timestamp(), match[6]
        except ValueError:
            pass
    match = NGINX_DATE.match(line)
    if match:
        try:
            return dt.datetime.strptime(match[1], "%Y/%m/%d %H:%M:%S").timestamp(), match[2]
        except ValueError:
            pass
    return None, ""


class Privacy:
    def __init__(self, context):
        self.ids = {}
        self.counts = {}
        self.names = []
        self.ip_owners = {}
        self.secrets = set()
        for value in context.get("secrets", []):
            if isinstance(value, str) and value:
                self.secrets.update((value, quote(value, safe="")))
        for kind, rows in (("WAN", context["wans"]), ("RULE", context["rules"])):
            for row in rows:
                alias = row.get("alias", "")
                if not re.fullmatch(kind + r"_\d+", alias):
                    raise ValueError("Invalid alias")
                names = [value for value in row["names"] if isinstance(value, str) and value]
                for name in names:
                    self.names.append((kind, alias, re.compile(
                        r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])", re.I)))
                if kind == "WAN":
                    for field in ("ipv4", "ipv6"):
                        tag = self.ip(row.get(field))
                        if tag:
                            self.ip_owners.setdefault(tag, set()).add(alias)

    def alias(self, kind, value):
        key = (kind, value)
        if key not in self.ids:
            self.counts[kind] = self.counts.get(kind, 0) + 1
            self.ids[key] = f"{kind}_{self.counts[kind]}"
        return self.ids[key]

    def ip(self, value):
        if not isinstance(value, str):
            return None
        try:
            address = ipaddress.ip_address(value.rstrip(".").split("%", 1)[0])
            return self.alias("IP" + str(address.version), str(address))
        except ValueError:
            return None

    def refs(self, text, kind):
        return sorted({alias for group, alias, pattern in self.names
                       if group == kind and pattern.search(text)})

    def dhcp_details(self, payload):
        """Only explicit log roles, never guessed DHCP state or lease duration."""
        details = {}
        for role, pattern in (
            ("destination_ip", r"\bDHCP(?:REQUEST|DISCOVER|DECLINE|RELEASE)\s+on\s+\S+\s+to\s+([^\s,;]+)"),
            ("server_ip", r"\b(?:DHCP(?:ACK|NAK|NACK|OFFER)|BOOTREPLY)\s+from\s+([^\s,;]+)"),
            ("leased_ip", r"\bbound to\s+([^\s,;]+)"),
        ):
            match = re.search(pattern, payload, re.I)
            if match and (tag := self.ip(match[1])):
                details[role] = tag
                if role == "destination_ip":
                    address = ipaddress.ip_address(match[1].rstrip(".").split("%", 1)[0])
                    details["destination_kind"] = (
                        "broadcast" if str(address) == "255.255.255.255" else
                        "multicast" if address.is_multicast else "unicast")
        match = re.search(
            r"\breason(?:\s*[:=]\s*|\s+)[\"']?"
            r"(PREINIT|BOUND|RENEW|REBIND|REBOOT|EXPIRE|FAIL|TIMEOUT|STOP|RELEASE|MEDIUM|ARPCHECK|ARPSEND)\b",
            payload, re.I)
        if match:
            details["script_reason"] = match[1].upper()
        for field, pattern in (
            ("retry_interval_seconds", r"\binterval\s+(\d+)\b"),
            ("renewal_seconds", r"\brenewal in\s+(\d+)\s+seconds\b"),
            ("lease_seconds", r"\blease(?:[- ]time)?\s*[:=]\s*(\d+)\s+seconds\b"),
        ):
            match = re.search(pattern, payload, re.I)
            if match and (value := number(match[1], 31536000)) is not None:
                details[field] = int(value)
        return details

    def event(self, payload, epoch, source):
        wans = self.refs(payload, "WAN")
        rules = self.refs(payload, "RULE")
        event = {"time": stamp(epoch), "source": source, "wans": wans, "rules": rules}
        if SENSITIVE.search(payload) or any(secret in payload for secret in self.secrets):
            event["events"] = ["SENSITIVE_LINE_OMITTED"]
            return event
        events = [key for key, pattern in EVENT_PATTERNS.items() if pattern.search(payload)]
        event["events"] = events or ["UNCLASSIFIED_DETAILS_OMITTED"]
        event["ips"] = sorted({tag for pattern in (V4, V6) for match in pattern.finditer(payload)
                               if (tag := self.ip(match[0]))})
        event["macs"] = sorted({self.alias("MAC", match[0].lower()) for match in MAC.finditer(payload)})
        if wans:
            event["wan_attribution"] = "explicit_name"
        if re.search(r"\b(?:dhclient|dhcp6c|dhclient-script)\b", payload, re.I):
            details = self.dhcp_details(payload)
            if details:
                event["dhcp"] = details
                if "script_reason" in details:
                    if event["events"] == ["UNCLASSIFIED_DETAILS_OMITTED"]:
                        event["events"] = []
                    event["events"].append("DHCP_SCRIPT_REASON")
                # A server/destination IP is NOT an interface owner. Only a
                # leased-address match may provide explicitly labelled evidence.
                if not wans and details.get("leased_ip") in self.ip_owners:
                    event["wans"] = sorted(self.ip_owners[details["leased_ip"]])
                    event["wan_attribution"] = "current_lease_address_match"
        process = re.search(r"\b([A-Za-z0-9_.-]+)\[(\d{1,8})\]:", payload)
        if process:
            event["process"] = enum(process[1], PROCESSES, "OTHER")
            event["pid"] = int(process[2])
        for severity in ("emerg", "alert", "crit", "error", "warning", "notice", "info", "debug"):
            if re.search(r"\b" + severity + r"\b", payload, re.I):
                event["severity"] = severity
                break
        match = re.search(r"undefined function\s+([A-Za-z0-9_\\]+)\s*\(", payload, re.I)
        if match:
            event["function"] = match[1] if match[1] in FUNCTIONS else self.alias("FUNCTION", match[1])
        matched_files = [name for name in sorted(FILES)
                         if re.search(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])", payload)]
        if matched_files:
            event["files"] = matched_files
        metrics = {}
        for field, pattern, maximum in (
            ("source_line", r"\b(?:Line:|on line)\s*(\d+)", 1000000),
            ("socket_errno", r"\b(?:sendto error|errno)\s*[:=]?\s*(\d+)", 4096),
            ("signal", r"\bsignal\s+(\d+)", 128),
            ("latency_ms", r"\blatency(?:_alarm)?[ :=]+(\d+(?:\.\d+)?)\s*ms", 1000000),
            ("loss_percent", r"\bloss(?:_alarm)?[ :=]+(\d+(?:\.\d+)?)\s*%", 100),
            ("renewal_seconds", r"\brenewal in\s+(\d+)\s+seconds", 31536000),
            ("http_status", r"\b(?:HTTP(?:/\d(?:\.\d)?)?|status|code)[ :=]+([45]\d\d)\b", 599),
        ):
            match = re.search(pattern, payload, re.I)
            if match and (value := number(match[1], maximum)) is not None:
                metrics[field] = value
        if metrics:
            event["metrics"] = metrics
        states = sorted(set(re.findall(r"\b(online|down|unknown)\b", payload, re.I)))
        if states:
            event["mentioned_states"] = [state.lower() for state in states]
        return event


def runtime_snapshot(context, privacy, enabled):
    result = {"enabled": enabled, "wans": [], "rules": []}
    for row in context["wans"]:
        wan = {"id": row["alias"], "enabled": bool(row.get("enabled"))}
        if enabled:
            wan.update(ipv4=privacy.ip(row.get("ipv4")), ipv6=privacy.ip(row.get("ipv6")))
            wan["gateways"] = [{
                "family": enum(gw.get("family"), {"A", "AAAA"}),
                "state": enum(gw.get("state"), {"online", "down", "unknown"}),
                "disabled": bool(gw.get("disabled")),
                "unmonitored": bool(gw.get("unmonitored")),
                "latency_high_ms": number(gw.get("latency_high_ms")),
                "loss_high_percent": number(gw.get("loss_high_percent"), 100),
            } for gw in row.get("gateways", [])]
        result["wans"].append(wan)
    valid_wans = {row["id"] for row in result["wans"]}
    for row in context["rules"]:
        rule = {
            "id": row["alias"],
            "provider": enum(row.get("provider"), PROVIDERS, "OTHER"),
            "families": [value for value in row.get("families", []) if value in ("A", "AAAA")],
            "wans": [value for value in row.get("wans", []) if value in valid_wans],
        }
        if enabled:
            rule["last_status"] = enum(row.get("last_status"), {"OK", "Error"})
            try:
                rule["last_updated"] = stamp(dt.datetime.strptime(
                    row.get("last_updated", ""), "%Y-%m-%d %H:%M:%S").timestamp())
            except (ValueError, TypeError):
                rule["last_updated"] = None
            for field in ("observed_a", "observed_aaaa"):
                raw = row.get(field)
                rule[field] = None if raw is None else sorted({tag for ip in raw if (tag := privacy.ip(ip))})
        result["rules"].append(rule)
    if not enabled:
        return result
    version = small_file(Path("/etc/version"), 256).decode("ascii", "ignore").strip()
    result["pfsense"] = version if re.fullmatch(r"[0-9][0-9A-Za-z.+_-]{0,79}", version) else "unknown"
    result["php"] = context["php_version"] if re.fullmatch(r"\d+\.\d+\.\d+(?:[A-Za-z0-9._-]*)", context["php_version"]) else "unknown"
    result["python"] = ".".join(str(part) for part in sys.version_info[:3])
    kernel = os.uname()
    result["kernel"] = kernel.release if re.fullmatch(r"[0-9A-Za-z.+_-]{1,80}", kernel.release) else "unknown"
    result["architecture"] = enum(kernel.machine, {"amd64", "aarch64", "arm64", "i386"}, "OTHER")
    result["processes"] = []
    try:
        output = subprocess.run(
            ["/bin/ps", "-ax", "-o", "pid,ppid,state,etime,comm"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=3, check=True).stdout[:512 * 1024].decode("utf-8", "replace")
        for line in output.splitlines()[1:]:
            fields = line.split()
            if len(fields) != 5:
                continue
            pid, parent, state, elapsed, command = fields
            command = os.path.basename(command)
            if command in PROCESSES and pid.isdigit() and parent.isdigit() and re.fullmatch(r"[A-Za-z+<>NsLIXW-]{1,12}", state) and re.fullmatch(r"[\d:-]{1,24}", elapsed):
                result["processes"].append({
                    "pid": int(pid), "ppid": int(parent), "state": state,
                    "elapsed": elapsed, "command": command,
                })
        watcher = small_file(Path("/var/run/mwddns_watcher.pid"), 32).decode("ascii").strip()
        result["watcher_pid"] = int(watcher) if watcher.isdigit() else None
        result["watcher_process_present"] = any(
            row["pid"] == result["watcher_pid"] and row["command"] == "python3.11"
            for row in result["processes"])
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        result["process_snapshot_incomplete"] = True
    try:
        cron = small_file(Path("/etc/crontab"), 1024 * 1024).decode("utf-8", "replace")
        entries = [line for line in cron.splitlines()
                   if not line.lstrip().startswith("#") and "/usr/local/bin/mwddns_cron.php" in line]
        result["cron_entries"] = len(entries)
        result["cron_every_five_minutes"] = any(
            re.match(r"^\s*\*/5\s+\*\s+\*\s+\*\s+\*\s+root\s+", line) for line in entries)
    except (OSError, ValueError):
        result["cron_snapshot_unavailable"] = True
    return result


def candidates(base):
    paths = []
    allowed = re.compile(re.escape(base.name) + r"(?:\.\d+(?:\.(?:gz|bz2|xz|zst))?)?$")
    for path in base.parent.glob(base.name + "*"):
        if allowed.fullmatch(path.name) and not path.is_symlink() and path.is_file():
            paths.append(path)
    return sorted(paths, key=lambda path: path.stat().st_mtime, reverse=True)


def open_log(path):
    if path.suffix == ".gz":
        return gzip.open(path, "rb")
    if path.suffix == ".bz2":
        return bz2.open(path, "rb")
    if path.suffix == ".xz":
        return lzma.open(path, "rb")
    return path.open("rb")


def relevant(source, line, settings):
    if source == "system":
        return bool(PLUGIN.search(line) or
                    (settings["network"] and NETWORK.search(line)) or
                    (settings["web"] and WEB.search(line)))
    if source == "dhcp":
        return bool(re.search(r"\b(?:dhclient|dhcp6c)\b", line, re.I))
    if source == "nginx":
        return bool(re.search(r"\[(?:error|crit|alert|emerg|warn)\]|upstream|\" [5]\d\d ", line, re.I))
    return True


def event_priority(event):
    codes = set(event["events"])
    if codes & {"PHP_FATAL", "PROCESS_CRASH", "MEMORY_ERROR", "HTTP_5XX",
                "UPSTREAM_ERROR", "WORKER_LIMIT", "DHCP_NAK", "LEASE_EXPIRED",
                "DHCP_NO_OFFER", "DHCP_NO_LEASE", "DHCP_ADDRESS_REMOVED",
                "LINK_DOWN", "INTERFACE_DOWN", "ADDRESS_UNAVAILABLE", "UPDATE_FAIL"}:
        return 2
    if codes <= {"DHCP_REQUEST", "UNCLASSIFIED_DETAILS_OMITTED", "DEPRECATED",
                 "SENSITIVE_LINE_OMITTED"}:
        return 0
    return 1


def event_class(event):
    codes = set(event["events"])
    if codes & {
        "DNS_PRESERVED", "ADDRESS_UNAVAILABLE", "MONITOR_UNKNOWN",
        "GATEWAY_CHANGE", "ROUTING_STATES_CLEARED", "WATCHER_STARTED",
        "LINK_UP", "LINK_DOWN", "INTERFACE_DOWN", "INTERFACE_RECONFIGURE",
        "NEW_WAN_ADDRESS", "DHCP_DISCOVER", "DHCP_ACK", "DHCP_NAK",
        "DHCP_OFFER", "DHCP_BOUND", "DHCP_REBIND", "DHCP_SCRIPT_REASON",
        "LEASE_EXPIRED", "DHCP_NO_OFFER", "DHCP_NO_LEASE", "DHCP_ADDRESS_REMOVED",
    }:
        return "transitions"
    if event_priority(event) == 2:
        return "errors"
    if event_priority(event) == 0 or codes <= {"DHCP_RENEW"}:
        return "routine"
    return "transitions"


def event_reservations(limit):
    # Production sources have hundreds of slots. Tiny fixture/size-fallback
    # buffers cannot guarantee all three classes and use priority alone.
    if limit < 3:
        return {"errors": 0, "transitions": 0, "routine": 0}
    errors, transitions = limit // 3, limit // 2
    return {"errors": errors, "transitions": transitions,
            "routine": limit - errors - transitions}


def retain_groups(events, limit):
    """Size fallback uses the same class guarantees as the scanning buffer."""
    if limit <= 0:
        return []
    rank = lambda event: (event_priority(event), event["last_seen"])
    reserves = event_reservations(limit)
    selected, remaining = [], []
    for name, reserved in reserves.items():
        rows = sorted((event for event in events if event_class(event) == name),
                      key=rank, reverse=True)
        selected.extend(rows[:reserved])
        remaining.extend(rows[reserved:])
    remaining.sort(key=rank, reverse=True)
    return selected + remaining[:max(0, limit - len(selected))]


class EventBuffer:
    """Bounded groups with borrowable reservations for independent classes."""
    def __init__(self, limit):
        self.limit = max(1, limit)
        self.reserves = event_reservations(self.limit)
        self.groups = {}
        self.heaps = {name: [] for name in self.reserves}
        self.counts = {name: 0 for name in self.reserves}
        self.heap_size = 0
        self.sequence = 0
        self.dropped = 0

    def oldest(self, name):
        heap = self.heaps[name]
        while heap and self.groups.get(heap[0][3], [None] * 3)[2] != heap[0][2]:
            heapq.heappop(heap)
            self.heap_size -= 1
        return heap[0] if heap else None

    def add(self, event, epoch):
        codes = set(event["events"])
        repeatable = codes <= {
            "DHCP_REQUEST", "PHP_FATAL", "UNDEFINED_FUNCTION", "DEPRECATED",
            "UNCLASSIFIED_DETAILS_OMITTED", "SENSITIVE_LINE_OMITTED",
        }
        # Only repetitive classes lose intermediate timestamps. ACK/BOUND,
        # link changes, script reasons and other transitions remain individual.
        bucket = int(epoch // AGGREGATION_SECONDS) if repeatable else epoch
        # Cron starts a new PHP PID on every invocation. Only errors with an
        # identified file AND function may cross process boundaries; unknown
        # errors and DHCP retain their original PID identity.
        cross_process = (
            repeatable and "PHP_FATAL" in codes and
            event.get("process") in {"php", "php-fpm"} and
            bool(event.get("files")) and bool(event.get("function")))
        omitted = {"time", "pid"} if cross_process else {"time"}
        identity = {key: value for key, value in event.items() if key not in omitted}
        key = (bucket, json.dumps(identity, sort_keys=True, separators=(",", ":")))
        priority = event_priority(event)
        name = event_class(event)
        self.sequence += 1
        if key in self.groups:
            group = self.groups[key]
            group[1] = max(group[1], epoch)
            group[2] = self.sequence
            group[4] = min(group[4], epoch)
            group[3]["occurrences"] += 1
            group[3]["time"] = group[3]["first_seen"] = stamp(group[4])
            group[3]["last_seen"] = stamp(group[1])
            if cross_process and "pid" in event:
                stored, pid = group[3], event["pid"]
                if stored.get("pid") != pid:
                    stored.pop("pid", None)
                    stored["pid_scope"] = "multiple_processes"
                if pid not in stored["pid_samples"]:
                    if len(stored["pid_samples"]) < 4:
                        stored["pid_samples"].append(pid)
                    else:
                        stored["pid_samples_limited"] = True
        else:
            if len(self.groups) >= self.limit:
                needs_reserve = self.counts[name] < self.reserves[name]
                eligible = [
                    lane for lane in self.reserves
                    if self.counts[lane] > self.reserves[lane] or
                    (not needs_reserve and lane == name)
                ]
                options = [(item, lane) for lane in eligible if (item := self.oldest(lane))]
                if not options:
                    self.dropped += 1
                    return
                oldest, lane = min(options, key=lambda option: option[0][:3])
                if not needs_reserve and (priority, epoch) <= oldest[:2]:
                    self.dropped += 1
                    return
                heapq.heappop(self.heaps[lane])
                self.heap_size -= 1
                self.dropped += self.groups.pop(oldest[3])[3]["occurrences"]
                self.counts[lane] -= 1
            event.update(occurrences=1, first_seen=event["time"], last_seen=event["time"])
            if cross_process and "pid" in event:
                event.update(pid_samples=[event["pid"]], pid_samples_limited=False,
                             pid_scope="single_process")
            group = [priority, epoch, self.sequence, event, epoch, name]
            self.groups[key] = group
            self.counts[name] += 1
        heapq.heappush(self.heaps[name], (group[0], group[1], group[2], key))
        self.heap_size += 1
        if self.heap_size > self.limit * 2:
            self.heaps = {lane: [] for lane in self.reserves}
            for identity, value in self.groups.items():
                self.heaps[value[5]].append((value[0], value[1], value[2], identity))
            for heap in self.heaps.values():
                heapq.heapify(heap)
            self.heap_size = len(self.groups)

    def events(self):
        return [value[3] for value in self.groups.values()]


def source_counts(summary, events):
    summary["selected_events"] = sum(event["occurrences"] for event in events)
    summary["exported_event_groups"] = len(events)
    summary["aggregated_events"] = summary["selected_events"] - len(events)
    summary["dropped_events"] = summary["matched_events"] - summary["selected_events"]
    if "matched_by_class" in summary:
        retained = {name: 0 for name in summary["matched_by_class"]}
        for event in events:
            retained[event_class(event)] += event["occurrences"]
        summary["retained_by_class"] = retained
        summary["dropped_by_class"] = {
            name: count - retained[name] for name, count in summary["matched_by_class"].items()
        }
    if "matched_by_event_code" in summary:
        retained = {code: 0 for code in summary["matched_by_event_code"]}
        for event in events:
            for code in set(event["events"]):
                retained[code] += event["occurrences"]
        summary["retained_by_event_code"] = retained
        summary["dropped_by_event_code"] = {
            code: count - retained[code]
            for code, count in summary["matched_by_event_code"].items()
        }


class DHCPRequestHistogram:
    """Source-wide counts, independent of event grouping and PID retention.

    At most 4033 five-minute buckets cover the inclusive 14-day window.
    Keep the newest buckets if the bound is reached; account for every omitted
    request. No text, address, alias dictionary or inferred WAN/PID is stored.
    """
    def __init__(self):
        self.limit = MAX_DHCP_BUCKETS
        self.buckets = {}
        self.order = []
        self.matched = 0
        self.omitted = 0

    def add(self, epoch):
        bucket = int(epoch // DHCP_BUCKET_SECONDS) * DHCP_BUCKET_SECONDS
        self.matched += 1
        if bucket not in self.buckets:
            if len(self.buckets) >= self.limit:
                if bucket < self.order[0]:
                    self.omitted += 1
                    return
                self.omitted += self.buckets.pop(heapq.heappop(self.order))
            self.buckets[bucket] = 0
            heapq.heappush(self.order, bucket)
        self.buckets[bucket] += 1

    def export(self):
        return {
            "bucket_seconds": DHCP_BUCKET_SECONDS, "bucket_limit": self.limit,
            "matched_requests": self.matched,
            "bucketed_requests": self.matched - self.omitted,
            "omitted_requests": self.omitted,
            "buckets": [{"start": stamp(bucket), "requests": self.buckets[bucket]}
                        for bucket in sorted(self.buckets)],
        }


def allocate_sources(report):
    """Allocate only after all sources have scanned, so order cannot starve one.

    The extra candidate buffer is bounded to seven sources * 2000 groups.
    Byte/time/process limits are unchanged. Unused guarantees and shared slots
    are distributed equally among sources that can still use them.
    """
    grouped = {row["source"]: [] for row in report["sources"]}
    for event in report["events"]:
        grouped[event["source"]].append(event)
    floor = min(MIN_SOURCE_EVENTS, MAX_EVENTS // max(1, len(grouped)))
    capacities = {name: min(len(rows), MAX_SOURCE_EVENTS) for name, rows in grouped.items()}
    allocations = {name: min(count, floor) for name, count in capacities.items()}
    spare = MAX_EVENTS - sum(allocations.values())
    while spare:
        pending = sorted(name for name in grouped if allocations[name] < capacities[name])
        if not pending:
            break
        share = max(1, spare // len(pending))
        for name in pending:
            grant = min(share, capacities[name] - allocations[name], spare)
            allocations[name] += grant
            spare -= grant
    retained = []
    for summary in report["sources"]:
        name = summary["source"]
        rows = retain_groups(grouped[name], allocations[name])
        before = sum(event["occurrences"] for event in grouped[name])
        source_counts(summary, rows)
        summary["guaranteed_event_groups"] = floor
        summary["allocated_event_groups"] = allocations[name]
        summary["event_class_reservations"] = event_reservations(allocations[name])
        summary["allocation_dropped_events"] = before - summary["selected_events"]
        if summary["allocation_dropped_events"]:
            summary["warnings"] = sorted(set(summary["warnings"] + ["SHARED_EVENT_LIMIT"]))
        retained.extend(rows)
    report["events"] = retained


def scan(source, base, settings, privacy, report, quota, now, cutoff):
    candidate_limit = min(MAX_SOURCE_EVENTS, quota["events"])
    histogram = DHCPRequestHistogram()
    summary = {
        "source": source, "files_scanned": 0, "bytes_scanned": 0,
        "selected_events": 0, "unknown_timestamp_lines": 0,
        "sensitive_lines_omitted": 0, "unclassified_events": 0,
        "matched_events": 0, "exported_event_groups": 0, "aggregated_events": 0,
        "dropped_events": 0, "budget": dict(quota, events=candidate_limit),
        "event_class_reservations": event_reservations(candidate_limit),
        "candidate_class_reservations": event_reservations(candidate_limit),
        "candidate_event_groups": 0, "candidate_retained_events": 0,
        "candidate_dropped_events": 0, "allocation_dropped_events": 0,
        "report_size_dropped_events": 0,
        "matched_by_class": {"errors": 0, "transitions": 0, "routine": 0},
        "retained_by_class": {"errors": 0, "transitions": 0, "routine": 0},
        "dropped_by_class": {"errors": 0, "transitions": 0, "routine": 0},
        "matched_by_event_code": {}, "retained_by_event_code": {},
        "dropped_by_event_code": {}, "dhcp_request_histogram": histogram.export(),
        "coverage": "unavailable", "timestamped_lines_in_window": 0,
        "warnings": [], "oldest_timestamp_seen": None, "newest_timestamp_seen": None,
    }
    report["sources"].append(summary)
    deadline = time.monotonic() + quota["seconds"]
    buffer = EventBuffer(candidate_limit)
    try:
        paths = candidates(base)
    except OSError:
        summary["warnings"].append("LOG_UNAVAILABLE")
        return
    if not paths:
        summary["warnings"].append("LOG_UNAVAILABLE")
        return
    if len(paths) > 24:
        summary["warnings"].append("ROTATION_FILE_LIMIT")
    oldest, newest = None, None
    for path in paths[:24]:
        if path.suffix == ".zst":
            summary["warnings"].append("ZSTD_ROTATION_NOT_SUPPORTED")
            continue
        if summary["bytes_scanned"] >= quota["bytes"]:
            summary["warnings"].append("SOURCE_BYTE_LIMIT")
            break
        if time.monotonic() >= deadline:
            summary["warnings"].append("SOURCE_TIME_LIMIT")
            break
        count, previous, selected = 0, None, False
        try:
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode):
                continue
            summary["files_scanned"] += 1
            with open_log(path) as handle:
                file_limit = min(MAX_FILE, quota["bytes"] - summary["bytes_scanned"])
                if path.suffix not in (".gz", ".bz2", ".xz") and metadata.st_size > file_limit:
                    handle.seek(metadata.st_size - file_limit)
                    raw = handle.readline(min(MAX_LINE, file_limit))
                    count += len(raw)
                    summary["bytes_scanned"] += len(raw)
                    # If this was still inside an overlong line, the loop below
                    # discards its remainder rather than exporting a fragment.
                    while raw and not raw.endswith(b"\n") and count < file_limit and time.monotonic() < deadline:
                        raw = handle.readline(min(MAX_LINE, file_limit - count))
                        count += len(raw)
                        summary["bytes_scanned"] += len(raw)
                    summary["warnings"].append("FILE_HEAD_SKIPPED")
                while count < file_limit and time.monotonic() < deadline:
                    read_limit = min(MAX_LINE + 1, file_limit - count)
                    raw = handle.readline(read_limit)
                    if not raw:
                        break
                    count += len(raw)
                    summary["bytes_scanned"] += len(raw)
                    if not raw.endswith(b"\n") and len(raw) == read_limit:
                        summary["warnings"].append(
                            "OVERLONG_RECORD_SKIPPED" if len(raw) > MAX_LINE else "TRUNCATED_RECORD_SKIPPED")
                        while raw and not raw.endswith(b"\n") and count < file_limit and time.monotonic() < deadline:
                            raw = handle.readline(min(MAX_LINE, file_limit - count))
                            count += len(raw)
                            summary["bytes_scanned"] += len(raw)
                        previous, selected = None, False
                        continue
                    line = raw.decode("utf-8", "replace")
                    epoch, payload = timestamp(line, metadata.st_mtime, now)
                    if epoch is None:
                        summary["unknown_timestamp_lines"] += 1
                        if source != "php" or previous is None or not selected:
                            continue
                        epoch, payload = previous, line
                    else:
                        previous = epoch
                        selected = relevant(source, line, settings)
                        oldest = epoch if oldest is None else min(oldest, epoch)
                        newest = epoch if newest is None else max(newest, epoch)
                        summary["timestamped_lines_in_window"] += cutoff <= epoch <= now
                    if not selected or not cutoff <= epoch <= now:
                        continue
                    event = privacy.event(payload, epoch, source)
                    summary["matched_events"] += 1
                    summary["matched_by_class"][event_class(event)] += 1
                    summary["sensitive_lines_omitted"] += "SENSITIVE_LINE_OMITTED" in event["events"]
                    summary["unclassified_events"] += "UNCLASSIFIED_DETAILS_OMITTED" in event["events"]
                    for code in set(event["events"]):
                        counts = summary["matched_by_event_code"]
                        counts[code] = counts.get(code, 0) + 1
                    if "DHCP_REQUEST" in event["events"]:
                        histogram.add(epoch)
                    buffer.add(event, epoch)
                if count >= file_limit:
                    summary["warnings"].append("FILE_READ_LIMIT")
                if summary["bytes_scanned"] >= quota["bytes"]:
                    summary["warnings"].append("SOURCE_BYTE_LIMIT")
                if time.monotonic() >= deadline:
                    summary["warnings"].append("SOURCE_TIME_LIMIT")
        except (OSError, EOFError, ValueError, lzma.LZMAError):
            summary["warnings"].append("FILE_UNREADABLE_OR_INVALID")
    retained = buffer.events()
    report["events"].extend(retained)
    source_counts(summary, retained)
    summary["candidate_event_groups"] = len(retained)
    summary["candidate_retained_events"] = summary["selected_events"]
    summary["candidate_dropped_events"] = summary["dropped_events"]
    summary["dhcp_request_histogram"] = histogram.export()
    if histogram.omitted:
        summary["warnings"].append("DHCP_HISTOGRAM_BUCKET_LIMIT")
    if buffer.dropped:
        summary["warnings"].append("SOURCE_EVENT_LIMIT")
    summary["oldest_timestamp_seen"] = stamp(oldest) if oldest is not None else None
    summary["newest_timestamp_seen"] = stamp(newest) if newest is not None else None
    if oldest is None or oldest > cutoff:
        summary["warnings"].append("REQUESTED_START_NOT_OBSERVED")
    if newest is not None and newest < cutoff:
        summary["warnings"].append("NO_RECORDS_IN_REQUESTED_WINDOW")
    if not summary["files_scanned"]:
        summary["coverage"] = "unreadable"
    elif not summary["bytes_scanned"] and not summary["warnings"]:
        summary["coverage"] = "empty"
        summary["warnings"].append("EMPTY_LOG")
    elif newest is not None and newest < cutoff:
        summary["coverage"] = "stale"
    elif not summary["timestamped_lines_in_window"]:
        # Empty logs also have REQUESTED_START_NOT_OBSERVED at this point.
        if not summary["bytes_scanned"] and set(summary["warnings"]) <= {"REQUESTED_START_NOT_OBSERVED"}:
            summary["coverage"] = "empty"
            summary["warnings"].append("EMPTY_LOG")
        else:
            summary["coverage"] = "no_records_in_window"
    elif not summary["matched_events"]:
        summary["coverage"] = "no_matching_events"
    else:
        summary["coverage"] = "observed"
    if summary["unknown_timestamp_lines"]:
        summary["warnings"].append("SOME_LINES_HAVE_NO_PARSED_TIMESTAMP")
    summary["warnings"] = sorted(set(summary["warnings"]))


def limit_report(report):
    """Trim the most populated source, never a global oldest-event slice."""
    report["report_size_limited"] = False
    while len((json.dumps(report, ensure_ascii=True, indent=2) + "\n").encode("utf-8")) > MAX_REPORT:
        grouped = {row["source"]: [] for row in report["sources"]}
        for event in report["events"]:
            grouped[event["source"]].append(event)
        above_floor = [name for name in grouped if len(grouped[name]) > MIN_SOURCE_EVENTS]
        source = max(above_floor or grouped, key=lambda name: len(grouped[name]))
        events = grouped[source]
        if not events:
            raise ValueError("Report metadata exceeds limit")
        target = len(events) - max(1, len(events) // 2)
        if above_floor:
            target = max(MIN_SOURCE_EVENTS, target)
        retained = retain_groups(events, target)
        retained_ids = {id(event) for event in retained}
        removed = {id(event) for event in events if id(event) not in retained_ids}
        report["events"] = [event for event in report["events"] if id(event) not in removed]
        summary = next(row for row in report["sources"] if row["source"] == source)
        summary["warnings"] = sorted(set(summary["warnings"] + ["REPORT_SIZE_LIMIT"]))
        summary["report_size_dropped_events"] = summary.get("report_size_dropped_events", 0) + sum(
            event["occurrences"] for event in events if id(event) in removed)
        summary["event_class_reservations"] = event_reservations(target)
        source_counts(summary, [event for event in events if id(event) not in removed])
        report["report_size_limited"] = True
    report["partial"] = any(source["warnings"] for source in report["sources"])


def collect(settings, now):
    completed = subprocess.run(
        ["/usr/local/bin/php", "/usr/local/bin/mwddns_debug_snapshot.php",
         "runtime" if settings["runtime"] else "context"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=15, check=True)
    if len(completed.stdout) > 1024 * 1024:
        raise ValueError("Context limit")
    context = json.loads(completed.stdout)
    privacy = Privacy(context)
    cutoff = now - settings["days"] * 86400
    report = {
        "schema": "mwddns-debug-v2",
        "collector_version": "1.0.12",
        "generated_at": stamp(now),
        "window": {"days": settings["days"], "start": stamp(cutoff), "end": stamp(now)},
        "privacy": {
            "mode": "strict_structured",
            "raw_messages_included": False,
            "configuration_included": False,
            "alias_dictionary_included": False,
            "aliases_scope": "This report only; current configuration order defines WAN labels.",
            "details": "Only fixed event codes, validated times/numbers and opaque aliases are exported.",
        },
        "limitations": [
            "Existing logs only. Missing, rotated-away or disabled logs cannot be reconstructed.",
            "Unrecognized free text is omitted. This is not a verbatim log export.",
            "Current WAN/address mapping cannot prove ownership of every historical IP.",
            "An empty WAN list means unattributed, not that every WAN was affected.",
            "Snapshot OK does not verify public DNS or historical failover.",
            "Sources are scanned newest-file first with bounded reads, not guaranteed complete.",
            "Repeated classes are grouped within one-hour buckets; occurrences and first/last times are retained, not every intermediate timestamp.",
            "Each enabled source keeps its byte/time budgets and buffers at most 2000 candidate groups before final allocation; up to 14000 candidate groups are temporarily buffered under the unchanged process resource limits.",
            "Final allocation guarantees up to 256 available groups per source, shares spare slots fairly, and exports at most 5000 groups total and 2000 per source. The report-byte ceiling may reduce guarantees after surplus slots are trimmed.",
            "Candidate, allocation and report-size dropped-event counts are occurrences lost at each stage; their sum equals final dropped_events. Unscanned records cannot be counted.",
            "DHCP server/destination addresses do not establish WAN ownership. Current leased-address matches are explicitly labelled.",
            "DHCP script EXPIRE is not proof of timer expiry. rc.newwanip is not proof of an address change.",
            "Event counts are occurrences, not the number of exported groups; cross-source duplicate messages are not deduplicated.",
            "Identified PHP errors may aggregate across PIDs within an hour. At most four PID samples are retained; they do not imply one process.",
            "Within each source, errors, transitions and routine events have borrowable reserved slots. Overflow cannot consume another class's reservation.",
            "Per-event-code matched/retained/dropped counts overlap when a record has multiple codes; do not sum them as a total number of records.",
            "Five-minute DHCPREQUEST histograms count scanned, timestamped, in-window requests before group eviction, combining WANs and PIDs within each source. Boundary buckets may be partial; sensitive lines and unscanned records are excluded. Cross-source duplicates remain.",
            "Histogram storage is bounded to 4033 buckets per source; newest buckets are kept and omitted_requests counts any overflow independently of event losses.",
            "DHCP events retain WAN aliases and PID identity. Anonymous DHCP_RENEW events are not merged across PIDs because a safe common identity cannot be established.",
        ],
        "limits": {"seconds": 75, "bytes_per_file": MAX_FILE, "bytes_total": MAX_TOTAL,
                   "events": MAX_EVENTS, "report_bytes": MAX_REPORT,
                   "seconds_per_source": SOURCE_SECONDS,
                   "aggregation_bucket_seconds": AGGREGATION_SECONDS,
                   "guaranteed_groups_per_source": MIN_SOURCE_EVENTS,
                   "candidate_groups_per_source": MAX_SOURCE_EVENTS,
                   "dhcp_histogram_bucket_seconds": DHCP_BUCKET_SECONDS,
                   "dhcp_histogram_buckets_per_source": MAX_DHCP_BUCKETS,
                   "pid_samples_per_group": 4},
        "snapshot": runtime_snapshot(context, privacy, settings["runtime"]),
        "sources": [],
        "events": [],
    }
    sources = [("system", Path("/var/log/system.log"))]
    if settings["network"]:
        sources += [
            ("dhcp", Path("/var/log/dhcpd.log")),
            ("gateways", Path("/var/log/gateways.log")),
            ("ppp", Path("/var/log/ppp.log")),
            ("routing", Path("/var/log/routing.log")),
        ]
    if settings["web"]:
        sources += [("php", Path("/tmp/PHP_errors.log")), ("nginx", Path("/var/log/nginx.log"))]
    quota = {"bytes": MAX_TOTAL // len(sources), "events": MAX_SOURCE_EVENTS,
             "seconds": SOURCE_SECONDS}
    report["limits"]["reserved_per_source"] = dict(quota, events=MIN_SOURCE_EVENTS)
    report["limits"]["candidate_groups_total"] = MAX_SOURCE_EVENTS * len(sources)
    for source, path in sources:
        scan(source, path, settings, privacy, report, quota, now, cutoff)
    allocate_sources(report)
    report["events"].sort(key=lambda event: event["time"])
    limit_report(report)
    return report


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r"[a-f0-9]{32}", sys.argv[1]):
        return 2
    os.umask(0o077)
    job = BASE / ("job-" + sys.argv[1])
    if BASE.is_symlink() or job.is_symlink() or not job.is_dir():
        return 2
    started = int(time.time())
    try:
        state = json.loads(small_file(job / "status.json", 4096))
        started = int(state["started"])
        if state.get("state") != "queued" or not 0 <= time.time() - started < 120:
            return 2
        settings = json.loads(small_file(job / "request.json", 4096))
        if type(settings.get("days")) is not int or not 1 <= settings["days"] <= 14 or any(
                type(settings.get(key)) is not bool for key in ("network", "web", "runtime")):
            raise ValueError("Invalid settings")
        resource.setrlimit(resource.RLIMIT_CPU, (60, 65))
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        def expired(signum, frame):
            raise TimeoutError("Deadline")
        signal.signal(signal.SIGALRM, expired)
        signal.alarm(75)
        atomic(job / "status.json", {"state": "running", "started": started})
        report = collect(settings, started)
        atomic(job / "report.json", report)
        atomic(job / "status.json", {
            "state": "complete", "started": started, "partial": report["partial"],
        })
        return 0
    except Exception:
        try:
            atomic(job / "status.json", {"state": "failed", "started": started})
        except Exception:
            pass
        return 1
    finally:
        signal.alarm(0)
        for name in ("request.json", "request.json.tmp", "report.json.tmp", "status.json.tmp"):
            try:
                (job / name).unlink(missing_ok=True)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
