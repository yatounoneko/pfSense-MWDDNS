#!/usr/local/bin/python3.11
"""Bounded, offline, strict-privacy export of existing pfSense diagnostics.

No raw messages, names, configuration or redaction dictionaries are written.
Unrecognized event details are deliberately omitted, not guessed to be safe.
"""
import bz2
import datetime as dt
import fcntl
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

# Legacy upgrade validators require one literal collector_version declaration.
COLLECTOR_METADATA = {"collector_version": "1.1.1"}

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
SCAN_WALL_SECONDS = 60
SCAN_CPU_SECONDS = 50
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
WEB_REASON_PATTERNS = {
    "CONNECTION_REFUSED": r"\bconnection refused\b",
    "CONNECTION_RESET": r"\bconnection reset by peer\b",
    "TIMEOUT": r"\btimed out\b",
    "NOT_FOUND": r"\bno such file or directory\b",
    "PERMISSION_DENIED": r"\bpermission denied\b",
    "RESOURCE_UNAVAILABLE": r"\bresource temporarily unavailable\b",
    "NO_BUFFER_SPACE": r"\bno buffer space available\b",
    "TOO_MANY_OPEN_FILES": r"\btoo many open files\b",
    "ADDRESS_IN_USE": r"\baddress already in use\b",
    "PREMATURE_CLOSE": r"\b(?:upstream prematurely closed|prematurely closed connection)\b",
    "INVALID_HEADER": r"\bupstream sent (?:an? )?invalid header\b",
    "NO_LIVE_UPSTREAMS": r"\bno live upstreams\b",
    "WORKER_LIMIT": r"\bserver reached\s+pm\.max_children\b",
    "MEMORY_EXHAUSTED": r"\bout of memory\b|\bcannot allocate memory\b",
}
WEB_REASON_PATTERNS = {key: re.compile(value, re.I) for key, value in WEB_REASON_PATTERNS.items()}
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


class CollectionDeadline(Exception):
    """Not an OSError: a job deadline must escape per-file I/O recovery."""
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class ProgressWriteError(Exception):
    pass


class JobProgress:
    """Only fixed identifiers, counters and timestamps reach status.json."""
    def __init__(self, job, started):
        self.job = job
        self.started = started
        self.wall_started = time.monotonic()
        self.cpu_started = time.process_time()
        self.next_write = 0.0
        self.reserve = bytearray(65536)
        self.data = {"stage": "starting", "source": "none", "error_code": "NONE"}

    def mark(self, stage, source=None, force=False, **details):
        self.data["stage"] = stage
        if source is not None and source != self.data["source"]:
            self.data.update(source=source, file_index=0, record_index=0,
                             record_bytes=0, record_epoch=0, source_bytes_scanned=0,
                             matched_events=0, candidate_event_groups=0)
        self.data.update(details)
        if force or time.monotonic() >= self.next_write:
            self.emit("running")

    def completed_totals(self, report):
        sources = report["sources"]
        self.data.update(
            total_sources=len(sources),
            total_files_scanned=sum(row["files_scanned"] for row in sources),
            total_bytes_scanned=sum(row["bytes_scanned"] for row in sources),
            total_matched_events=sum(row["matched_events"] for row in sources),
            total_retained_events=sum(row["selected_events"] for row in sources),
            total_dropped_events=sum(row["dropped_events"] for row in sources),
            total_event_groups=len(report["events"]))

    def measurements(self):
        return dict(self.data, elapsed_seconds=round(time.monotonic() - self.wall_started, 3),
                    cpu_seconds=round(time.process_time() - self.cpu_started, 3),
                    checkpoint_at=int(time.time()))

    def emit(self, state, partial=None):
        value = {"state": state, "started": self.started,
                 **COLLECTOR_METADATA, "diagnostics": self.measurements()}
        if isinstance(partial, bool):
            value["partial"] = partial
        try:
            atomic(self.job / "status.json", value)
        except (OSError, ValueError) as error:
            raise ProgressWriteError() from error
        self.next_write = time.monotonic() + 2.0

    def finish(self, state, error_code="NONE", collector_line=0, partial=None):
        self.reserve = None
        self.data.update(error_code=error_code, collector_line=collector_line)
        if state == "complete":
            self.data["stage"] = "complete"
            # Per-source progress is not a collection total after scanning ends.
            for key in ("file_index", "record_index", "record_bytes", "record_epoch",
                        "source_bytes_scanned", "matched_events", "candidate_event_groups",
                        "collector_line"):
                self.data.pop(key, None)
        self.emit(state, partial)


def failure_code(error):
    if isinstance(error, CollectionDeadline):
        return error.code
    if isinstance(error, MemoryError):
        return "MEMORY_ALLOCATION_FAILED"
    if isinstance(error, subprocess.TimeoutExpired):
        return "SNAPSHOT_TIMEOUT"
    if isinstance(error, subprocess.CalledProcessError):
        return "SNAPSHOT_FAILED"
    if isinstance(error, ProgressWriteError):
        return "PROGRESS_WRITE_FAILED"
    if isinstance(error, OSError):
        return "IO_FAILED"
    if isinstance(error, (ValueError, OverflowError)):
        return "INVALID_INPUT"
    return "COLLECTOR_EXCEPTION"


def collector_error_line(error):
    line = 0
    trace = error.__traceback__
    while trace is not None:
        code = trace.tb_frame.f_code
        if code.co_filename == __file__ and code.co_name not in {"wall_expired", "cpu_expired"}:
            line = trace.tb_lineno
        trace = trace.tb_next
    return line


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
        web = web_details(payload, source)
        if web:
            event["web"] = web
            if web.get("http_status", 0) >= 500:
                events.append("HTTP_5XX")
            if web.get("upstream_context") and ("reason" in web or "socket_errno" in web):
                events.append("UPSTREAM_ERROR")
            if "operation" in web and ("reason" in web or "socket_errno" in web):
                events.append("SOCKET_ERROR")
            reason_event = {
                "TIMEOUT": "TIMEOUT", "PERMISSION_DENIED": "PERMISSION_DENIED",
                "WORKER_LIMIT": "WORKER_LIMIT", "MEMORY_EXHAUSTED": "MEMORY_ERROR",
            }.get(web.get("reason"))
            if reason_event:
                events.append(reason_event)
            if "lifecycle" in web:
                events.append("PHP_FPM_" + web["lifecycle"])
        event["events"] = list(dict.fromkeys(events)) or ["UNCLASSIFIED_DETAILS_OMITTED"]
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
        if "worker_pid" in web:
            event.setdefault("process", "nginx")
            event.setdefault("pid", web["worker_pid"])
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
        for field in ("http_status", "socket_errno"):
            if field in web:
                metrics[field] = web[field]
        if metrics:
            event["metrics"] = metrics
        states = sorted(set(re.findall(r"\b(online|down|unknown)\b", payload, re.I)))
        if states:
            event["mentioned_states"] = [state.lower() for state in states]
        return event


def web_details(payload, source):
    """Fixed classifications and bounded numbers only, never messages or endpoints."""
    if source not in {"nginx", "php", "system"}:
        return {}
    # Do not diagnose text supplied in a logged URL, Host, Referer or request.
    head = re.split(r",\s*(?:client|server|request|host|referrer):",
                    payload, maxsplit=1, flags=re.I)[0]
    fpm = source != "nginx" and bool(re.search(
        r"\bphp-fpm\b|\bfpm is running\b", head, re.I))
    if source != "nginx" and not fpm:
        return {}
    result = {}
    if source == "nginx":
        # nginx combined: "$request" $status $body_bytes_sent. Read only status,
        # never export the request, referrer, user-agent or response body length.
        access = re.search(
            r'"[^"\r\n]*\sHTTP/\d(?:\.\d+)?"\s+([1-5]\d{2})\s+(?:\d+|-)(?=\s|$)',
            payload)
        if access:
            return {"log_kind": "access", "http_status": int(access[1])}
        if not re.search(
                r"\[(?:emerg|alert|crit|error|warn|notice|info|debug)\]|"
                r"\b(?:connect|bind|accept|send|recv|read|write|sendto|recvfrom)\(\)|\bupstream\b",
                head, re.I):
            return {}
        result["log_kind"] = "error"
        worker = re.search(r"\[(?:emerg|alert|crit|error|warn|notice|info|debug)\]\s+"
                           r"(\d{1,8})#(\d{1,12}):(?:\s+\*(\d{1,12}))?", head, re.I)
        if worker:
            result["worker_pid"] = int(worker[1])
            if worker[3] is not None:
                result["connection_id"] = int(worker[3])
        upstream = re.search(r',\s*upstream:\s*"([^"\r\n]{1,2048})"', payload, re.I)
        endpoint = upstream[1] if upstream else ""
        if not endpoint:
            unix = re.search(r"\bunix:([^\s,\"]{1,2048})", head, re.I)
            endpoint = "unix:" + unix[1] if unix else ""
        if endpoint:
            if "unix:" in endpoint.lower():
                result["transport"] = "unix"
            elif re.match(r"(?:https?|fastcgi)://", endpoint, re.I):
                result["transport"] = "tcp"
            if re.search(r"/php[-_]fpm(?:\.sock(?:et)?)?(?=[:/?#]|$)", endpoint, re.I):
                result["backend"] = "php_fpm"
            elif endpoint.lower().startswith("fastcgi://"):
                result["backend"] = "fastcgi"
            elif re.match(r"https?://", endpoint, re.I):
                result["backend"] = "http"
        phases = {
            "CONNECT": r"while connecting to upstream",
            "READ_HEADER": r"while reading response header from upstream",
            "READ_RESPONSE": r"while reading upstream",
            "SEND_REQUEST": r"while sending request to upstream",
            "TLS_HANDSHAKE": r"while SSL handshaking to upstream",
        }
        for code, pattern in phases.items():
            if re.search(pattern, head, re.I):
                result["phase"] = code
                break
        if upstream or re.search(r"\bupstream\b", head, re.I):
            result["upstream_context"] = True
    else:
        result["log_kind"] = "php_fpm"
        lifecycle = {
            "READY": r"\bready to handle connections\b",
            "STARTED": r"\bfpm is running\b",
            "RELOADING": r"\breloading(?: in progress|:)",
            "CHILD_EXIT": r"\bchild\s+\d+\s+exited\b",
            "STOPPING": r"\bterminating\b|\bexiting, bye-bye\b|\bshutting down\b",
        }
        for code, pattern in lifecycle.items():
            if re.search(pattern, head, re.I):
                result["lifecycle"] = code
                break
        children = re.search(r"\bserver reached\s+pm\.max_children\s+setting\s*\((\d{1,6})\)", head, re.I)
        if children:
            result["max_children"] = int(children[1])
    operation = re.search(
        r"\b(connect|bind|accept|send|recv|read|write|sendto|recvfrom|writev|readv)\(\)", head, re.I)
    if operation:
        result["operation"] = operation[1].upper()
    # Match reported OS errors; never translate Linux/FreeBSD errno numbers into
    # guessed causes. The fixed reason is matched independently from the text.
    error = re.search(r"\b(?:failed|timed out)\s*\((\d{1,4}):", head, re.I)
    if not error:
        error = re.search(r"\b(?:sendto error|errno)\s*[:=]?\s*(\d{1,4})\b", head, re.I)
    if error and 0 <= int(error[1]) <= 4096:
        result["socket_errno"] = int(error[1])
    for code, pattern in WEB_REASON_PATTERNS.items():
        if pattern.search(head):
            result["reason"] = code
            break
    return result


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
    """Share final slots fairly after every source has had its scan reservation.

    Candidate borrowing is bounded separately by the collection-wide pool.
    Unused guarantees and shared output slots go to sources that can use them.
    """
    grouped = {row["source"]: [] for row in report["sources"]}
    for event in report["events"]:
        grouped[event["source"]].append(event)
    floor = min(MIN_SOURCE_EVENTS, MAX_EVENTS // max(1, len(grouped)))
    capacities = {name: min(len(rows), MAX_EVENTS) for name, rows in grouped.items()}
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


def scan(source, base, settings, privacy, report, quota, now, cutoff, *, cpu_deadline=None, progress=None):
    candidate_limit = min(MAX_EVENTS, quota["events"])
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
        "oldest_timestamp_in_window": None, "newest_timestamp_in_window": None,
    }
    report["sources"].append(summary)
    deadline = time.monotonic() + quota["seconds"]

    def time_left():
        return (time.monotonic() < deadline and
                (cpu_deadline is None or time.process_time() < cpu_deadline))

    buffer = EventBuffer(candidate_limit)
    if progress:
        progress.mark("enumerate", source=source, force=True)
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
    window_oldest, window_newest = None, None
    for file_index, path in enumerate(paths[:24], 1):
        if path.suffix == ".zst":
            summary["warnings"].append("ZSTD_ROTATION_NOT_SUPPORTED")
            continue
        if summary["bytes_scanned"] >= quota["bytes"]:
            summary["warnings"].append("SOURCE_BYTE_LIMIT")
            break
        if not time_left():
            summary["warnings"].append("SOURCE_TIME_LIMIT")
            break
        count, previous, selected = 0, None, False
        record_index, file_matches = 0, 0
        if progress:
            progress.mark("open_file", force=True, file_index=file_index,
                          record_index=0, record_bytes=0, record_epoch=0,
                          source_bytes_scanned=summary["bytes_scanned"])
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
                    while raw and not raw.endswith(b"\n") and count < file_limit and time_left():
                        raw = handle.readline(min(MAX_LINE, file_limit - count))
                        count += len(raw)
                        summary["bytes_scanned"] += len(raw)
                    summary["warnings"].append("FILE_HEAD_SKIPPED")
                while count < file_limit and time_left():
                    if progress:
                        progress.mark("read_record", source_bytes_scanned=summary["bytes_scanned"],
                                      matched_events=summary["matched_events"],
                                      candidate_event_groups=len(buffer.groups))
                    read_limit = min(MAX_LINE + 1, file_limit - count)
                    raw = handle.readline(read_limit)
                    if not raw:
                        break
                    count += len(raw)
                    summary["bytes_scanned"] += len(raw)
                    if not raw.endswith(b"\n") and len(raw) == read_limit:
                        summary["warnings"].append(
                            "OVERLONG_RECORD_SKIPPED" if len(raw) > MAX_LINE else "TRUNCATED_RECORD_SKIPPED")
                        while raw and not raw.endswith(b"\n") and count < file_limit and time_left():
                            raw = handle.readline(min(MAX_LINE, file_limit - count))
                            count += len(raw)
                            summary["bytes_scanned"] += len(raw)
                        previous, selected = None, False
                        continue
                    record_index += 1
                    if progress:
                        progress.mark("parse_timestamp", record_index=record_index,
                                      record_bytes=len(raw), record_epoch=0,
                                      source_bytes_scanned=summary["bytes_scanned"])
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
                        if cutoff <= epoch <= now:
                            summary["timestamped_lines_in_window"] += 1
                            window_oldest = epoch if window_oldest is None else min(window_oldest, epoch)
                            window_newest = epoch if window_newest is None else max(window_newest, epoch)
                    if not selected or not cutoff <= epoch <= now:
                        continue
                    if progress:
                        progress.mark("classify_event", force=file_matches == 0,
                                      record_epoch=int(epoch) if 0 <= epoch <= 4102444800 else 0)
                    event = privacy.event(payload, epoch, source)
                    file_matches += 1
                    if progress:
                        progress.mark("group_event")
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
                if not time_left():
                    summary["warnings"].append("SOURCE_TIME_LIMIT")
        except (OSError, EOFError, ValueError, lzma.LZMAError):
            summary["warnings"].append("FILE_UNREADABLE_OR_INVALID")
    if progress:
        progress.mark("source_summary", force=True, source_bytes_scanned=summary["bytes_scanned"],
                      matched_events=summary["matched_events"], candidate_event_groups=len(buffer.groups))
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
    summary["oldest_timestamp_in_window"] = stamp(window_oldest) if window_oldest is not None else None
    summary["newest_timestamp_in_window"] = stamp(window_newest) if window_newest is not None else None
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


def scan_workload(base):
    """Estimate disk work only; compression and filtering can change actual cost."""
    try:
        return sum(min(MAX_FILE, path.stat().st_size) for path in candidates(base)[:24]
                   if path.suffix != ".zst")
    except OSError:
        # Let scan() report the unavailable source using its existing warnings.
        return 0


def collect(settings, now, progress=None):
    scan_deadline = time.monotonic() + SCAN_WALL_SECONDS
    cpu_deadline = time.process_time() + SCAN_CPU_SECONDS
    if progress:
        progress.mark("snapshot", source="none", force=True)
    completed = subprocess.run(
        ["/usr/local/bin/php", "/usr/local/bin/mwddns_debug_snapshot.php",
         "runtime" if settings["runtime"] else "context"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=15, check=True)
    if len(completed.stdout) > 1024 * 1024:
        raise ValueError("Context limit")
    if progress:
        progress.mark("privacy_setup", force=True)
    context = json.loads(completed.stdout)
    privacy = Privacy(context)
    cutoff = now - settings["days"] * 86400
    report = {
        "schema": "mwddns-debug-v2",
        **COLLECTOR_METADATA,
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
            "Web diagnostics retain only recognized HTTP status, reported errno, fixed operation/reason/phase/backend classes, numeric nginx worker/connection IDs and explicit PHP-FPM lifecycle messages. No request, URL, endpoint, raw error text or guessed root cause is exported.",
            "A connection ID is scoped to nginx workers, not a unique request ID. Separate records and equal counts do not establish causality. Sensitive lines remain omitted before diagnostic extraction.",
            "Current WAN/address mapping cannot prove ownership of every historical IP.",
            "An empty WAN list means unattributed, not that every WAN was affected.",
            "Snapshot OK does not verify public DNS or historical failover.",
            "Sources are scanned newest-file first with bounded reads, not guaranteed complete.",
            "Repeated classes are grouped within one-hour buckets; occurrences and first/last times are retained, not every intermediate timestamp.",
            "Smaller estimated on-disk sources scan first. Each remaining source reserves 6 scan seconds and 2000 candidate groups; completed sources release unused capacity. A source may borrow up to 5000 candidate groups, within a shared pool of max(5000, 2000 * enabled sources), at most 14000 groups.",
            "Scanning stops within a 60-second collection wall budget and 50 collector CPU seconds, leaving headroom under the unchanged 75-second, 60-CPU-second and 256 MiB process limits. Reservations are subject to these total deadlines. Byte budgets remain independent.",
            "Final allocation guarantees up to 256 available groups per source, shares spare slots fairly, and exports at most 5000 groups overall. The report-byte ceiling may reduce guarantees after surplus slots are trimmed.",
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
                   "seconds_per_source": SCAN_WALL_SECONDS,
                   "reserved_seconds_per_source": SOURCE_SECONDS,
                   "scan_wall_seconds": SCAN_WALL_SECONDS,
                   "scan_cpu_seconds": SCAN_CPU_SECONDS,
                   "source_budget_mode": "shared_bounded",
                   "aggregation_bucket_seconds": AGGREGATION_SECONDS,
                   "guaranteed_groups_per_source": MIN_SOURCE_EVENTS,
                   "candidate_groups_per_source": MAX_EVENTS,
                   "reserved_candidate_groups_per_source": MAX_SOURCE_EVENTS,
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
    byte_budget = MAX_TOTAL // len(sources)
    report["limits"]["reserved_per_source"] = {
        "bytes": byte_budget, "events": MIN_SOURCE_EVENTS, "seconds": SOURCE_SECONDS}
    pool = max(MAX_EVENTS, MAX_SOURCE_EVENTS * len(sources))
    report["limits"]["candidate_groups_total"] = pool
    # Sorting is an estimate, not a coverage guarantee. Reserve capacity for
    # every unvisited source even if an early source proves unexpectedly busy.
    if progress:
        progress.mark("source_order", source="none", force=True)
    ordered = sorted(sources, key=lambda item: scan_workload(item[1]))
    for index, (source, path) in enumerate(ordered):
        remaining = len(ordered) - index - 1
        available = max(0.0, min(scan_deadline - time.monotonic(),
                                 cpu_deadline - time.process_time()))
        seconds = min(available, max(SOURCE_SECONDS, available - remaining * SOURCE_SECONDS))
        quota = {
            "bytes": byte_budget,
            "events": min(MAX_EVENTS, pool - remaining * MAX_SOURCE_EVENTS),
            "seconds": seconds,
        }
        started = time.monotonic()
        scan(source, path, settings, privacy, report, quota, now, cutoff,
             cpu_deadline=cpu_deadline, progress=progress)
        summary = report["sources"][-1]
        summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
        summary["budget"]["seconds"] = round(seconds, 3)
        summary["borrowed_seconds"] = round(max(0.0, seconds - SOURCE_SECONDS), 3)
        summary["borrowed_candidate_groups"] = max(0, quota["events"] - MAX_SOURCE_EVENTS)
        pool -= summary["candidate_event_groups"]
    order = {name: index for index, (name, _) in enumerate(sources)}
    report["sources"].sort(key=lambda row: order[row["source"]])
    if progress:
        progress.mark("allocate", source="none", force=True)
    allocate_sources(report)
    report["events"].sort(key=lambda event: event["time"])
    if progress:
        progress.mark("report_limit", force=True)
        measured = progress.measurements()
        report["collection"] = {
            "elapsed_seconds_before_write": measured["elapsed_seconds"],
            "cpu_seconds_before_write": measured["cpu_seconds"],
        }
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
    worker, owns_job, progress, report = None, False, None, None
    try:
        lock_path = job / "worker.lock"
        if lock_path.is_symlink():
            return 2
        worker = lock_path.open("a+b")
        try:
            fcntl.flock(worker, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 2
        owns_job = True
        state = json.loads(small_file(job / "status.json", 4096))
        started = int(state["started"])
        if state.get("state") != "queued" or not 0 <= time.time() - started < 120:
            return 2
        progress = JobProgress(job, started)
        progress.mark("starting", force=True)
        settings = json.loads(small_file(job / "request.json", 4096))
        if type(settings.get("days")) is not int or not 1 <= settings["days"] <= 14 or any(
                type(settings.get(key)) is not bool for key in ("network", "web", "runtime")):
            raise ValueError("Invalid settings")
        progress.data.update(requested_days=settings["days"], network=settings["network"],
                             web=settings["web"], runtime=settings["runtime"])
        resource.setrlimit(resource.RLIMIT_CPU, (60, 65))
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        def wall_expired(signum, frame):
            raise CollectionDeadline("WALL_TIME_LIMIT")
        def cpu_expired(signum, frame):
            raise CollectionDeadline("CPU_TIME_LIMIT")
        signal.signal(signal.SIGALRM, wall_expired)
        signal.signal(signal.SIGXCPU, cpu_expired)
        signal.alarm(75)
        report = collect(settings, started, progress)
        progress.completed_totals(report)
        progress.mark("write_report", source="none", force=True)
        atomic(job / "report.json", report)
        progress.finish("complete", partial=report["partial"])
        return 0
    except Exception as error:
        code, line = failure_code(error), collector_error_line(error)
        # Release collected data and exception frames before a bounded failure
        # write. Never persist exception text, traceback, paths or private context.
        error.__traceback__ = None
        report = None
        try:
            if owns_job:
                if progress is None:
                    progress = JobProgress(job, started)
                progress.finish("failed", code, line)
        except Exception:
            # The last successful checkpoint still survives a failed final write.
            pass
        return 1
    finally:
        signal.alarm(0)
        if owns_job:
            for name in ("request.json", "request.json.tmp", "report.json.tmp", "status.json.tmp"):
                try:
                    (job / name).unlink(missing_ok=True)
                except OSError:
                    pass
        if worker is not None:
            worker.close()


if __name__ == "__main__":
    sys.exit(main())
