# Debug information

Reference for **Services > Multi-WAN DDNS > Debug information**. See
[README.md](../README.md#debug-information) for the short version.

The collector exports **structured diagnostics** from logs that already exist on
the firewall. It does not change DNS, restart services, record future activity or
upload anything.

- [Running a collection](#running-a-collection)
- [What is collected](#what-is-collected)
- [Privacy model](#privacy-model)
- [Storage and retention](#storage-and-retention)
- [Progress, totals and failure diagnostics](#progress-totals-and-failure-diagnostics)
- [Resource limits](#resource-limits)
- [How events are allocated and dropped](#how-events-are-allocated-and-dropped)
- [Report schema (`mwddns-debug-v2`)](#report-schema-mwddns-debug-v2)
- [Interpreting a report](#interpreting-a-report)
- [Page behaviour](#page-behaviour)

## Running a collection

1. Open **Services > Multi-WAN DDNS > Debug information**.
2. Choose the number of recent days (default **3**, range 1-14).
3. Select the optional network / WebGUI / runtime sources.
4. Click **Save and collect**.

Collection reads existing logs only. The background collector runs on the
explicitly installed Python 3.11 interpreter. No extra cron job or permanent
watcher is added.

## What is collected

| Source | Contents |
|---|---|
| MWDDNS | Selected MWDDNS system events |
| DHCP | WAN DHCP client events from `dhcpd.log` |
| Network | Gateway, PPP and routing events |
| WebGUI | PHP errors and nginx errors |

Numbered plain, gzip, bzip2 and xz rotations are supported. Unsupported
compression, missing files, unparsed timestamps and read limits are reported
explicitly. Existing log retention on the firewall may be shorter than the
requested window.

Web diagnostics include recognized HTTP status codes (including nginx combined
access logs), reported OS error numbers, fixed failure / operation / phase /
backend classifications, numeric nginx worker and connection identifiers, and
explicit PHP-FPM startup, ready, reload, stop and child-exit messages when
present in scanned logs. Endpoint paths, request URLs, headers and raw error
messages are never exported. Sensitive-line filtering runs first.

## Privacy model

Exports are structured diagnostics, **not** raw messages passed through a
best-effort regular-expression scrub. Only fixed event categories, validated
dates and numbers, known program and function names, and opaque aliases leave
the collector.

Not exported: arbitrary text, usernames, domain names, credentials,
configuration, and the alias dictionaries themselves. Unknown error text is
intentionally omitted, which can limit diagnosis of new errors. There is **no
raw / unredacted download switch**.

Aliases keep one report internally consistent without revealing values:

- `WAN_1`, `WAN_2`, … distinguish monitored interfaces throughout one report.
- `IP4_N` / `IP6_N` distinguish addresses without disclosing them.

The private interface-name legend is visible only on the authenticated page and
is never included in the download. **Do not share screenshots of that legend.**
Historical IP ownership is not guessed when an event lacks an interface or
gateway identifier.

## Storage and retention

New Debug jobs use the private `/tmp/mwddns-debug` directory rather than the
small `/var/run` filesystem. Older reports under `/var/run/mwddns/debug` remain
downloadable and deletable until they expire.

- Reports are root-private runtime files, never files under the web document root.
- Download expires after **24 hours**; expired files are removed lazily on the next collection.
- At most **three** jobs are retained, and boot cleanup removes owned jobs.
- Collection requires room for the bounded report plus a **1 MiB** safety margin. Insufficient space is reported explicitly, without touching DNS rules or credentials.
- Preview is limited to **128 KiB**; use **Download sanitized report** for the full JSON.
- Reports can be deleted explicitly.

**Recent Debug reports** lists retained jobs newest first with browser-local
times, status, and open / download actions. Listing reads metadata only; it does
not start a collection or extend expiry.

## Progress, totals and failure diagnostics

The collector retains bounded progress checkpoints. The result page shows the
last collector stage and source, elapsed and collector CPU seconds, scan indexes
and counters. Checkpoint writes are throttled to two seconds with explicit stage
and file checkpoints. Displayed times describe the last persisted measurement,
not GUI waiting time. A worker wall-clock or CPU deadline escapes per-file
read-error handling and is recorded as a specific failure code.

Completed jobs show collection-wide source, file and byte counts, matched /
retained / dropped occurrences, and exported event groups, calculated after
final report allocation and size trimming. Per-source progress fields are not
displayed as misleading zero totals after completion. During global stages with
no active source, source-specific progress is labelled not applicable. Jobs
collected by older versions may lack totals; **missing totals are never
invented**.

Two small downloads are available:

| Download | When | Contents |
|---|---|---|
| **Download failure diagnostics** | After a failed collection, before retrying | Allowlisted stage / source / reason codes, validated timestamps, numeric counters |
| **Download collector diagnostics** | After a completed collection | The same, plus final worker measurements and bounded totals |

Neither includes a raw log line, filename, traceback, exception message,
credential or configuration. A numeric collector code line can help locate an
exception without disclosing its text. Old jobs without checkpoints report
missing measurements rather than invented durations.

### Unconfirmed status

A missing final status after 120 seconds is explicitly **unconfirmed**. It does
not establish a timeout, memory exhaustion, or even worker exit. A live worker
lock prevents deletion or overlapping collection despite a stale GUI status. The
last source and stage are an investigation lead, not proof that the named log
caused the failure.

## Resource limits

| Bound | Value |
|---|---|
| Worker wall-clock deadline | 75 s |
| Scanning wall clock, from collection entry | 60 s |
| Collector CPU, soft / hard | 60 s / 65 s |
| Scanning collector CPU | 50 s |
| Worker memory | 256 MiB |
| Total decompressed scan budget | 64 MiB |
| Per-file scan budget | 8 MiB |
| Files per source | 24 |
| Exported event groups | 5,000 |
| Shared candidate pool | max(5,000, 2,000 x enabled sources), never above 14,000 |
| Per-unvisited-source reservation | 6 scan seconds, 2,000 candidate groups |
| Report output cap | 6 MiB |

Scanning bounds leave headroom under the unchanged worker limits for
serialization and output. This release does not claim that every 11- or 14-day
collection will complete; retained logs and resource limits still apply.

## How events are allocated and dropped

- Scan bytes are divided equally among enabled sources.
- Smaller estimated on-disk sources are processed first, so completed sources release unused capacity. Compressed disk size is only a work estimate.
- Per-source reservations are subject to the total deadlines. A busy source can borrow up to 5,000 candidate groups.
- Final allocation guarantees up to 256 available groups per source, then shares remaining slots fairly within the 5,000 exported groups overall. DHCP traffic cannot consume other sources' reservations.
- Excess groups retain important events first, then newer events within that priority, subject to per-class reservations: errors reserve one third of a source's slots, transitions one half, and routine messages the remainder.
- Unused reservations are borrowable, but an error flood cannot take the slots reserved for WAN and service context.

Source summaries distinguish matched, retained, grouped and dropped occurrences,
including per-class counts. The page explains each source warning, actual versus
allocated scan seconds, candidate capacity, and occurrences dropped at the
candidate, shared-allocation and report-size stages. Dropped counts cannot
measure records that were never read.

## Report schema (`mwddns-debug-v2`)

Repeated requests, PHP errors and other repetitive classes are grouped within
one-hour buckets. Each group carries `occurrences`, `first_seen` and `last_seen`;
`time` is its first occurrence. Intermediate timestamps are not retained.
ACK/BOUND, link changes and script-reason transitions remain separate.

> **Sum `occurrences`, not array length, when counting retained events.**

PHP fatal errors with an identified file and function can merge across changing
PIDs when their other structured fields match. At most four `pid_samples` are
kept; `pid_scope` and `pid_samples_limited` disclose multiple processes and
truncated samples. DHCP process identity is not merged across PIDs.

Source summaries record the oldest and newest observed timestamps inside the
requested window. Neither those bounds nor empty warnings prove continuous log
coverage. The schema also adds pre-output timing measurements.

## Interpreting a report

Check `partial`, source warnings, dropped counts and coverage timestamps before
drawing conclusions. The resource bounds above are limits, not a promise that
the whole requested window fits.

- Per-event-code matched / retained / dropped counts reveal which messages were lost. Codes can overlap on the same record, so their totals must not be added as if they were disjoint events.
- A bounded five-minute `DHCPREQUEST` histogram counts scanned, non-sensitive requests before event eviction. It combines WANs and PIDs per source; use the individual event aliases for attribution.
- The source table separates empty or stale logs, matching events, and collection limits.
- DHCP details distinguish request destination, server and leased-address aliases, explicit script reasons and numeric intervals. A renewal interval is not a lease lifetime. Server and destination addresses never establish WAN ownership; inferred current leased-address matches are labelled.
- `EXPIRE` alone does not prove timer expiry, and `rc.newwanip` alone does not prove that the public address changed.
- An errno is reported, not translated using another operating system's error table. Classifications and equal event counts alone do not establish a root cause or pair separate requests.
- Offline regressions do not certify on-device pfSense behaviour.

## Page behaviour

The page uses theme-compatible padded panels, a responsive two-column form,
separate action rows and a keyboard-scrollable preview. The private WAN legend
starts collapsed.

Downloads are named after the report generation time, for example
`mwddns-debug-2026-09-18_21-46-52.json`, not the time the download was clicked,
so downloading the same report twice produces the same filename. Coverage
timestamps use the browser locale and time zone including seconds, while hover
text and the downloaded JSON retain the original ISO timestamps. Source names,
timestamps and numeric groups stay intact, with horizontal table scrolling on
narrow screens. Plugin panels and controls follow the main page's square-corner
geometry without changing other pfSense pages or overriding theme colours.
