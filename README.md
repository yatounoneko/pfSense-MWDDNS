# pfSense-MWDDNS
pfSense Multi-WAN DDNS Plugin

A pfSense package that monitors **multiple WAN
interfaces** and keeps DNS A/AAAA records in sync automatically across multiple DNS providers.

The purpose of this plugin is to solve the problem that the native DDNS plugin cannot add multiple A/AAAA records to a single hostname at the same time.
(Runs independently)

---

Dashboard widget:

<img width="auto" height="150" alt="Image" src="https://github.com/user-attachments/assets/fc0b71f2-c7f2-4889-b89c-3705e9a2acca" />

Portal / status page:

<img width="800" height="auto" alt="Image" src="https://github.com/user-attachments/assets/73700895-9a3c-48ed-b622-b094f6b5ebb9" />

Rule configuration：

<img width="800" height="auto" alt="Image" src="https://github.com/user-attachments/assets/b8efbede-9f06-4c27-941d-2a5e1cb238cd" />


---

## Features

| # | Feature |
|---|---------|
| 1 | Per-rule configuration: **Name**, **Hostname**, **TTL**, **Interfaces**, **Record Types** (A / AAAA / both) plus provider-specific fields |
| 2 | Each rule can watch **multiple WAN interfaces** simultaneously; one A/AAAA record is maintained per interface address |
| 3 | **IPv6/AAAA support** – select A, AAAA, or both per rule; interfaces without the requested address type are silently skipped |
| 4 | **Pluggable DNS providers** – Cloudflare, Alibaba Cloud DNS (International), Alibaba Cloud DNS (China), Alibaba Cloud ESA, PowerDNS |
| 5 | **Portal / status page** (`Services → Multi-WAN DDNS`) shows custom name, provider, hostname, per-interface IPv4/IPv6 with colour indicators: 🟢 green = DNS matches, 🔴 red = DNS mismatch |
| 6 | **Dashboard widget** (titled “Multi-WAN DDNS”) with the same colour-coded status |
| 7 | **Force Update** button on every rule's edit page for instant sync |
| 8 | Cron job runs every 5 minutes in the background |
| 9 | Written in **PHP 8 + Python 3.11 + shell**; requires the pfSense `python311` package for the watcher |
| 10 | Provider-aware status matching for proxy/CDN modes (see Proxy-mode matching note) |
| 11 | Background Debug information collection: recent 3 days by default, strict structured privacy, consistent WAN aliases, local preview and JSON download |

---

## Supported DNS Providers

| Provider Key | Description | Auth Method |
|---|---|---|
| `cloudflare` | Cloudflare (global) | Bearer API Token |
| `alidns_intl` | Alibaba Cloud DNS – International (`ap-southeast-1`) | AccessKey + HMAC-SHA1 V1 |
| `alidns_cn` | Alibaba Cloud DNS – China mainland | AccessKey + HMAC-SHA1 V1 |
| `aliesa` | Alibaba Cloud ESA (Edge Security Acceleration) | AccessKey + ACS4-HMAC-SHA256 V4 |
| `powerdns` | PowerDNS Authoritative Server (self-hosted) | X-API-Key header |

---

## Repository layout

### Debug information (1.1.0)

Open **Services > Multi-WAN DDNS > Debug information**. Choose the number of
recent days (default **3**, range 1-14), select optional network/WebGUI/runtime
sources, and click **Save and collect**. This reads existing logs; it does not
record for three future days, change DNS, restart services, or upload anything.

The background collector uses the explicitly installed Python 3.11 interpreter.
It includes selected MWDDNS system events, WAN DHCP client events from
`dhcpd.log`, gateway/PPP/routing events, PHP errors and nginx errors. Numbered
plain, gzip, bzip2 and xz rotations are supported. Unsupported compression,
missing files, unparsed timestamps and read limits are reported explicitly.
Existing log retention may be shorter than the requested three days.

Exports are **structured diagnostics**, not raw messages with a best-effort
regular-expression scrub. Only fixed event categories, validated dates/numbers,
known program/function names, and opaque aliases leave the collector. Arbitrary
text, usernames, domain names, credentials, configuration and alias dictionaries
are not exported. Unknown error text is intentionally omitted, which can limit
diagnosis of new errors. There is no raw/unredacted download switch.

`WAN_1`, `WAN_2`, etc. distinguish monitored interfaces throughout one report;
`IP4_N` / `IP6_N` distinguish addresses without revealing them. The private
interface-name legend is visible only on the authenticated page, not in the
download. Do not share screenshots of that legend. Historical IP ownership is
not guessed when the event lacks an interface/gateway identifier.

Reports are root-private runtime files, not files under the web document root.
They expire for download after 24 hours; expired files are removed lazily on the
next collection, and at most three jobs are retained. Preview is limited to
128 KiB; use **Download sanitized report** for the full collected JSON. Reports
can also be explicitly deleted. **Recent Debug reports** lists retained jobs
newest first with browser-local times, status, open and download actions.
Listing reads metadata only; it does not start a collection or extend expiry.
No extra cron job or permanent watcher is added.

Version 1.0.18 also retains bounded progress checkpoints. The result page shows
the last collector stage/source, elapsed and collector CPU seconds, scan indexes
and counters. Writes are throttled to two seconds with explicit stage/file
checkpoints. Times describe the last persisted measurement, not GUI waiting time.
A worker wall-clock or CPU deadline now escapes per-file read-error handling
and is recorded as a specific failure code.

Starting with 1.1.0, completed jobs show collection-wide source/file/byte counts,
matched/retained/dropped occurrences and exported event groups, calculated after
final report allocation and size trimming. Per-source progress fields are not
displayed as misleading zero totals after completion. During global stages with
no active source, source-specific progress is labelled not applicable. Jobs
collected by older versions may lack totals; missing totals are never invented.
The small collector-diagnostics download includes these bounded totals.

If collection fails, use **Download failure diagnostics** in the result or recent
reports list before retrying. Completed jobs also offer **Download collector
diagnostics** for final worker measurements. These small JSON exports contain
only allowlisted stage/source/reason codes, validated timestamps and numeric
counters; no raw log line, filename, traceback, exception message, credential or
configuration is included. A numeric collector code line can help locate an
exception without disclosing its text. Old jobs without checkpoints report
missing measurements rather than invented durations. The normal report retains
schema `mwddns-debug-v2` and adds pre-output timing measurements.

A missing final status after 120 seconds is explicitly **unconfirmed**: it does
not establish a timeout, memory exhaustion or even worker exit. A live worker
lock prevents deletion or overlapping collection despite a stale GUI status.
The last source/stage is an investigation lead, not proof that its log caused
the failure. Existing 75-second wall, 60/65-second soft/hard CPU and 256 MiB memory
limits are unchanged. This release does not claim every 11- or 14-day collection
will complete; retained logs and resource limits still apply.

The worker has a 75-second deadline, a 64 MiB total decompressed scan budget,
8 MiB per file, 24 files per source, 5,000 event groups, and a 6 MiB output cap.
Scan bytes are divided equally among enabled sources. Smaller estimated on-disk
sources are processed first so completed sources can release unused capacity.
Each unvisited source reserves 6 scan seconds and 2,000 candidate groups, subject
to the total deadlines. Scanning is bounded to 60 wall-clock seconds from collection
entry and 50 collector CPU seconds, leaving headroom under the unchanged worker
limits for serialization and output. Compressed disk size is only a work estimate.
A busy source can borrow up to 5,000 candidate groups. The shared candidate pool
is max(5,000, 2,000 * enabled sources), never more than 14,000 groups; the existing
256 MiB worker memory limit still applies. Final allocation guarantees up to 256
available groups per source, then shares remaining slots fairly within 5,000
exported groups overall. DHCP traffic cannot consume other sources' reservations.
Excess groups retain important events first, then newer events within that
priority, subject to per-class reservations. Errors reserve one third of a
source's slots, transitions one half, and routine messages the remainder.
Unused reservations are borrowable, but an error flood cannot take the slots
reserved for WAN/service context. Source summaries distinguish matched,
retained, grouped and dropped occurrences, including per-class counts.
The page explains each source warning, actual versus allocated scan seconds,
candidate capacity, and occurrences dropped at the candidate, shared allocation
and report-size stages. Dropped counts cannot measure records that were never
read. New source summaries also record the oldest/newest observed timestamps
inside the requested window; neither these bounds nor empty warnings prove
continuous log coverage.

Schema `mwddns-debug-v2` groups repeated requests, PHP errors and other repetitive
classes within one-hour buckets. Each group has `occurrences`, `first_seen` and
`last_seen`; `time` is its first occurrence. Intermediate timestamps are not
retained. ACK/BOUND, link changes and script-reason transitions remain separate.
Sum `occurrences`, not array length, when counting retained events.

PHP fatal errors with an identified file and function can merge across changing
PIDs when their other structured fields match. At most four `pid_samples` are
kept; `pid_scope` and `pid_samples_limited` disclose multiple processes and
truncated samples. DHCP process identity is not merged across PIDs.

Per-event-code matched/retained/dropped counts reveal which messages were lost.
Codes can overlap on the same record, so their totals must not be added as if
they were disjoint events. A bounded five-minute DHCPREQUEST histogram counts
scanned, non-sensitive requests before event eviction. It combines WANs/PIDs
per source; use the individual event aliases for attribution. The source table
separates empty/stale logs, matching events and collection limits.

Web diagnostics include recognized HTTP status codes (including nginx combined
access logs), reported OS error numbers, fixed failure/operation/phase/backend
classifications, numeric nginx worker/connection identifiers, and explicit
PHP-FPM startup/ready/reload/stop/child-exit messages when present in scanned logs.
Endpoint paths, request URLs, headers and raw error messages are never exported.
Sensitive-line filtering still runs first. An errno is reported, not translated
using another operating system's error table; classifications and equal event
counts alone do not establish a root cause or pair separate requests.

The page uses theme-compatible padded panels, a responsive two-column form,
separate action rows and a keyboard-scrollable preview. The private WAN legend
starts collapsed. Downloads use the report generation time, for example
`mwddns-debug-2026-09-18_21-46-52.json`, not the time the download was clicked.
Downloading the same report twice still produces the same filename.
Coverage timestamps use the browser locale and time zone, including seconds;
hover text and downloaded JSON retain the original ISO timestamps. Source names,
timestamps and numeric groups stay intact, with horizontal table scrolling on
narrow screens. Plugin panels and controls use the main page's square-corner
geometry without changing other pfSense pages or overriding theme colors.

DHCP details distinguish request destination, server and leased-address aliases,
explicit script reasons and numeric intervals. A renewal interval is not a lease
lifetime. Server/destination addresses never establish WAN ownership; inferred
current leased-address matches are labelled. `EXPIRE` alone does not prove timer
expiry, and `rc.newwanip` alone does not prove that the public address changed.

These are resource bounds, not a promise that all three days fit. Check
`partial`, source warnings, dropped counts and coverage timestamps before
interpreting results. Offline regressions do not certify on-device pfSense
behavior. Upgrade using the same `sh install.sh` flow without uninstalling;
existing rules, credentials and debug preferences are retained.

### 1.1.0 release

- Show actual collection-wide Debug totals after completion instead of reset
  source counters. Keep per-source checkpoints for active and failed jobs.
- Preserve bounded, structured diagnostic exports and all existing resource
  limits. Missing or rotated-away logs remain explicit coverage limitations.
- Keep one shared collector version declaration for compatibility with existing
  GUI upgrade validators; installer, package XML and collector versions agree.
- Include the preceding maintenance updates: rule copying and duplicate-name
  protection, native action icons and Cloudflare proxy indicators, consistent
  rectangular/localized pages, Debug history and failure diagnostics, and
  bounded upgrade-upload retention.
- Upgrade using the attached versioned release ZIP with Preserve data selected.
  GitHub's automatic source archives are not GUI upgrade packages.

### 1.0.18 maintenance update

- Prevent collector deadlines from being swallowed as recoverable log I/O errors.
- Retain bounded, privacy-safe progress and failure codes with elapsed/CPU timings.
- Add failure diagnostic downloads and live progress to the existing Debug page.
- Distinguish an explicitly recorded failure from an unconfirmed stale status;
  keep worker locks to protect active jobs during removal and new collection.
- Preserve existing collection limits, DNS behavior and saved configuration.

### 1.0.17 maintenance update

- Add a native `fa-regular fa-clone` action before Edit. It opens the Add Rule
  form with the source configuration, including provider fields and credentials,
  prefilled. Source revision checks prevent a stale list from copying a
  different rule after reindexing. No rule is saved and no DNS update starts
  until Save; Cancel or leaving abandons the copy. Runtime update metadata is
  not copied, and credentials are not put in URLs or draft storage.
- Keep the source name in the form and require a different name before saving.
  Names are compared after trimming surrounding whitespace and folding ASCII
  letter case. New rules and edits reject conflicts with a translated error;
  an edit excludes its own name. The shared write lock rejects any increase in
  duplicate-name counts without preventing removal of legacy duplicates.
- Save retains the existing CSRF/revision checks and immediate DNS update
  behavior. A rejected save does not invoke the updater.

### 1.0.16 maintenance update

- Align the edit and delete controls in a shared flex row with matching 18px
  native icons and equal-height transparent controls. Existing delete
  confirmation, POST, revision and CSRF checks are unchanged.
- Start the Cloudflare token storage warning on a separate line, retaining
  its translated text and warning emphasis.
- The version increment allows testing the normal data-preserving upgrade
  from 1.0.15. DNS update behavior and upload/report retention are unchanged.

### 1.0.15 maintenance update

Rule deletion uses the native Font Awesome `fa-solid fa-trash-can` icon without
a filled button background. The red icon keeps the existing confirmation,
POST, revision check and CSRF protection.

Uploading a fourth release automatically removes the oldest idle temporary
upload to maintain the three-job limit. Ready, expired, completed, failed and
rolled-back jobs are eligible only when their worker lock is free and their
persisted state is idle. Active, interrupted, unknown and recovery-required
jobs are not automatically removed. If all slots are protected, the upload is
refused with an explanation. Temporary cleanup is bounded to the selected
private `/tmp/mwddns-upgrade/job-*` tree and does not follow symbolic links.
Persistent credential-bearing backups in `/conf/mwddns-backups` are never
removed by upload rotation.

Debug history lists report times, statuses and open/download actions.
The existing 24-hour expiry and three-job retention policy are unchanged.

### 1.0.14 maintenance update

- Add bounded, structured WebGUI diagnostics without exporting requests, endpoints
  or raw messages. Existing privacy filters, WAN/PID identity and quotas remain.
- Keep Debug table identifiers/timestamps/numeric groups intact and format visible
  coverage timestamps with the browser locale/time zone; JSON remains ISO.
- Use a red delete-rule button with a separate trash icon, preserving POST/CSRF,
  revision checking and explicit confirmation.
- Use a localized upgrade confirmation dialog and translated validation/stage
  labels. The exact reset phrase remains CLEAR MWDDNS; server-side trust, CSRF,
  version, backup and reset checks are unchanged.
- Share square-corner styling across the rule, edit, Debug and upgrade pages.
  Upgrades still preserve data by default.

### 1.0.13 maintenance update

- Let busy Debug sources borrow unused scan time and candidate capacity while
  preserving reservations for unvisited sources and all existing process limits.
- Keep the 5,000-group final output and 6 MiB report caps; do not merge DHCP WAN
  or PID identities. Existing five-minute request histograms remain available.
- Explain limit reasons and per-stage dropped counts in English, Traditional
  Chinese and Simplified Chinese, with actual scan time and requested-window bounds.
- Upgrade using the existing WebGUI ZIP upload with data preservation selected,
  or the original installer without uninstalling. Rules and credentials remain
  unchanged. A 14-day request is still not a guarantee of 14-day retained logs.

### 1.0.12 maintenance update

- Show **Discard temporary upload (keep backup)** for jobs whose status file is
  missing or malformed. The action still requires an authenticated administrator,
  a valid POST/CSRF token and the existing worker lock/path checks.
- Checking, queued and running jobs remain protected. Cleanup affects temporary
  upload files only, never the persistent upgrade backup.
- Existing 1.0.10/1.0.11 installations can upload the versioned 1.0.12 release ZIP.
  If an older installation already has all three slots blocked by unreadable
  jobs, use the original manual installation flow without uninstalling; the
  newer cleanup page is available only after that installation completes.

### 1.0.11 maintenance update

- Treat both `false` and `-1` configuration-write results as failures during
  rule/Debug saves and installer registration/removal.
- Clean incomplete uploads before starting a worker. Discarding an abandoned
  upload no longer requires a readable status file; worker locking, temporary
  path restrictions and persistent backups are unchanged.
- An existing 1.0.10 installation can upload the versioned 1.0.11 release ZIP
  through the upgrade page. Keep **Preserve data** selected for a normal update.

### Local WebGUI upgrades (1.0.10 and later)

Install 1.0.10 once using the original `unzip` / `sh install.sh` flow. Thereafter,
open **Services > Multi-WAN DDNS > Plugin upgrade**, upload a newer versioned
release ZIP, wait for validation, then choose a mode and click **Upgrade now**.
The installed updater rejects equal/older versions; there is no bypass switch.
Only numeric major.minor.patch release versions and release-manifest ZIPs are
supported, not GitHub source-code ZIPs. The ZIP limit is 8 MiB and the WebGUI/PHP
upload limit may be lower.

**Preserve data** is the default. **Reset data** requires typing
`CLEAR MWDDNS` and removes only MWDDNS rules, provider credentials, preferences,
cache/status and Debug data after backup. Other pfSense settings and existing
records at DNS providers are not deliberately cleared. Do not uninstall first.

Uploads, extracted files and status live under `/tmp/mwddns-upgrade`. Treat them
as temporary and lost on reboot. Before either upgrade mode, private backups of
plugin configuration, existing application files and runtime data are written
under `/conf/mwddns-backups/upgrade-ID` (directories 0700, files 0600).
These contain credentials and survive reset/reboot; do not share them. Backups
are not automatically deleted. Remove old backups only after acceptance and
your own retention decision. At most three temporary uploads are kept; use
**Discard temporary upload** to free a slot without deleting its backup.

The page requires UID-0 administrator or effective `page-all` privilege without
read-only restrictions. A delegated MWDDNS page privilege alone is insufficient.
pfSense authentication/CSRF and the plugin form token remain enabled.

**Only use trusted releases.** The installed worker validates archive paths,
file types/counts/sizes, manifest SHA256 and matching version fields before
executing the ZIP's installer as root. The manifest is integrity metadata,
**not a digital signature or proof of publisher identity**. Confirm the source
and compare the displayed archive SHA256 with an independently trusted checksum.

Installation runs in a background process, serializes MWDDNS operations and
checks the installed files/version/watcher. It does not restart PHP-FPM/nginx.
Failure triggers a best-effort rollback of backed-up MWDDNS files/configuration;
unrelated effects of an arbitrary trusted installer cannot be rolled back.
Power loss/reboot can interrupt installation before rollback and require manual
recovery using the persistent backup and a known-good release. Do not reboot or
make concurrent pfSense configuration changes during installation: the official
configuration writer serializes file replacement, not the entire read-modify-write
transaction across all system writers. Offline fixtures are not a device upgrade
or power-loss-recovery certification.

### Source tree

```
src/
└── usr/local/
    ├── pkg/
    │   ├── mwddns.inc              # Core library (config, interface helpers, provider dispatch, cron)
    │   ├── mwddns.xml              # pfSense package definition
    │   └── mwddns/                 # Provider modules
    │       ├── cloudflare.php      # Cloudflare provider
    │       ├── alidns.php          # Alibaba Cloud DNS (intl + CN)
    │       ├── aliesa.php          # Alibaba Cloud ESA
    │       ├── powerdns.php        # PowerDNS HTTP API
    │       └── locale/             # GUI translations
    │           ├── zh_CN.php       # Simplified Chinese
    │           └── zh_HK.php       # Traditional Chinese (HK terminology)
    ├── www/
    │   ├── mwddns.php              # Rules list / portal status page
    │   ├── mwddns_edit.php         # Add / Edit rule (incl. Force Update)
    │   └── widgets/widgets/
    │       └── mwddns.widget.php   # Dashboard widget
    └── bin/
        └── mwddns_cron.php         # Periodic cron runner
install.sh                          # Manual installation helper
```

---

## Requirements

* pfSense CE: 2.8.1 is the user-reported operational baseline. The 2.9.0 upgrade exposed a removed configuration API; this tree contains source-level compatibility fixes, **not completed on-device certification**. Older-version fallbacks remain, but 2.7.x and 2.9.x must not be read as universally tested.
* Python 3.11
* Credentials/API access for **at least one supported DNS provider**:
  * Cloudflare: API Token + Zone ID
  * Alibaba Cloud DNS (intl/CN): AccessKey ID + AccessKey Secret + Root Domain
  * Alibaba Cloud ESA: AccessKey ID + AccessKey Secret + Site ID
  * PowerDNS: API URL + API Key + Server ID + Zone Name

---

## Installation

### Install dependencies
> Skip installation only if `/usr/local/bin/python3.11` is already available. A different Python version or a `python3` alias is not equivalent. Use the repository configured by pfSense; do not add a generic FreeBSD package repository.
```sh
# Install Python3.11
pkg install python311

# Verify installation
python3.11 --version
```

### Option A – Manual (SSH into pfSense)

> pfSense 2.8.1 You must enable System/Advanced Settings -> Secure Shell

Access via CMD or other terminals(Replace your pfSense IP):
```cmd
ssh admin@192.168.0.1
```

or custom SSH port

```cmd
ssh admin@192.168.0.1 -p 6666
```

Then like:
```
C:\Users\YOU>ssh admin@192.168.0.1 -p 6666
(admin@192.168.0.1) Password for admin@pfSense.lan:
pfSense - Netgate Device ID: abcde...

*** Welcome to pfSense 2.8.1-RELEASE on pfSense ***

 LAN (lan)    -> ix1  -> v4: 192.168.0.1/24
 Wan1 (wan)   -> igc0 -> v4/DHCP4: 192.168.0.2/24
 Wan2 (opt1)  -> igc1 -> v4/DHCP4: 192.168.0.3/21
 Wan3 (opt2)  -> igc2 -> v4/DHCP4: 192.168.0.4/25

 0) Logout / Disconnect SSH            9) pfTop
 1) Assign Interfaces                 10) Filter Logs
 2) Set interface(s) IP address       11) Restart GUI
 3) Reset admin account and password  12) PHP shell + pfSense tools
 4) Reset to factory defaults         13) Update from console
 5) Reboot system                     14) Disable Secure Shell (sshd)
 6) Halt system                       15) Restore recent configuration
 7) Ping host                         16) Restart PHP-FPM
 8) Shell

Enter an option: 
```
Select item 8 to enter Shell

```sh
# Upload your download file on pfSense GUI first. (like: https://192.168.0.1/diag_command.php -> Upload File)
unzip /tmp/pfSense-MWDDNS-(version).zip
cd pfSense-MWDDNS-(version)/
sh install.sh
```

Optional (only SSH manually installed on pfSense):

```sh
cd pfSense-MWDDNS-(version)/
sh install.sh                            # install
sh install.sh --help
sh install.sh --uninstall                # remove (keep config.xml settings)
sh install.sh --uninstall --purge-config # remove and purge config.xml settings
```

### Option B – pfSense Package Manager (future)

Once packaged as a proper FreeBSD `.pkg`, it will be installable via
**System → Package Manager → Available Packages**.

---

## Usage

1. Navigate to **Services → Multi-WAN DDNS**.
2. Click **Add** to create a rule.
3. Fill in the common fields:

   | Field | Description |
   |-------|-------------|
   | Rule Name | Friendly label shown in the portal |
   | Hostname | FQDN to update (e.g. `home.example.com`) |
   | TTL | Seconds (1 = auto, 60–86400; AliDNS minimum is 600) |
   | Interfaces | Hold Ctrl/⌘ to select multiple WAN interfaces |
   | Record Types | **A** (IPv4), **AAAA** (IPv6), or both. At least one must be selected. |

4. Select the **DNS Provider** and fill in the provider-specific fields:

### Cloudflare

| Field | Description |
|-------|-------------|
| API Token | Bearer token with *Zone → DNS → Edit* permission |
| Zone ID | 32-char hex from Cloudflare Dashboard → Overview |
| Cloudflare Proxy | Enable/disable orange-cloud CDN proxy |

### Alibaba Cloud DNS (International / China)

| Field | Description |
|-------|-------------|
| AccessKey ID | RAM user AccessKey ID with `AliyunDNSFullAccess` |
| AccessKey Secret | Corresponding secret |
| Root Domain | Root domain registered in AliDNS (e.g. `example.com`) |

> The subdomain prefix (RR) is derived automatically from Hostname − Root Domain.
> International uses endpoint `alidns.ap-southeast-1.aliyuncs.com`;
> China uses `alidns.aliyuncs.com`.

### Alibaba Cloud ESA (Edge Security Acceleration)

| Field | Description |
|-------|-------------|
| AccessKey ID | RAM user AccessKey ID with ESA DNS permissions |
| AccessKey Secret | Corresponding secret |
| ESA Site ID | Numeric Site ID from ESA Console → Sites |

### PowerDNS

| Field | Description |
|-------|-------------|
| API Server URL | Base URL of the PowerDNS HTTP API, e.g. `http://pdns.lan:8081` |
| API Key | Value of `api-key=` in `pdns.conf` |
| Server ID | PowerDNS server identifier, almost always `localhost` |
| Zone Name | Authoritative zone that contains the hostname (e.g. `example.com`) |

5. Click **Save**. The cron job will sync records within 5 minutes.
6. To sync immediately, re-open the rule and click **Force Update**.

---

## Status colours (portal & widget)

| Colour | Meaning |
|--------|---------|
| 🟢 Green | The DNS lookup for the hostname already contains this interface IP |
| 🔴 Red | The interface IP is **not** yet in DNS (update pending or failed) |

### Proxy-mode matching note

When a provider configuration intentionally hides origin IPs behind proxy/CDN
(for example, Cloudflare orange-cloud / proxied mode), recursive DNS answers can
return edge proxy IPs rather than your origin A/AAAA values. In those modes,
MWDDNS status matching uses provider API record lists (when available) to avoid
false “out of sync” indicators.

---

## Configuration storage

Rules are stored in pfSense's `/cf/conf/config.xml` under the `<mwddns>`
element. The `provider` field determines which module handles the sync.
The `record_types` field is space-separated (`A`, `AAAA`, or `A AAAA`).
Existing rules without these fields default to `cloudflare` and `A` respectively.

```xml
<mwddns>
  <!-- Cloudflare dual-stack example -->
  <rule>
    <provider>cloudflare</provider>
    <name>Home WAN – CF</name>
    <token><!-- Cloudflare API token --></token>
    <zone_id>0123456789abcdef0123456789abcdef</zone_id>
    <hostname>home.example.com</hostname>
    <ttl>300</ttl>
    <proxied>0</proxied>
    <record_types>A AAAA</record_types>
    <interfaces>wan opt1</interfaces>
  </rule>
  <!-- PowerDNS IPv6-only example -->
  <rule>
    <provider>powerdns</provider>
    <name>Home WAN – PDNS IPv6</name>
    <pdns_url>http://pdns.lan:8081</pdns_url>
    <pdns_api_key><!-- API key --></pdns_api_key>
    <pdns_server_id>localhost</pdns_server_id>
    <pdns_zone>example.com</pdns_zone>
    <hostname>home.example.com</hostname>
    <ttl>300</ttl>
    <record_types>AAAA</record_types>
    <interfaces>wan</interfaces>
  </rule>
</mwddns>
```

---

## Sync algorithm (all providers)

For each rule update cycle the dispatcher collects IPs grouped by record type
(`['A' => ['1.2.3.4' => true, …], 'AAAA' => ['2001:db8::1' => true, …]]`)
and then, for **each configured record type**:

1. Collect current addresses from all selected interfaces for that type.
2. Fetch existing records of that type from the DNS provider.
3. **Update** records whose address matches a current WAN address (keeps TTL/settings in sync).
4. **Create** new records for addresses that have no existing record.
5. **Delete** records whose address no longer appears on any monitored interface.

This ensures DNS always reflects exactly the current set of WAN addresses for
each type (A for IPv4, AAAA for IPv6) independently.

---

## Adding a new DNS provider

1. Create `src/usr/local/pkg/mwddns/<key>.php`.
2. Implement the three contract functions:
   - `mwddns_{key}_fields(): array` — field definitions for the edit UI
   - `mwddns_{key}_validate(array $post, array &$errors): bool` — validate provider-specific POST fields
   - `mwddns_{key}_update(array $ipsByType, array $rule): array` — perform sync, return `['ok', 'message', 'actions']`
     - `$ipsByType` shape: `['A' => ['1.2.3.4' => true, …], 'AAAA' => ['::1' => true, …]]`
     - Known-empty types are included as empty arrays so stale RRsets can be deleted. Types with uncertain monitoring are omitted entirely and MUST remain untouched.
     - The provider must loop over `$ipsByType` and handle each type independently.
3. Register the provider in `mwddns_get_providers()` inside `mwddns.inc`.
4. Add the new file to `install.sh`, `mwddns.xml`, and the reviewed-source allowlist in `.gitignore`.

---

## License

This project is licensed under the **Apache License 2.0** – see the [LICENSE](LICENSE) file for details.

### Attribution

The gateway watcher module (`mwddns_gateway_watcher.py`) is adapted from
**[psych0d0g/pfSense-MWAN-DDNS](https://github.com/psych0d0g/pfSense-MWAN-DDNS)**
(Apache License 2.0).

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for complete third-party attribution.

## Compatibility and safety repair (2026-09-08)

The compatibility changes below preserve existing features while making
configuration access and monitoring failures explicit.

* Configuration: prefer `config_read_file(false, false)`; its return value is
  boolean, not a configuration array. Use `parse_config(true)` only on older
  systems which lack the newer function. Stop on an unreadable configuration.
* Monitoring: PHP and Python connect to dpinger Unix stream sockets with
  bounded reads. Unreadable, missing or malformed monitoring is **unknown**,
  not **down**. Affected A or AAAA RRsets are preserved; a confirmed all-down
  family can still be cleared. Administratively disabled gateways/interfaces
  and explicitly unmonitored gateways are handled separately.
* Family selection: use the matching IPv4 or IPv6 gateway, including dynamically
  generated gateway definitions. Ambiguous gateway mappings are not guessed.
* Concurrency: saves, deletions and DNS updates share one operation lock. Forms
  carry a configuration revision and stale edits are rejected. Updates recheck
  their rule after reloading configuration. Competing requests ask for a retry.
* Runtime timestamps/status live in `/var/run/mwddns/metadata.json`, not in
  `config.xml`. Metadata writes use a lock and atomic replacement; entries are keyed by rule
  fingerprints so deletion/reordering cannot attach a result to a different rule.
* PowerDNS: choose **HTTP** or **HTTPS** with the connection-protocol selector.
  Existing rules derive their selection from the saved URL. The hostname, port,
  path and credentials are preserved. HTTP shows a clear unencrypted-transport
  warning; HTTPS verifies the certificate and hostname. No separate HTTP
  permission checkbox or automatic switch to HTTPS is required.
* Full backups: all provider credentials remain in pfSense configuration,
  including inactive-provider fields. Protect backups as secrets; this repair
  does not remove credentials or introduce machine-bound encryption.
* Installation and removal no longer suppress PHP failures or report success
  after a failed configuration write. An interrupted operation may require
  rerunning the installer after resolving the reported error.

Validate compatibility in an isolated pfSense VM with test DNS zones before
production rollout. Offline checks do not certify device behavior or establish
the cause of nginx/PHP-FPM HTTP 50x errors.

## 1.0.6 candidate follow-up

* Provider add/update failure preserves old records for the affected family;
  a successful family still reconciles normally and a confirmed-empty family
  still clears its records.
* Failed configuration writes are shown in the GUI, retain submitted inputs,
  and do not start a DNS update. Full backup data and inactive credentials remain.
* List/widget GET requests only read locally cached observations. Missing,
  failed or older-than-six-minute observations display as unknown, not red.
  CLI updates refresh actual provider/DNS observations; fresh installs can show
  pending status until the next five-minute cron run.
* Manual updates keep their immediate behavior but share a 20-second HTTP
  budget and release the browser session lock before external work. CLI rules
  use a 90-second HTTP budget. This bounds HTTP operations, not OS DNS resolver
  delays; resolver work is kept out of GUI requests.
* PHP 8.5's deprecated `curl_close()` calls were replaced with object release.
* ESA's API path is initialized in the scope used by the provider dispatcher.

On-device acceptance is still required; offline success alone is not a
production compatibility guarantee.
