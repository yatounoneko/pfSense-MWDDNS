# pfSense-MWDDNS

**Multi-WAN Dynamic DNS for pfSense.** Monitors multiple WAN interfaces and
keeps DNS A/AAAA records in sync automatically across several DNS providers.

The native pfSense DDNS client cannot publish multiple A/AAAA records for the
same hostname at once. MWDDNS solves that: each rule watches as many WAN
interfaces as you like and maintains one record per interface address. It runs
independently of the built-in DDNS service.

Current version: **1.1.2** &nbsp;•&nbsp; License: **Apache-2.0** &nbsp;•&nbsp;
[Changelog](CHANGELOG.md)

**Dashboard widget**

<img width="auto" height="150" alt="Dashboard widget" src="https://github.com/user-attachments/assets/fc0b71f2-c7f2-4889-b89c-3705e9a2acca" />

**Portal / status page**

<img width="800" height="auto" alt="Portal status page" src="https://github.com/user-attachments/assets/73700895-9a3c-48ed-b622-b094f6b5ebb9" />

**Rule configuration**

<img width="800" height="auto" alt="Rule configuration page" src="https://github.com/user-attachments/assets/b8efbede-9f06-4c27-941d-2a5e1cb238cd" />

---

## Contents

- [Features](#features)
- [Supported DNS providers](#supported-dns-providers)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Status colours](#status-colours)
- [Upgrading](#upgrading)
- [Debug information](#debug-information)
- [Reference](#reference)
- [License](#license)

---

## Features

- **Multi-WAN by design.** Each rule watches multiple WAN interfaces at once and maintains one A/AAAA record per interface address.
- **Dual stack.** Choose A, AAAA or both per rule. Interfaces without the requested address type are silently skipped.
- **Pluggable providers.** Cloudflare, Alibaba Cloud DNS (International and China), Alibaba Cloud ESA, PowerDNS.
- **Per-rule configuration.** Name, hostname, TTL, interfaces and record types, plus provider-specific fields.
- **Portal / status page** at *Services > Multi-WAN DDNS*, showing name, provider, hostname and per-interface IPv4/IPv6 with colour indicators.
- **Dashboard widget** ("Multi-WAN DDNS") with the same colour-coded status.
- **Force Update** button on every rule's edit page for an instant sync.
- **Background cron job** every 5 minutes, plus a gateway watcher that reacts to WAN address changes.
- **Proxy-aware status matching** for CDN/proxy modes, so proxied records are not reported as out of sync.
- **WebGUI upgrades** from an uploaded release ZIP or a verified GitHub release.
- **Privacy-preserving Debug reports** with structured, bounded diagnostics and no raw log export.
- Written in **PHP 8 + Python 3.11 + shell**.

Localized GUI strings are available in Simplified Chinese (`zh_CN`) and
Traditional Chinese (`zh_HK` / `zh_TW`).

---

## Supported DNS providers

| Provider key | Description | Authentication |
|---|---|---|
| `cloudflare` | Cloudflare (global) | Bearer API token |
| `alidns_intl` | Alibaba Cloud DNS, International (`ap-southeast-1`) | AccessKey + HMAC-SHA1 V1 |
| `alidns_cn` | Alibaba Cloud DNS, China mainland | AccessKey + HMAC-SHA1 V1 |
| `aliesa` | Alibaba Cloud ESA (Edge Security Acceleration) | AccessKey + ACS4-HMAC-SHA256 V4 |
| `powerdns` | PowerDNS Authoritative Server (self-hosted) | `X-API-Key` header |

---

## Requirements

- **pfSense CE.** 2.8.1 is the user-reported operational baseline. The 2.9.0 upgrade exposed a removed configuration API; this tree contains source-level compatibility fixes, **not completed on-device certification**. Older-version fallbacks remain, but 2.7.x and 2.9.x must not be read as universally tested.
- **Python 3.11**, installed as the pfSense `python311` package.
- **Credentials for at least one supported provider:**

| Provider | Needed |
|---|---|
| Cloudflare | API token + Zone ID |
| Alibaba Cloud DNS (intl / CN) | AccessKey ID + AccessKey Secret + root domain |
| Alibaba Cloud ESA | AccessKey ID + AccessKey Secret + Site ID |
| PowerDNS | API URL + API key + server ID + zone name |

---

## Installation

### 1. Install Python 3.11

> Skip this only if `/usr/local/bin/python3.11` already exists. A different
> Python version or a `python3` alias is not equivalent. Use the repository
> configured by pfSense; do not add a generic FreeBSD package repository.

```sh
pkg install python311
python3.11 --version   # verify
```

### 2. Install the plugin over SSH

On pfSense 2.8.1 you must first enable **System > Advanced > Secure Shell**.

Connect from any terminal, replacing the address (and port, if customized):

```sh
ssh admin@192.168.0.1
ssh admin@192.168.0.1 -p 6666
```

The pfSense console menu appears after login:

```text
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
```

Choose **8) Shell**, then upload the release ZIP through the WebGUI first
(for example *Diagnostics > Command Prompt > Upload File*) and run:

```sh
unzip /tmp/pfSense-MWDDNS-(version).zip
cd pfSense-MWDDNS-(version)/
sh install.sh
```

Other installer options:

```sh
sh install.sh --help
sh install.sh --uninstall                # remove, keep config.xml settings
sh install.sh --uninstall --purge-config # remove and purge config.xml settings
```

### 3. Package Manager (future)

Once packaged as a proper FreeBSD `.pkg`, the plugin will be installable from
**System > Package Manager > Available Packages**.

---

## Usage

1. Go to **Services > Multi-WAN DDNS** and click **Add**.
2. Fill in the common fields:

| Field | Description |
|---|---|
| Rule Name | Friendly label shown in the portal |
| Hostname | FQDN to update, e.g. `home.example.com` |
| TTL | Seconds (1 = auto, 60-86400; AliDNS minimum is 600) |
| Interfaces | Hold Ctrl/Cmd to select multiple WAN interfaces |
| Record Types | **A** (IPv4), **AAAA** (IPv6) or both. At least one is required. |

3. Select the **DNS Provider** and complete its fields (below).
4. Click **Save**. The cron job syncs records within 5 minutes.
5. To sync immediately, re-open the rule and click **Force Update**.

### Cloudflare

| Field | Description |
|---|---|
| API Token | Bearer token with *Zone > DNS > Edit* permission |
| Zone ID | 32-character hex value from Cloudflare Dashboard > Overview |
| Cloudflare Proxy | Enable or disable the orange-cloud CDN proxy |

### Alibaba Cloud DNS (International / China)

| Field | Description |
|---|---|
| AccessKey ID | RAM user AccessKey ID with `AliyunDNSFullAccess` |
| AccessKey Secret | The corresponding secret |
| Root Domain | Root domain registered in AliDNS, e.g. `example.com` |

> The subdomain prefix (RR) is derived automatically from hostname minus root
> domain. International uses endpoint `alidns.ap-southeast-1.aliyuncs.com`;
> China uses `alidns.aliyuncs.com`.

### Alibaba Cloud ESA

| Field | Description |
|---|---|
| AccessKey ID | RAM user AccessKey ID with ESA DNS permissions |
| AccessKey Secret | The corresponding secret |
| ESA Site ID | Numeric site ID from ESA Console > Sites |

### PowerDNS

| Field | Description |
|---|---|
| API Server URL | Base URL of the PowerDNS HTTP API, e.g. `http://pdns.lan:8081` |
| API Key | Value of `api-key=` in `pdns.conf` |
| Server ID | PowerDNS server identifier, almost always `localhost` |
| Zone Name | Authoritative zone containing the hostname, e.g. `example.com` |

---

## Status colours

Used on both the portal page and the dashboard widget.

| Colour | Meaning |
|---|---|
| Green | The DNS lookup for the hostname already contains this interface IP |
| Red | The interface IP is **not** yet in DNS: update pending or failed |

**Proxy-mode matching.** When a provider configuration intentionally hides
origin IPs behind a proxy or CDN (for example Cloudflare orange-cloud mode),
recursive DNS answers return edge proxy IPs rather than your origin A/AAAA
values. In those modes MWDDNS matches status against the provider's API record
list, when available, to avoid false "out of sync" indicators.

---

## Upgrading

Upgrades preserve existing rules, credentials and Debug preferences. **Do not
uninstall first.**

- **Over SSH:** repeat the `sh install.sh` flow with the newer release.
- **From the WebGUI** (1.0.10 and later): open **Services > Multi-WAN DDNS > Plugin upgrade**.

The upgrade page accepts a release in two ways:

1. **Upload a release ZIP,** wait for validation, choose a mode, then click **Upgrade now**.
2. **Check GitHub** for the latest stable release and download its exact versioned ZIP. Checking and downloading never install automatically, and no scheduled check or background auto-update exists. Requests use verified HTTPS with a fixed repository, redirect-host restrictions, no credentials or proxies, size and time limits, and a SHA256 that must match GitHub's asset digest.

Only numeric `major.minor.patch` release ZIPs with a release manifest are
accepted, not GitHub source-code archives. Equal or older versions are rejected
and there is no bypass switch. The ZIP limit is 8 MiB, and the WebGUI/PHP upload
limit may be lower.

### Data modes

**Preserve data** is the default. **Reset data** requires typing `CLEAR MWDDNS`
and removes only MWDDNS rules, provider credentials, preferences, cache/status
and Debug data, after a backup. Other pfSense settings and existing records at
the DNS provider are not deliberately cleared.

### Backups and temporary files

Before either mode, private backups of plugin configuration, existing
application files and runtime data are written under
`/conf/mwddns-backups/upgrade-ID` (directories `0700`, files `0600`).

> These backups contain credentials and survive reset and reboot. **Do not share
> them.** They are never deleted automatically; remove old backups only after
> acceptance and your own retention decision.

Uploads, extracted files and status live under `/tmp/mwddns-upgrade` and are
lost on reboot. At most three temporary uploads are kept; use **Discard
temporary upload** to free a slot without deleting its backup.

### Access control

The page requires UID-0 administrator or effective `page-all` privilege without
read-only restrictions. A delegated MWDDNS page privilege alone is insufficient.
pfSense authentication, CSRF protection and the plugin form token remain
enabled.

### Trust and failure handling

> **Only install trusted releases.** The installed worker validates archive
> paths, file types, counts and sizes, the manifest SHA256 and matching version
> fields before executing the ZIP's installer as root. The manifest is integrity
> metadata, **not a digital signature or proof of publisher identity**. Confirm
> the source and compare the displayed archive SHA256 against an independently
> trusted checksum.

Installation runs in a background process, serializes MWDDNS operations and
verifies the installed files, version and watcher. It does not restart PHP-FPM
or nginx. Failure triggers a best-effort rollback of backed-up MWDDNS files and
configuration; unrelated effects of an arbitrary trusted installer cannot be
rolled back.

Do not reboot or make concurrent pfSense configuration changes during
installation: the official configuration writer serializes file replacement, not
the entire read-modify-write transaction across all system writers. Power loss
or a reboot can interrupt installation before rollback and require manual
recovery from the persistent backup and a known-good release. Offline fixtures
are not a device upgrade or power-loss-recovery certification.

---

## Debug information

**Services > Multi-WAN DDNS > Debug information** collects bounded, structured
diagnostics from logs that already exist on the firewall. Choose a window
(default 3 days, range 1-14) and the sources to include, then click **Save and
collect**. It reads existing logs only: it does not record future activity,
change DNS, restart services or upload anything.

Exports are structured diagnostics, not raw messages with a best-effort scrub.
Only fixed event categories, validated dates and numbers, known program and
function names, and opaque aliases (`WAN_1`, `IP4_2`, …) leave the collector.
Arbitrary text, usernames, domain names, credentials and configuration are never
exported, and there is no raw download switch. The private interface-name legend
appears only on the authenticated page; do not share screenshots of it.

Reports are root-private runtime files under `/tmp/mwddns-debug`. They expire
for download after 24 hours, at most three jobs are retained, and preview is
limited to 128 KiB. Use **Download sanitized report** for the full JSON.

Collection is bounded by wall-clock, CPU, memory, scan-byte and output limits,
so a long window may be partial. Check `partial`, source warnings, dropped
counts and coverage timestamps before drawing conclusions.

> Full reference, including the privacy model, resource limits, event allocation
> and the `mwddns-debug-v2` schema: **[docs/debug-information.md](docs/debug-information.md)**.

---

## Reference

### Configuration storage

Rules live in pfSense's `/cf/conf/config.xml` under the `<mwddns>` element. The
`provider` field selects the module that handles the sync. The `record_types`
field is space-separated (`A`, `AAAA` or `A AAAA`). Existing rules without those
fields default to `cloudflare` and `A` respectively.

```xml
<mwddns>
  <!-- Cloudflare dual-stack example -->
  <rule>
    <provider>cloudflare</provider>
    <name>Home WAN - CF</name>
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
    <name>Home WAN - PDNS IPv6</name>
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

### Sync algorithm

For each update cycle the dispatcher collects IPs grouped by record type
(`['A' => ['1.2.3.4' => true, …], 'AAAA' => ['2001:db8::1' => true, …]]`), then
for **each configured record type**:

1. Collect current addresses from all selected interfaces for that type.
2. Fetch existing records of that type from the DNS provider.
3. **Update** records whose address matches a current WAN address, keeping TTL and settings in sync.
4. **Create** records for addresses that have none.
5. **Delete** records whose address no longer appears on any monitored interface.

DNS therefore reflects exactly the current set of WAN addresses for each type,
with A and AAAA handled independently.

### Source tree

```text
src/usr/local/
├── pkg/
│   ├── mwddns.inc                    # Core library: config, interface IPs, DNS status, provider dispatch, cron
│   ├── mwddns.xml                    # pfSense package definition: menu, privileges, installed files
│   └── mwddns/
│       ├── cloudflare.php            # Cloudflare provider
│       ├── alidns.php                # Alibaba Cloud DNS (intl + CN)
│       ├── aliesa.php                # Alibaba Cloud ESA
│       ├── powerdns.php              # PowerDNS HTTP API
│       ├── debug.inc                 # Debug job settings, storage and retention
│       ├── upgrade.inc               # Upgrade job state, privilege checks, upload limits
│       └── locale/
│           ├── zh_CN.php             # Simplified Chinese
│           └── zh_HK.php             # Traditional Chinese (HK terminology)
├── www/
│   ├── mwddns.php                    # Rules list / portal status page
│   ├── mwddns_edit.php               # Add / edit rule, incl. Force Update
│   ├── mwddns_debug.php              # Debug information page
│   ├── mwddns_upgrade.php            # Plugin upgrade page
│   └── widgets/widgets/
│       └── mwddns.widget.php         # Dashboard widget
├── bin/
│   ├── mwddns_cron.php               # Periodic cron runner (every 5 minutes)
│   ├── mwddns_gateway_watcher.py     # Gateway / WAN address change watcher
│   ├── mwddns_debug.py               # Bounded, privacy-preserving diagnostics collector
│   ├── mwddns_debug_snapshot.php     # Private collector context, anonymous pipe only
│   ├── mwddns_upgrade.py             # Upgrade worker: validation, install, rollback
│   └── mwddns_upgrade_config.php     # MWDDNS config subtree backup / restore helper
└── etc/rc.d/
    └── mwddns_watcher                # rc script for the gateway watcher daemon

install.sh                            # Manual install / uninstall helper
```

### Adding a new DNS provider

1. Create `src/usr/local/pkg/mwddns/<key>.php`.
2. Implement the three contract functions:
   - `mwddns_{key}_fields(): array` — field definitions for the edit UI.
   - `mwddns_{key}_validate(array $post, array &$errors): bool` — validate provider-specific POST fields.
   - `mwddns_{key}_update(array $ipsByType, array $rule): array` — perform the sync and return `['ok', 'message', 'actions']`.
3. Register the provider in `mwddns_get_providers()` inside `mwddns.inc`.
4. Add the new file to `install.sh`, `mwddns.xml`, and the reviewed-source allowlist in `.gitignore`.

`$ipsByType` has the shape `['A' => ['1.2.3.4' => true, …], 'AAAA' => ['::1' => true, …]]`.
Known-empty types are included as empty arrays so stale RRsets can be deleted.
Types with uncertain monitoring are omitted entirely and **must remain
untouched**. The provider must loop over `$ipsByType` and handle each type
independently.

---

## License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).

The gateway watcher module (`mwddns_gateway_watcher.py`) is adapted from
[psych0d0g/pfSense-MWAN-DDNS](https://github.com/psych0d0g/pfSense-MWAN-DDNS)
(Apache License 2.0). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for
complete third-party attribution.
