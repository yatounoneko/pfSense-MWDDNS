# pfSense-MWDDNS
pfSense Multi-WAN DDNS Plugin

A pfSense package (PHP, no extra dependencies) that monitors **multiple WAN
interfaces** and keeps DNS A/AAAA records in sync automatically across multiple
DNS providers.

---

## Features

| # | Feature |
|---|---------|
| 1 | Per-rule configuration: **Name**, **Hostname**, **TTL**, **Interfaces**, **Record Types** (A / AAAA / both) plus provider-specific fields |
| 2 | Each rule can watch **multiple WAN interfaces** simultaneously; one A/AAAA record is maintained per interface address |
| 3 | **IPv6/AAAA support** – select A, AAAA, or both per rule; interfaces without the requested address type are silently skipped |
| 4 | **Pluggable DNS providers** – Cloudflare, Alibaba Cloud DNS (International), Alibaba Cloud DNS (China), Alibaba Cloud ESA, PowerDNS |
| 5 | **Portal / status page** (`Services → Multi-WAN DDNS`) shows custom name, provider, hostname, per-interface IPv4/IPv6 with colour indicators: 🟢 green = DNS matches, 🔴 red = DNS mismatch |
| 6 | **Dashboard widget** with the same colour-coded status |
| 7 | **Force Update** button on every rule's edit page for instant sync |
| 8 | Cron job runs every 5 minutes in the background |
| 9 | Written in **PHP 8 + shell** – runs on pfSense 2.7/2.8 with zero extra dependencies |
| 10 | Provider-aware status matching for proxy/CDN modes (see Proxy-mode matching note) |

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

* pfSense CE 2.7.x / 2.8.x (FreeBSD 14, PHP 8.x)
* Credentials/API access for **at least one supported DNS provider**:
  * Cloudflare: API Token + Zone ID
  * Alibaba Cloud DNS (intl/CN): AccessKey ID + AccessKey Secret + Root Domain
  * Alibaba Cloud ESA: AccessKey ID + AccessKey Secret + Site ID
  * PowerDNS: API URL + API Key + Server ID + Zone Name

---

## Installation

### Option A – Manual (SSH into pfSense)

> pfSense 2.8.1 does **not** include `git` by default. Use this upload-based flow.

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
    <last_updated>2024-01-01 00:00:00</last_updated>
    <last_status>OK</last_status>
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
    <last_updated>2024-01-01 00:00:00</last_updated>
    <last_status>OK</last_status>
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
     - Only types with at least one available address are included as keys.
     - The provider must loop over `$ipsByType` and handle each type independently.
3. Register the provider in `mwddns_get_providers()` inside `mwddns.inc`.
4. Add the new file to `install.sh` and `mwddns.xml`.
