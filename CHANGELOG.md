# Changelog

Release notes and maintenance history for pfSense-MWDDNS.
See [README.md](README.md) for installation, usage and current operational guidance.

## 1.1.1 release

- The upgrade page can check GitHub's latest stable release, download its exact
  versioned upgrade ZIP, and pass it through the existing confirmation/install
  flow. Checking and downloading never install automatically. No cron check
  or background auto-update has been added.
- GitHub requests run in a bounded worker with verified HTTPS, fixed repository
  and redirect-host restrictions, no credentials/proxies, size/time limits and
  pinned release/asset identity. The downloaded SHA256 must match GitHub's
  asset digest; all existing manifest, file and newer-version checks still apply.
  These integrity checks are not a digital publisher signature.
- Three retained jobs and one provisional check/upload are permitted. Previous
  jobs are pruned only after a newer ZIP passes validation. If a provisional
  check/download fails, discard that job before retrying when all slots are full.
  Active/interrupted/recovery-required jobs and persistent backups are protected.
- PHP-FPM opcode invalidation is recorded once per completed upgrade rather than
  repeated on every status/history read.
- First install 1.1.1 using the existing manual upload/install route. Its new
  online flow can install subsequent newer releases; equal/older versions remain
  rejected. Network failure leaves manual upload available.

## 1.1.0 release

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

## 1.0.18 maintenance update

- Prevent collector deadlines from being swallowed as recoverable log I/O errors.
- Retain bounded, privacy-safe progress and failure codes with elapsed/CPU timings.
- Add failure diagnostic downloads and live progress to the existing Debug page.
- Distinguish an explicitly recorded failure from an unconfirmed stale status;
  keep worker locks to protect active jobs during removal and new collection.
- Preserve existing collection limits, DNS behavior and saved configuration.

## 1.0.17 maintenance update

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

## 1.0.16 maintenance update

- Align the edit and delete controls in a shared flex row with matching 18px
  native icons and equal-height transparent controls. Existing delete
  confirmation, POST, revision and CSRF checks are unchanged.
- Start the Cloudflare token storage warning on a separate line, retaining
  its translated text and warning emphasis.
- The version increment allows testing the normal data-preserving upgrade
  from 1.0.15. DNS update behavior and upload/report retention are unchanged.

## 1.0.15 maintenance update

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

## 1.0.14 maintenance update

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

## 1.0.13 maintenance update

- Let busy Debug sources borrow unused scan time and candidate capacity while
  preserving reservations for unvisited sources and all existing process limits.
- Keep the 5,000-group final output and 6 MiB report caps; do not merge DHCP WAN
  or PID identities. Existing five-minute request histograms remain available.
- Explain limit reasons and per-stage dropped counts in English, Traditional
  Chinese and Simplified Chinese, with actual scan time and requested-window bounds.
- Upgrade using the existing WebGUI ZIP upload with data preservation selected,
  or the original installer without uninstalling. Rules and credentials remain
  unchanged. A 14-day request is still not a guarantee of 14-day retained logs.

## 1.0.12 maintenance update

- Show **Discard temporary upload (keep backup)** for jobs whose status file is
  missing or malformed. The action still requires an authenticated administrator,
  a valid POST/CSRF token and the existing worker lock/path checks.
- Checking, queued and running jobs remain protected. Cleanup affects temporary
  upload files only, never the persistent upgrade backup.
- Existing 1.0.10/1.0.11 installations can upload the versioned 1.0.12 release ZIP.
  If an older installation already has all three slots blocked by unreadable
  jobs, use the original manual installation flow without uninstalling; the
  newer cleanup page is available only after that installation completes.

## 1.0.11 maintenance update

- Treat both `false` and `-1` configuration-write results as failures during
  rule/Debug saves and installer registration/removal.
- Clean incomplete uploads before starting a worker. Discarding an abandoned
  upload no longer requires a readable status file; worker locking, temporary
  path restrictions and persistent backups are unchanged.
- An existing 1.0.10 installation can upload the versioned 1.0.11 release ZIP
  through the upgrade page. Keep **Preserve data** selected for a normal update.

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
