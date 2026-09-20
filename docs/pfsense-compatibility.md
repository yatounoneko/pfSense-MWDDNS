# pfSense version compatibility

MWDDNS targets pfSense CE. One version is verified on real hardware; the others
are expected to work from source-level analysis but carry no device testing.

## Support matrix

| pfSense CE | Status | Configuration reader used |
|---|---|---|
| **2.9.0** | **Verified on hardware.** Current baseline. | `config_read_file()` |
| 2.8.x | Not device-tested. Takes the same primary code path as 2.9.0, so it is expected to work. | `config_read_file()` |
| 2.7.x | Not device-tested. Depends on the legacy fallback below. | `parse_config()` |

Earlier releases are unsupported: they provide neither API in a form the plugin
accepts.

## What 2.9.0 changed

For this plugin, 2.9.0 is a **removal, not an addition**. It deleted the legacy
`parse_config()` configuration reader and introduced no replacement call that
MWDDNS needs, because `config_read_file()` has existed since 2.8.0.

| Change in pfSense source | Landed in | Effect |
|---|---|---|
| `config_read_file()` introduced (`735b768`, 2024-08-08) | 2.8.0 | Explicit reader added |
| `parse_config()` reduced to a backwards-compatibility stub (`485fe02`, 2024-08-15) | 2.8.0 | Both readers available |
| `parse_config()` removed (`0e56ef4`, 2025-10-08) | 2.9.0 | Legacy reader gone |

So 2.8.x and 2.9.x expose the same reader, and only 2.7.x is limited to the old
one.

## How MWDDNS handles it

`mwddns_reload_config()` in `mwddns.inc`, and the equivalent PHP snippets in
`install.sh`, probe at runtime instead of testing a version string:

1. If `config_read_file()` exists, use it. This is the path on 2.8.x and 2.9.x.
2. Otherwise, if `parse_config()` exists, use it. This is the path on 2.7.x.
3. Otherwise abort, rather than operate on an empty configuration.

Both arguments are passed explicitly as `config_read_file(false, false)`, so
2.9.0 changing the `$use_cache` default from `false` to `true` does not alter
plugin behaviour.

Because step 1 is taken on both 2.8.x and 2.9.x, the code exercised by the
verified 2.9.0 installation is the same code that runs on 2.8.x. Step 2 is the
only path that no device-tested version reaches.

## Every other pfSense function the plugin calls

All of them are present in 2.9.x. Those whose availability varies across
versions are probed with `function_exists()` before use.

| Function | Probed before use |
|---|---|
| `write_config`, `install_cron_job`, `mwexec` | No: present in every supported version |
| `get_interface_ip`, `get_interface_ipv6`, `get_configured_interface_list` | No: present in every supported version |
| `get_real_interface`, `convert_real_interface_to_friendly_interface_name`, `return_gateways_array` | Yes |
| `isAdminUID`, `getUserEntry`, `userHasPrivilege` | Yes |
| `config_read_file`, `parse_config` | Yes |

## Limits of this statement

- Only 2.9.0 has been exercised on a real firewall. The 2.7.x and 2.8.x rows rest on source-level analysis and the runtime fallback, not on testing.
- A matching function name is not proof of unchanged behaviour. A signature or semantic change inside a function that still exists would not be caught by the check above.
- 2.9.0 also moves to PHP 8.4 and migrates `config.xml` entity encoding from `ENT_HTML401` to `ENT_XML1`. MWDDNS never parses `config.xml` itself; it reads and writes only through the pfSense configuration API.
- The 2.7.x fallback path has no device coverage at all. Treat 2.7.x as best-effort.
