# pfSense version compatibility

MWDDNS requires pfSense CE 2.8.0 or later. One version is verified on real
hardware; 2.8.x is expected to work from source-level analysis.

## Support matrix

| pfSense CE | Status |
|---|---|
| **2.9.0** | **Verified on hardware.** Current baseline. |
| 2.8.x | Not device-tested. Takes the same code path as 2.9.0, so it is expected to work. |
| 2.7.x and earlier | **Not supported.** The installer refuses to run and changes nothing. |

## What 2.9.0 changed

For this plugin, 2.9.0 is a **removal, not an addition**. It deleted the legacy
`parse_config()` configuration reader and introduced no replacement call that
MWDDNS needs, because `config_read_file()` has existed since 2.8.0.

| Change in pfSense source | Landed in | Effect |
|---|---|---|
| `config_read_file()` introduced (`735b768`, 2024-08-08) | 2.8.0 | Explicit reader added |
| `parse_config()` reduced to a backwards-compatibility stub (`485fe02`, 2024-08-15) | 2.8.0 | Both readers available |
| `parse_config()` removed (`0e56ef4`, 2025-10-08) | 2.9.0 | Legacy reader gone |

2.8.x and 2.9.x therefore expose the same reader. 2.7.x has only the removed
one, which is why support starts at 2.8.0.

## How MWDDNS reads the configuration

Every configuration reload calls `config_read_file(false, false)`: the
`mwddns_reload_config()` function in `mwddns.inc`, the WebGUI upgrade helper,
and the PHP snippets in `install.sh`. If the function is missing they abort
rather than operate on an empty configuration.

`install.sh` checks for `config_read_file()` before it copies or removes any
file, so an install or uninstall on 2.7.x stops with nothing changed.

Both arguments are passed explicitly, so 2.9.0 changing the `$use_cache` default
from `false` to `true` does not alter plugin behaviour. Because 2.8.x and 2.9.x
take the same path, the code exercised by the verified 2.9.0 installation is the
same code that runs on 2.8.x.

## Existing 2.7.x installations

Releases up to 1.1.2 carried an untested `parse_config()` fallback; later
releases removed it.

- **To keep using MWDDNS,** upgrade pfSense to 2.8.0 or later first, then upgrade MWDDNS. A WebGUI upgrade attempted on 2.7.x fails, and the newer installer refuses to run.
- **To remove MWDDNS,** run `sh install.sh --uninstall` from the MWDDNS release that is installed, not from a newer one.

## Every other pfSense function the plugin calls

All of them are present in 2.9.x. Those whose availability varies across
versions are probed with `function_exists()` before use.

| Function | Probed before use |
|---|---|
| `write_config`, `install_cron_job`, `mwexec` | No: present in every supported version |
| `get_interface_ip`, `get_interface_ipv6`, `get_configured_interface_list` | No: present in every supported version |
| `get_real_interface`, `convert_real_interface_to_friendly_interface_name`, `return_gateways_array` | Yes |
| `isAdminUID`, `getUserEntry`, `userHasPrivilege` | Yes |
| `config_read_file` | Yes; the installer checks it before changing anything |

## Limits of this statement

- Only 2.9.0 has been exercised on a real firewall. The 2.8.x row rests on source-level analysis, not on testing.
- A matching function name is not proof of unchanged behaviour. A signature or semantic change inside a function that still exists would not be caught by the check above.
- 2.9.0 also moves to PHP 8.5.7 and migrates `config.xml` entity encoding from `ENT_HTML401` to `ENT_XML1`. MWDDNS never parses `config.xml` itself; it reads and writes only through the pfSense configuration API.
