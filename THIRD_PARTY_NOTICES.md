# Third-Party Code Attribution

## Gateway Watcher Module

**Original Project:** psych0d0g/pfSense-MWAN-DDNS  
**Repository:** https://github.com/psych0d0g/pfSense-MWAN-DDNS  
**License:** Apache License 2.0

### Files

- `src/usr/local/bin/mwddns_gateway_watcher.py`

### Modification Notes

The gateway watcher module (`mwddns_gateway_watcher.py`) is adapted from the
`gateway_watcher.py` module in the upstream project. Significant changes include:

- Adapted for this project's MWDDNS gateway-monitoring workflow
- Uses the current watcher implementation to read dpinger status data and detect
  gateway state changes
- Integrated with the MWDDNS update pipeline (`mwddns_cron.php`) instead of the
  upstream PowerDNS-specific update flow
- Extended exception handling, structured logging, and command-line argument support
- Reworked the upstream hook/update flow so the Python watcher drives updates while
  still invoking the PHP-based MWDDNS updater

### License Terms

This project incorporates code adapted from psych0d0g/pfSense-MWAN-DDNS, which is
licensed under the Apache License 2.0.

**You may:**
- Use, modify, and distribute this code
- Use this code in commercial products

**You must:**
- Include a copy of the Apache License 2.0 (see [LICENSE](LICENSE) file)
- Retain all original copyright notices and attributions
- State significant changes made to the files
- Include this THIRD_PARTY_NOTICES.md file in distributions

**Full License:** Apache License 2.0  
See [LICENSE](LICENSE) in the root directory for complete terms.
