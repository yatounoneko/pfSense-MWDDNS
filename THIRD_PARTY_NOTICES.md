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

- Refactored into an abstract `BasePlatform` / `PfSensePlatform` class hierarchy
  to support testing and future portability
- Replaced direct file I/O with a `DpingerReader` abstraction over dpinger sockets
- Integrated with the MWDDNS update pipeline (`mwddns_cron.php`) instead of the
  upstream PowerDNS-specific update flow
- Extended exception handling, structured logging, and command-line argument support
- All PHP-based hook scripts replaced by this standalone Python daemon

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
