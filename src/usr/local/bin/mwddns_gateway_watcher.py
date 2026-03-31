#!/usr/local/bin/python3
"""
mwddns_gateway_watcher.py – Poll gateway state and trigger MWDDNS updates

This watcher mirrors the flow of
https://raw.githubusercontent.com/yatounoneko/pfSense-MWAN-DDNS/refs/heads/main/gateway_watcher.py:
it polls dpinger sockets, applies per-gateway thresholds from config.xml, and
invokes the updater whenever a state change is detected. This ensures stale IPs
are purged even when link/rc scripts are not triggered (e.g. cable unplug).
"""

import argparse
import glob
import os
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Dict, Optional

MWDDNS_CRON_PATH = "/usr/local/bin/mwddns_cron.php"
PHP_BIN = "/usr/local/bin/php"
POLL_INTERVAL_SECONDS = 5


class PfSensePlatform:
    """pfSense-specific helpers for gateway config and state."""

    def load_gateways(self) -> Dict[str, dict]:
        """
        Parse /conf/config.xml for gateway thresholds and interface mapping.
        Returns: { gateway_name: { 'interface': 'wan', 'latencyhigh': 500, 'losshigh': 20 } }
        """
        gateways = {}
        defaults = {"latencyhigh": 500, "losshigh": 20}
        try:
            tree = ET.parse("/conf/config.xml")
            root = tree.getroot()
            gw_cfg = root.find(".//gateways")
            if gw_cfg is not None:
                defaults["latencyhigh"] = int(gw_cfg.findtext("latencyhigh", defaults["latencyhigh"]))
                defaults["losshigh"] = int(gw_cfg.findtext("losshigh", defaults["losshigh"]))

            for gw_item in root.findall(".//gateways/gateway_item"):
                name = (gw_item.findtext("name") or "").strip()
                if not name:
                    continue
                gateways[name] = {
                    "interface": (gw_item.findtext("interface") or "").strip(),
                    "latencyhigh": int(gw_item.findtext("latencyhigh", defaults["latencyhigh"])),
                    "losshigh": int(gw_item.findtext("losshigh", defaults["losshigh"])),
                }
        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"[{time.ctime()}] WATCHER ERROR: Failed to parse gateway config: {exc}")
        return gateways

    def get_gateway_statuses(self, gateways: Dict[str, dict]) -> Dict[str, dict]:
        """
        Inspect dpinger sockets and return per-gateway status.
        Format: { gateway_name: { 'status': 'online'|'down', 'interface': 'wan' } }
        """
        statuses: Dict[str, dict] = {}
        try:
            for socket_path in glob.glob("/var/run/dpinger_*.sock"):
                basename = os.path.basename(socket_path)
                try:
                    gateway_name = basename.replace("dpinger_", "", 1).split("~", 1)[0]
                except Exception:
                    continue

                gw_cfg = gateways.get(gateway_name, {})
                latency_high_ms = int(gw_cfg.get("latencyhigh", 500))
                loss_high_pct = int(gw_cfg.get("losshigh", 20))

                status = "down"
                try:
                    result = subprocess.run(["cat", socket_path], capture_output=True, text=True, timeout=2)
                    output = result.stdout.strip()
                    parts = output.split()
                    if len(parts) >= 4:
                        live_latency_us = int(parts[1])
                        live_loss_pct = int(parts[3])
                        if (live_latency_us / 1000) < latency_high_ms and live_loss_pct < loss_high_pct:
                            status = "online"
                except Exception:
                    status = "down"

                statuses[gateway_name] = {"status": status, "interface": gw_cfg.get("interface", "")}
        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"[{time.ctime()}] WATCHER ERROR: Could not read dpinger sockets: {exc}")
        return statuses


class GatewayWatcher:
    def __init__(self, platform: PfSensePlatform, poll_interval: int = POLL_INTERVAL_SECONDS):
        self.platform = platform
        self.poll_interval = poll_interval
        self.previous_statuses: Dict[str, dict] = {}

    def run_updater(self, interfaces: Optional[set]) -> None:
        """
        Trigger mwddns_cron.php. If interfaces are provided, run once per
        interface so only affected rules are refreshed; otherwise run globally.
        """
        if not os.path.exists(MWDDNS_CRON_PATH):
            print(f"[{time.ctime()}] WATCHER WARNING: {MWDDNS_CRON_PATH} not found; skip update.")
            return

        targets = sorted(iface for iface in (interfaces or set()) if iface)
        if not targets:
            targets = [None]

        for iface in targets:
            args = [PHP_BIN, MWDDNS_CRON_PATH]
            if iface:
                args.append(iface)
            try:
                subprocess.run(args, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if iface:
                    print(f"[{time.ctime()}] Triggered MWDDNS update for interface '{iface}'.")
                else:
                    print(f"[{time.ctime()}] Triggered MWDDNS global update.")
            except Exception as exc:  # pragma: no cover - defensive logging
                print(f"[{time.ctime()}] WATCHER ERROR: Failed to run updater ({iface or 'all'}): {exc}")

    def start(self) -> None:
        gateways = self.platform.load_gateways()
        self.previous_statuses = self.platform.get_gateway_statuses(gateways)
        print(f"[{time.ctime()}] MWDDNS gateway watcher started. Poll every {self.poll_interval}s.")
        print(f"[{time.ctime()}] Initial gateways: {gateways}")
        print(f"[{time.ctime()}] Initial statuses: {self.previous_statuses}")

        while True:
            time.sleep(self.poll_interval)
            gateways = self.platform.load_gateways()
            current_statuses = self.platform.get_gateway_statuses(gateways)
            if current_statuses and current_statuses != self.previous_statuses:
                changed_ifaces = {
                    entry.get("interface", "")
                    for entry in current_statuses.values()
                }.union(
                    {entry.get("interface", "") for entry in self.previous_statuses.values()}
                )
                print(f"[{time.ctime()}] Gateway status change detected.")
                print(f"    Old: {self.previous_statuses}")
                print(f"    New: {current_statuses}")
                self.run_updater(changed_ifaces)
                self.previous_statuses = current_statuses


def main() -> None:
    parser = argparse.ArgumentParser(description="pfSense MWDDNS gateway watcher")
    parser.add_argument(
        "--interval",
        type=int,
        default=POLL_INTERVAL_SECONDS,
        help=f"Polling interval in seconds (default: {POLL_INTERVAL_SECONDS})",
    )
    args = parser.parse_args()

    watcher = GatewayWatcher(PfSensePlatform(), poll_interval=max(1, args.interval))
    watcher.start()


if __name__ == "__main__":
    main()
