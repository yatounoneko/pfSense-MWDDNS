#!/usr/local/bin/python3.11
"""
mwddns_gateway_watcher.py – Gateway/Interface health watcher for MWDDNS

Implements the same detection flow as
https://raw.githubusercontent.com/yatounoneko/pfSense-MWAN-DDNS/refs/heads/main/gateway_watcher.py:
  * Read per-gateway thresholds from /conf/config.xml
  * Poll dpinger socket outputs for latency/loss
  * Track state transitions and trigger updater on change
Detection and triggering are handled entirely in Python; legacy PHP-based hook
scripts have been removed.
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


class BasePlatform:
    """Abstract platform interface (mirrors reference gateway_watcher)."""

    def get_gateway_monitoring_thresholds(self) -> Dict[str, Dict[str, int]]:
        raise NotImplementedError

    def get_gateway_statuses(self, thresholds: Dict[str, Dict[str, int]]) -> Dict[str, str]:
        raise NotImplementedError


class PfSensePlatform(BasePlatform):
    """pfSense-specific implementation matching the reference watcher."""

    def get_gateway_monitoring_thresholds(self) -> Dict[str, Dict[str, int]]:
        thresholds: Dict[str, Dict[str, int]] = {}
        try:
            tree = ET.parse("/conf/config.xml")
            root = tree.getroot()
            gateways_config = root.find(".//gateways")
            defaults = {
                "latencyhigh": gateways_config.findtext("latencyhigh", "500") if gateways_config is not None else "500",
                "losshigh": gateways_config.findtext("losshigh", "20") if gateways_config is not None else "20",
            }
            for gw_item in root.findall(".//gateways/gateway_item"):
                gw_name = gw_item.findtext("name")
                if gw_name:
                    thresholds[gw_name] = {
                        "latencyhigh": int(gw_item.findtext("latencyhigh", defaults["latencyhigh"])),
                        "losshigh": int(gw_item.findtext("losshigh", defaults["losshigh"])),
                    }
        except Exception as e:
            print(f"[{time.ctime()}] WATCHER ERROR: Could not parse gateway monitoring thresholds: {e}")
        return thresholds

    def get_gateway_statuses(self, thresholds: Dict[str, Dict[str, int]]) -> Dict[str, str]:
        statuses: Dict[str, str] = {}
        try:
            dpinger_sockets = glob.glob("/var/run/dpinger_*.sock")
            for socket_path in dpinger_sockets:
                basename = os.path.basename(socket_path)
                gateway_name = ""
                try:
                    name_part = basename.replace("dpinger_", "", 1)
                    gateway_name = name_part.split("~", 1)[0]
                except IndexError:
                    continue
                status = "down"
                try:
                    result = subprocess.run(["cat", socket_path], capture_output=True, text=True, timeout=2)
                    socket_output = result.stdout.strip()
                    parts = socket_output.split()
                    if len(parts) >= 4:
                        live_latency_us = int(parts[1])
                        live_loss_pct = int(parts[3])
                        gw_thresholds = thresholds.get(gateway_name, {})
                        latency_high_ms = gw_thresholds.get("latencyhigh", 500)
                        loss_high_pct = gw_thresholds.get("losshigh", 20)
                        if (live_latency_us / 1000) < latency_high_ms and live_loss_pct < loss_high_pct:
                            status = "online"
                except Exception:
                    pass
                statuses[gateway_name] = status
        except Exception as e:
            print(f"[{time.ctime()}] WATCHER ERROR: Could not retrieve gateway statuses from dpinger sockets: {e}")
        return statuses


class GatewayWatcher:
    def __init__(self, platform: BasePlatform, updater_script: str, poll_interval: int = POLL_INTERVAL_SECONDS):
        self.platform = platform
        self.updater_script = updater_script
        self.poll_interval = poll_interval
        self.previous_statuses: Dict[str, str] = {}

    def _run_updater(self) -> None:
        if not os.path.exists(self.updater_script):
            print(f"[{time.ctime()}] WATCHER WARNING: updater script {self.updater_script} not found; skipping.")
            return
        try:
            subprocess.run([PHP_BIN, self.updater_script], timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[{time.ctime()}] Triggered MWDDNS updater (gateway state change).")
        except Exception as e:
            print(f"[{time.ctime()}] WATCHER ERROR: Failed to execute updater: {e}")

    def start(self) -> None:
        thresholds = self.platform.get_gateway_monitoring_thresholds()
        self.previous_statuses = self.platform.get_gateway_statuses(thresholds)
        print(f"[{time.ctime()}] Gateway state watcher started. Polling every {self.poll_interval} seconds.")
        print(f"[{time.ctime()}] Initial thresholds: {thresholds}")
        print(f"[{time.ctime()}] Initial state: {self.previous_statuses}")

        while True:
            time.sleep(self.poll_interval)
            thresholds = self.platform.get_gateway_monitoring_thresholds()
            current_statuses = self.platform.get_gateway_statuses(thresholds)

            # Trigger if:
            # 1. We have data and something changed (includes online→down transitions), OR
            # 2. A gateway that was previously tracked has disappeared from the
            #    current snapshot (e.g., dpinger restarted or socket was removed
            #    while the interface went offline).
            disappeared = self.previous_statuses and not current_statuses.keys() >= self.previous_statuses.keys()
            changed = bool(current_statuses) and current_statuses != self.previous_statuses
            if changed or disappeared:
                print(f"[{time.ctime()}] Status change detected!")
                print(f"    Old status: {self.previous_statuses}")
                print(f"    New status: {current_statuses}")
                self._run_updater()
                self.previous_statuses = current_statuses


def main() -> None:
    parser = argparse.ArgumentParser(description="pfSense gateway state watcher daemon for MWDDNS")
    parser.add_argument(
        "--updater",
        default=MWDDNS_CRON_PATH,
        help="Path to the updater script to invoke on gateway state changes (default: /usr/local/bin/mwddns_cron.php)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=POLL_INTERVAL_SECONDS,
        help=f"Polling interval in seconds (default: {POLL_INTERVAL_SECONDS})",
    )
    args = parser.parse_args()

    platform = PfSensePlatform()
    watcher = GatewayWatcher(platform, args.updater, poll_interval=max(1, args.interval))
    watcher.start()


if __name__ == "__main__":
    main()
