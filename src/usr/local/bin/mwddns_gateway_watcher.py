#!/usr/local/bin/python3.11
# SPDX-License-Identifier: Apache-2.0
#
# mwddns_gateway_watcher.py – Part of pfSense-MWDDNS
# Copyright 2026 yatounoneko
#
# Adapted from gateway_watcher.py in psych0d0g/pfSense-MWAN-DDNS
# Original: https://github.com/psych0d0g/pfSense-MWAN-DDNS
# Original license: Apache License 2.0
#
# Modifications:
# - Refactored into BasePlatform / PfSensePlatform class hierarchy
# - Replaced file I/O with DpingerReader socket abstraction
# - Integrated with MWDDNS update pipeline (mwddns_cron.php)
# - Extended exception handling, structured logging, and CLI argument support
# - Removed PHP-based hook scripts; replaced by this standalone daemon
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
import math
import re
import socket
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
            def threshold(value, default, maximum=float("inf")):
                try:
                    number = float(value)
                    return number if math.isfinite(number) and 0 < number <= maximum else default
                except (TypeError, ValueError):
                    return default

            defaults = {
                "latencyhigh": threshold(defaults["latencyhigh"], 500),
                "losshigh": threshold(defaults["losshigh"], 20, 100),
            }
            thresholds[""] = defaults
            for gw_item in root.findall(".//gateways/gateway_item"):
                gw_name = gw_item.findtext("name")
                if gw_name:
                    thresholds[gw_name] = {
                        "latencyhigh": threshold(gw_item.findtext("latencyhigh"), defaults["latencyhigh"]),
                        "losshigh": threshold(gw_item.findtext("losshigh"), defaults["losshigh"], 100),
                    }
        except Exception as e:
            print(f"[{time.ctime()}] WATCHER ERROR: Could not parse gateway monitoring thresholds: {e}")
        return thresholds

    def get_gateway_statuses(self, thresholds: Dict[str, Dict[str, int]]) -> Dict[str, str]:
        statuses: Dict[str, str] = {}
        for socket_path in glob.glob("/var/run/dpinger_*.sock"):
            fallback = os.path.basename(socket_path)[8:].split("~", 1)[0]
            gateway_name = fallback.removesuffix(".sock")
            status = "unknown"
            try:
                deadline = time.monotonic() + 2
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(2)
                    connection.connect(socket_path)
                    data = bytearray()
                    while b"\n" not in data:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or len(data) >= 4096:
                            raise ValueError("Incomplete dpinger report")
                        connection.settimeout(remaining)
                        chunk = connection.recv(4096 - len(data))
                        if not chunk:
                            break
                        data.extend(chunk)
                parts = data.decode("ascii").strip().split()
                if len(data) >= 4096 or len(parts) != 4 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", parts[0]):
                    raise ValueError("Invalid dpinger report")
                latency_us, deviation_us, loss_pct = map(float, parts[1:])
                if not all(math.isfinite(value) and value >= 0 for value in (latency_us, deviation_us, loss_pct)):
                    raise ValueError("Invalid dpinger measurements")
                if loss_pct > 100:
                    raise ValueError("Invalid packet loss")
                gateway_name = parts[0]  # Also handles pfSense's hashed socket names.
                limits = thresholds.get(gateway_name, thresholds.get("", {}))
                latency_high = limits.get("latencyhigh", 500)
                loss_high = limits.get("losshigh", 20)
                status = "online" if latency_us / 1000 < latency_high and loss_pct < loss_high else "down"
            except (OSError, ValueError, UnicodeError):
                # A missing/unreadable socket is not evidence that a WAN is down.
                pass
            if gateway_name in statuses and statuses[gateway_name] != status:
                statuses[gateway_name] = "unknown"
            else:
                statuses[gateway_name] = status
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
            subprocess.run([PHP_BIN, self.updater_script], timeout=120, check=True, stdout=subprocess.DEVNULL)
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
