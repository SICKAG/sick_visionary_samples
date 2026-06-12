#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 SICK AG, Waldkirch
#
# SPDX-License-Identifier: MIT

import argparse
import time
from typing import Optional
from base.python.Control import Control
from shared.python.devices_config import get_device_config


def safe_close(device_control: Optional[Control]):
    """Best-effort close helper so reconnect tests continue after close failures."""
    if device_control is None:
        return

    try:
        device_control.close()
    except Exception as exc:
        print(f"[warn] close() raised: {exc}")


def runConnectionStabilityDemo(
    ip_address: str,
    cola_protocol: str,
    control_port: int,
    poll_interval: float,
    reconnect_interval: float,
    reconnect_mode: str,
):
    print(
        f"Starting connection monitor for {ip_address}:{control_port} "
        f"(mode={reconnect_mode}, poll={poll_interval}s, reconnect={reconnect_interval}s)"
    )
    print("Unplug/replug the Ethernet cable and observe the log messages.")

    device_control = None

    while True:
        if device_control is None:
            # tag::open_control[]
            try:
                device_control = Control(ip_address, cola_protocol, control_port)
                device_control.open()
                name, version = device_control.getIdent()
                print(f"[connected] DeviceIdent: {name} {version}")
            except Exception as exc:
                print(f"[connect-failed] {exc}")
                safe_close(device_control)
                device_control = None
                time.sleep(reconnect_interval)
                continue
            # end::open_control[]

        # tag::poll_ident[]
        try:
            name, version = device_control.getIdent()
            print(f"[alive] DeviceIdent: {name} {version}")
            time.sleep(poll_interval)
        except Exception as exc:
            print(f"[connection-lost] {exc}")
            # end::poll_ident[]

            # tag::reconnect[]
            if reconnect_mode == "reuse":
                safe_close(device_control)
                time.sleep(reconnect_interval)
                try:
                    device_control.open()
                    name, version = device_control.getIdent()
                    print(f"[reconnected-reuse] DeviceIdent: {name} {version}")
                    continue
                except Exception as reconnect_exc:
                    print(f"[reuse-open-failed] {reconnect_exc}")

            safe_close(device_control)
            device_control = None
            time.sleep(reconnect_interval)
            # end::reconnect[]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Monitor connection stability by polling getIdent() in a loop and "
            "automatically reconnecting after disconnects."
        )
    )
    parser.add_argument('-i', '--ipAddress', required=False, type=str,
                        default="192.168.136.10", help="The ip address of the device.")
    parser.add_argument('-d', '--device_type', required=False, type=str,
                        default="Visionary-T Mini", help="Device type: Visionary-T | Visionary-S | Visionary-T Mini ")
    parser.add_argument('--poll-interval', required=False, type=float,
                        default=1.0, help="Seconds between getIdent() calls while connected.")
    parser.add_argument('--reconnect-interval', required=False, type=float,
                        default=1.0, help="Seconds to wait before reconnect attempts.")
    parser.add_argument('--reconnect-mode', required=False, type=str,
                        choices=["recreate", "reuse"], default="recreate",
                        help="recreate: create a new Control object each reconnect; reuse: call close()/open() on same object.")
    args = parser.parse_args()

    cola_protocol, control_port, _ = get_device_config(args.device_type)

    try:
        runConnectionStabilityDemo(
            args.ipAddress,
            cola_protocol,
            control_port,
            args.poll_interval,
            args.reconnect_interval,
            args.reconnect_mode,
        )
    except KeyboardInterrupt:
        print("\nStopped by user.")
