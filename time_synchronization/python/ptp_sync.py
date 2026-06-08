#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse
from python_base.Control import Control
from shared.python.devices_config import get_device_config
from datetime import datetime, timezone
import time

def run_PTP_demo(ip_address: str):
    # tag::open_control_channel[]
    device_control = Control(ip_address, cola_protocol, control_port)
    device_control.open()
    # end::open_control_channel[]

    # tag::timestamp_before[]
    device_timestamp_ms = device_control.getDeviceTime()
    device_time = datetime.fromtimestamp(device_timestamp_ms / 1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    print(f"Device time before time synchronization: {device_time}")
    # end::timestamp_before[]

    print(f"PTP State: {device_control.getPtpState()}")

    # tag::wait_for_userinput[]
    # Ask user about PTP Master
    print("Running PTP Master is connected to the network? [Y/N]")
    user_input = input().strip().upper()
    # end::wait_for_userinput[]

    if user_input == 'Y':
        # tag::login[]
        device_control.login(Control.USERLEVEL_SERVICE, 'CUST_SERV')
        # end::login[]
        
        # tag::ptp_setting[]
        device_control.setPtpMode("SLAVE")
        print("Set PTP Mode: SLAVE")
        # end::ptp_setting[]

        # tag::enable_ptp[]
        device_control.setTimeSyncMode('PTP')
        print("Enabled PTP time synchronization")
        # end::enable_ptp[]
        device_control.logout()

        # tag::sleep[]
        print("Waiting for 5 seconds to be on the safe side.")
        time.sleep(5)
        # end::sleep[]
        print(f"PTP State: {device_control.getPtpState()}")

        # tag::timestamp_after[]
        device_timestamp_ms = device_control.getDeviceTime()
        device_time = datetime.fromtimestamp(device_timestamp_ms/1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        print(f"Device time after time synchronization: {device_time}")
        # end::timestamp_after[]
        
    # tag::disable_ptp[]
    device_control.login(Control.USERLEVEL_SERVICE, 'CUST_SERV')
    device_control.setTimeSyncMode('NONE')
    print("Disabled PTP (timeSyncMode)")
    # end::disable_ptp[]
    
    # tag::logout_and_close[]
    device_control.logout()
    device_control.close()
    # end::logout_and_close[]
    print("Logged out. Closed connection.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="This script demonstrates how to synchronize the device time with PTP.")
    parser.add_argument('-i', '--ip_address', required=False, type=str,
                        default="192.168.1.10", help="The ip address of the device.")
    args = parser.parse_args()

    cola_protocol, control_port, _ = get_device_config("Visionary-T Mini")

    run_PTP_demo(args.ip_address)
