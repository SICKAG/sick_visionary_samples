#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse

from python_base.Control import Control
from shared.python.devices_config import get_device_config

from datetime import datetime, timezone

import time

def run_ntp_demo(ip_address: str, server_ip: str, ntp_port:int, timeout:int, cola_protocol: str, control_port: int):

    # tag::open_control_channel[]
    device_control = Control(ip_address, cola_protocol, control_port)
    device_control.open()
    # end::open_control_channel[]

    # tag::timestamp_before[]
    device_timestamp_ms = device_control.getDeviceTime()
    device_time = datetime.fromtimestamp(device_timestamp_ms/1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    print(f"Device time before time synchronization: {device_time}")
    # end::timestamp_before[]

    # tag::wait_for_userinput[]
    # Ask user about NTP Master
    print("Running NTP Master is connected to the network? [Y/N]")
    user_input = input().strip().upper()
    # end::wait_for_userinput[]
    
    if user_input == 'Y':
        # tag::login[]
        # Login to the device for access rights to certain methods
        device_control.login(Control.USERLEVEL_SERVICE, 'CUST_SERV')
        # end::login[]
        
        # tag::set_ntp_server_ip[]
        device_control.setNtpClientServerAddress(server_ip)
        print(f"Set NTP server IP: {server_ip}")
        # end::set_ntp_server_ip[]

        # tag::set_ntp_server_port[]
        device_control.setNtpClientServerPort(ntp_port) # default is 123
        print(f"Set NTP port: {ntp_port}")
        # end::set_ntp_server_port[]

        # tag::set_ntp_server_timeout[]
        device_control.setNtpClientTimeout(timeout)
        print(f"Set NTP request timeout: {timeout}")
        # end::set_ntp_server_timeout[]

        # tag::enable_ntp[]
        device_control.setTimeSyncMode('NTP')
        print("Enabled NTP time synchronization")
        # end::enable_ntp[]
        device_control.logout()

        # tag::sleep[]
        time.sleep(5)
        print("Waiting for 5 seconds to be on the safe side.")
        # end::sleep[]

        # tag::timestamp_after[]
        device_timestamp_ms = device_control.getDeviceTime()
        device_time = datetime.fromtimestamp(device_timestamp_ms/1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        print(f"Device time after time synchronization: {device_time}")
        # end::timestamp_after[]

    device_control.login(Control.USERLEVEL_SERVICE, 'CUST_SERV')
    # tag::disable_ntp[]
    device_control.setTimeSyncMode('NONE')
    print("Disabled NTP time synchronization")
    # end::disable_ntp[]

    # tag::logout_and_close[]
    device_control.logout()
    device_control.close()
    print("Logged out. Closed connection.")
    # end::logout_and_close[]

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="This script demonstrates how to synchronize the device time with NTP.")
    parser.add_argument('-i', '--ip_address', required=False, type=str,
                        default="192.168.1.10", help="The ip address of the device.")
    parser.add_argument('-s', '--server_ip', required=False, type=str,
                        default="127.0.0.1", help="The ip address of the ntp server.")
    parser.add_argument('-p', '--ntp_port', required=False, type=int,
                        default="123", help="The port of the ntp server.")
    parser.add_argument('-t', '--timeout', required=False, type=int,
                        default="10000", help="Timeout of the NTP client in microseconds.")
    args = parser.parse_args()

    cola_protocol, control_port, _ = get_device_config("Visionary-T Mini")

    run_ntp_demo(args.ip_address, args.server_ip, args.ntp_port, args.timeout, cola_protocol, control_port)
