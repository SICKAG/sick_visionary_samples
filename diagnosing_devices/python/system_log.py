#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse

from base.python.Control import Control
from shared.python.devices_config import get_device_config


def runSystemLogDemo(ip_address: str, cola_protocol: str, control_port: int):
    # tag::control_connection[]
    # Create a Control object for the device
    deviceControl = Control(ip_address, cola_protocol, control_port)
    # Open a connection to the device
    deviceControl.open()
    # end::control_connection[]

    # tag::call_getMessageLog[]
    # get the device message log
    msgLog = deviceControl.getMessageLog("MSinfo")
    # end::call_getMessageLog[]

    # tag::parse_response[]
    # print the message log
    for error in msgLog:
        print(f"ErrorId: {error['ErrorId']}")
        print(f"ErrorState: {error['ErrorState']}")
        print(f"FirstTime_PwrOnCnt: {error['FirstTime_PwrOnCnt']}")
        print(f"FirstTime_OpSecs: {error['FirstTime_OpSecs']}")
        print(f"FirstTime_TimeOccur: {error['FirstTime_TimeOccur']}")
        print(f"LastTime_PwrOnCnt: {error['LastTime_PwrOnCnt']}")
        print(f"LastTime_OpSecs: {error['LastTime_OpSecs']}")
        print(f"LastTime_TimeOccur: {error['LastTime_TimeOccur']}")
        print(f"NumberOccurance: {error['NumberOccurance']}")
        print(f"ErrReserved: {error['ErrReserved']}")
        print(f"ExtInfo: {error['ExtInfo'].decode('utf-8')}")
        print("\n")
    # end::parse_response[]

    # tag::control_disconnect[]
    # Close the connection to the device
    deviceControl.close()
    # end::control_disconnect[]


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="This script demonstrates how to change the device password.")
    parser.add_argument('-i', '--ip_address', required=False, type=str,
                        default="192.168.1.10", help="The ip address of the device.")
    parser.add_argument('-d', '--device_type', required=False, type=str,
                        default="Visionary-T Mini", choices=["Visionary-S", "Visionary-T Mini"],
                        help="Visionary product type.")
    args = parser.parse_args()

    cola_protocol, control_port, _ = get_device_config(args.device_type)

    runSystemLogDemo(args.ip_address, cola_protocol, control_port)
