#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse
import struct

from base.python.Control import Control
from shared.python.devices_config import get_device_config


def runLoginLogoutDemo(ip_address: str, cola_protocol: str, control_port: int):
    # tag::control_connection[]
    deviceControl = Control(ip_address, cola_protocol, control_port)
    deviceControl.open()
    # end::control_connection[]

    # Read the variable "SysTemperatureWarningMargin" and store its original value
    # tag::read_variable[]
    sysTemperatureWarningMarginResponse = deviceControl.readVariable(
        b'SysTemperatureWarningMargin')
    sysTemperatureWarningMargin = struct.unpack(
        '>h', sysTemperatureWarningMarginResponse)[0]
    print(
        f"Current SysTemperatureWarningMargin: {sysTemperatureWarningMargin}°C")
    # end::read_variable[]

    # This section demonstrates what would happen if there is an attempt to write a variable which needs SERVICE access
    # level - but without any login. It is expected, that a CoLaError is reported, actually VARIABLE_WRITE_ACCESS_DENIED
    # is expected to occur in this case.

    # Decrease the original warning margin by 1 and write it back to the device
    sysTemperatureWarningMargin -= 1
    try:
        # tag::write_variable[]
        deviceControl.writeVariable(b'SysTemperatureWarningMargin', struct.pack(
            '>h', sysTemperatureWarningMargin))
        print("Successfully written new value to variable SysTemperatureWarningMargin")
        print(
            f"Current SysTemperatureWarningMargin: {sysTemperatureWarningMargin}°C")
        # end::write_variable[]
    except RuntimeError as e:
        print(e)

    # Now we will login/authenticate as user level "SERVICE" to obtain the needed access rights to write
    # SysTemperatureWarningMargin variable.
    # tag::login[]
    deviceControl.login(Control.USERLEVEL_SERVICE, "CUST_SERV")
    print("\nLogin with user level SERVICE was successful")
    # end::login[]

    # Now writing to SysTemperatureWarningMargin must succeed
    # Attempt to write the variable
    deviceControl.writeVariable(b'SysTemperatureWarningMargin', struct.pack(
        '>h', sysTemperatureWarningMargin))
    print("Successfully written new value to variable SysTemperatureWarningMargin")
    print(
        f"Current SysTemperatureWarningMargin: {sysTemperatureWarningMargin}°C")

    # Finally restore the original value for SysTemperatureWarningMargin variable
    sysTemperatureWarningMargin += 1
    # Attempt to write the variable
    deviceControl.writeVariable(b'SysTemperatureWarningMargin', struct.pack(
        '>h', sysTemperatureWarningMargin))
    print("Restoring SysTemperatureWarningMargin to initial value")
    print(
        f"Current SysTemperatureWarningMargin: {sysTemperatureWarningMargin}°C\n")

    # tag::logout_and_disconnect[]
    deviceControl.logout()
    deviceControl.close()
    # end::logout_and_disconnect[]
    print("Logout user level SERVICE from device")
    print("Closed the connection to the Visionary device")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="This script demonstrates how to change the device password.")
    parser.add_argument('-i', '--ip_address', required=False, type=str,
                        default="192.168.1.10", help="The ip address of the device.")
    parser.add_argument('-t', '--type', required=False, type=str,
                        default="Visionary-T Mini", choices=["Visionary-S", "Visionary-T Mini"],
                        help="Visionary product type.")
    args = parser.parse_args()

    cola_protocol, control_port, _ = get_device_config(args.type)

    runLoginLogoutDemo(args.ip_address, cola_protocol, control_port)
