#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse
import struct

from base.python.Control import Control
from base.python.Usertypes import ThreeLevels
from shared.python.devices_config import get_device_config
from shared.python.error_decode import decode_error_code


def runDiagnosticsDemo(ip_address: str, cola_protocol: str, control_port: int):
    # Create a Control object for the device
    device_control = Control(ip_address, cola_protocol, control_port)
    # Open a connection to the device
    device_control.open()

    # -----------------------------------------------
    # This section shows how read system health variables
    # Read current integration time
    print("//-----------------------------------------------")
    # tag::tempLvl_command[]
    # Read temperature level
    tmp_lvl_response = device_control.readVariable(b'TmpLvl')
    # end::tempLvl_command[]
    # tag::read_tmpLvl[]
    tmp_lvl_enum = struct.unpack('>B', tmp_lvl_response)[0]
    tmp_lvl = ThreeLevels(tmp_lvl_enum)
    print(f"Read Temperature Level: {tmp_lvl.name}")
    # end::read_tmpLvl[]

    # tag::read_sysTmp[]
    # System temperature
    sys_temp_response = device_control.readVariable(
        b'SysTemperatureCurrentValue')
    sys_temp = struct.unpack('>h', sys_temp_response)[0]
    print(f"Read SysTemperatureCurrentValue: {sys_temp/10.}°C")
    # end::read_sysTmp[]

    print("//-----------------------------------------------")
    # tag::opVoltage_command[]
    # Read operating voltage status
    op_voltage_status_response = device_control.readVariable(
        b'OpVoltageStatus')
    # end::opVoltage_command[]
    # tag::read_opVoltage[]
    op_voltage_status_enum = struct.unpack('>B', op_voltage_status_response)[0]
    op_voltage_status = ThreeLevels(op_voltage_status_enum)
    print(f"Read operating voltage status: {op_voltage_status.name}")
    # end::read_opVoltage[]

    # Close the connection to the device
    device_control.close()


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

    runDiagnosticsDemo(args.ip_address, cola_protocol, control_port)
