#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse
from base.python.Control import Control
from shared.python.devices_config import get_device_config


def runHelloSensorDemo(ip_address:str, cola_protocol:str, control_port:int):
    # tag::control_connection[]
    deviceControl = Control(ip_address, cola_protocol, control_port)
    deviceControl.open()
    # end::control_connection[]

    # tag::get_deviceIdent[]
    name, version = deviceControl.getIdent()
    print(f"DeviceIdent: {name} {version}")
    # end::get_deviceIdent[]

    # tag::control_disconnect[]
    deviceControl.close()
    # end::control_disconnect[]


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="This script simply connects to a device and prints the device ident.")
    parser.add_argument('-i', '--ipAddress', required=False, type=str,
                        default="192.168.1.10", help="The ip address of the device.")
    parser.add_argument('-d', '--device_type', required=False, type=str,
                        default="Visionary-T Mini", help="Device type: Visionary-T | Visionary-S | Visionary-T Mini ")
    args = parser.parse_args()

    cola_protocol, control_port, _ = get_device_config(args.device_type)

    runHelloSensorDemo(args.ipAddress, cola_protocol, control_port)
