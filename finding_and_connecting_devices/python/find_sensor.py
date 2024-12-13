#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse

from base.python.Protocol.AutoIp import AutoIp

def runFindSensorDemo(ip_address:str):
    # tag::find_sensor[]
    autoIp = AutoIp(ip_address)
    # end::find_sensor[]

    # tag::get_deviceInformation[]
    devices = autoIp.scan()
    for device in devices:
        print(f"Device name:  {device.deviceIdent}")
        print(f"SerialNumber: {device.serialNumber}")
        print(f"MAC Address:  {device.macAddress}")
        print(f"IP Address:   {device.ipAddress}")
        print(f"Network Mask: {device.netmask}")
        print(f"CoLa port:    {device.colaPort}")
        print(f"CoLa version: {int(device.colaVersion)}")
    print("Number of found devices: ", len(devices))
    # end::get_deviceInformation[]


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="This script scans the devices in the network and outputs their device information.")
    parser.add_argument('-i', '--ipAddress', required=True, type=str,
                    default="192.168.1.10/24",
                    help="""Ip address of the interface on which the scan is performed.
                    It is expected to be in a CIDR manner,
                    i.e., using ip address and the length of network prefix seperated by /.
                    For example, -i192.168.1.100/24
                    Note the range of prefix is [0, 32].""")
    args = parser.parse_args()
    runFindSensorDemo(args.ipAddress)
