#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse

from enum import Enum
from base.python.Protocol.AutoIp import AutoIp

# Define cola version enums
class ColaVersion(Enum):
    COLA1 = 1
    COLA2 = 2

def runConfigureSensorIPDemo(ip_address:str, mac_address:str, cola_version:int, new_ip_address:str, network_mask:str, gateway:str, dhcp:bool):

    autoIp = AutoIp(ip_address)
    # tag::configure_sensor[]
    succ = autoIp.assign(mac_address, cola_version, new_ip_address, network_mask, gateway, dhcp)
    # end::configure_sensor[]

    print("Configuration succeeded!") if succ else print("Configuration failed!")

parser = argparse.ArgumentParser(description="This script scans the devices in the network and outputs their device information.")
parser.add_argument('-o', '--macAddress', required=True, type=str,
                    help="MAC address of the device to assign.")
parser.add_argument('-i', '--interfaceIp', required=True, type=str,
                    default="192.168.1.10/24",
                    help="""Ip address of the interface on which the scan is performed.
                    It is expected to be in a CIDR manner,
                    i.e., using ip address and the length of network prefix seperated by /.
                    For example, -i192.168.1.100/24
                    Note the range of prefix is [0, 32].""")
parser.add_argument('-c', '--colaVersion', required=True, type=str,
                    default="2", help="cola version either  -c1 (COLA1) or -c2 (COLA2)")
parser.add_argument('-n', '--newIp', required=True, type=str,
                    help="new ip address of the device")
parser.add_argument('-m', '--mask', required=True, type=str,
                    help="network mask of the device")
parser.add_argument('-g', '--gateway', required=False, type=str,
                    default="0.0.0.0", help="gateway of the device")
parser.add_argument('-d', '--dhcp', required=False, type=bool,
                    default=False, help="enable dhcp")

args = parser.parse_args()

runConfigureSensorIPDemo(args.interfaceIp, args.macAddress, args.colaVersion, args.newIp, args.mask, args.gateway, args.dhcp)
