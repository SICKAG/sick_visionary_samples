#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse
import struct

from base.python.Control import Control
from base.python.Usertypes import BinningOption
from shared.python.devices_config import get_device_config


def run_configure_frontend_demo(ip_address: str, cola_protocol: str, control_port: int):
    # tag::connect_and_login[]
    device_control = Control(ip_address, cola_protocol, control_port)
    device_control.open()
    device_control.login(Control.USERLEVEL_AUTH_CLIENT, "CLIENT")
    # end::connect_and_login[]

    # -----------------------------------------------
    # Section: Configure binningOption
    # tag::set_binningOption[]
    new_binning_option = BinningOption['TWO_BY_TWO']
    device_control.writeVariable(
        b'binningOption', struct.pack('>B', new_binning_option))
    print(f"Set BinningOption to {new_binning_option.name}")
    # end::set_binningOption[]

    # tag::read_binningOption[]
    get_binning_option = device_control.readVariable(b'binningOption')
    binning_option_enum = struct.unpack('>B', get_binning_option)[0]
    binning_option = BinningOption(binning_option_enum)
    print(f"Read BinningOption: {binning_option.name}\n")
    # end::read_binningOption[]

    # -----------------------------------------------
    # Section: Configure framePeriodUs
    # tag::set_framePeriodUs[]
    new_frame_period_us = 60000
    device_control.setFramePeriodUs(new_frame_period_us)
    print(f"Set FramePeriodUS to {new_frame_period_us}")
    # end::set_framePeriodUs[]

    # tag::read_framePeriodUs[]
    frame_period_us = device_control.getFramePeriodUs()
    print(f"Read framePeriodUs: {frame_period_us}\n")
    # end::read_framePeriodUs[]
    # -----------------------------------------------

    # tag::logout_and_disconnect[]
    device_control.logout()
    device_control.close()
    # end::logout_and_disconnect[]


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="This script demonstrates how to change the device password.")
    parser.add_argument('-i', '--ip_address', required=False, type=str,
                        default="192.168.1.10", help="The ip address of the device.")
    args = parser.parse_args()

    cola_protocol, control_port, _ = get_device_config("Visionary-T Mini")

    run_configure_frontend_demo(args.ip_address, cola_protocol, control_port)
