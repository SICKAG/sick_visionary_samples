#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse

from base.python.Control import Control
from shared.python.devices_config import get_device_config


def runSavePermanentlyDemo(ip_address: str, cola_protocol: str,
                           control_port: int, device_type: str, restore_original: bool):
    # tag::control_connection[]
    device_control = Control(ip_address, cola_protocol, control_port)
    device_control.open()
    # end::control_connection[]

    # Login as user level "SERVICE" to obtain the needed access rights to write/invoke cola variables/methods
    device_control.login(Control.USERLEVEL_SERVICE, "CUST_SERV")
    print("\nLogin with user level SERVICE was successful")

    if device_type == "Visionary-S":
        if not restore_original:
            print(
                f"Read IntegrationTimeUS: {device_control.getIntegrationTimeUs()} µs.")
            # tag::save_permanently_integration_time[]
            new_integration_time = 3000
            device_control.setIntegrationTimeUs(new_integration_time)
            print(f"Set IntegrationTimeUS: {new_integration_time} µs.")
            # call writeEeprom to permanently save the changed parameters
            result = device_control.writeEeprom()
            if result:
                print(
                    f"Permanently changed IntegrationTimeUs to {new_integration_time} µs.")
            else:
                print("Failed to save parameter permanently.")
            # end::save_permanently_integration_time[]

        else:
            # tag::restore_default_integration_time[]
            default_integration_time_us = 1000  # µs
            device_control.setIntegrationTimeUs(default_integration_time_us)
            result = device_control.writeEeprom()
            if result:
                print(
                    f"Restored IntegrationTimeUs to default of {default_integration_time_us} µs.")
            else:
                print("Failed to restore default value for IntegrationTimeUs.")
            # end::restore_default_integration_time[]

    elif device_type == "Visionary-T Mini":
        if not restore_original:
            print(
                f"Read framePeriodUs: {device_control.getFramePeriodUs()} µs.")
            new_frame_period_us = 60000
            device_control.setFramePeriodUs(new_frame_period_us)
            print(f"Set FramePeriodUS to {new_frame_period_us} µs.")
            # call writeEeprom to permanently save the changed parameters
            result = device_control.writeEeprom()
            if result:
                print(
                    f"Permanently changed FramePeriodUS to {new_frame_period_us} µs.")
            else:
                print("Failed to save parameter permanently.")
        else:
            default_frame_period_us = 40000  # µs
            device_control.setFramePeriodUs(default_frame_period_us)
            result = device_control.writeEeprom()
            if result:
                print(
                    f"Restored framePeriodUs to default of {default_frame_period_us} µs.")
            else:
                print("Failed to restore default value for FramePeriodUs.")

    device_control.logout()
    device_control.close()
    print("Logout user level SERVICE from device")
    print("Closed the connection to the Visionary device")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="This script demonstrates how to change the device password.")
    parser.add_argument('-i', '--ip_address', required=False, type=str,
                        default="192.168.1.10", help="The ip address of the device.")
    parser.add_argument('-d', '--device_type', required=False, type=str,
                        default="Visionary-T Mini", choices=["Visionary-S", "Visionary-T Mini"],
                        help="Visionary product type.")
    parser.add_argument('-r', '--restore_values', required=False, type=str, choices=["True", "False"],
                        default="False", help="Restores the permanetly changed value to its default value.")

    args = parser.parse_args()

    restore_original = True if args.restore_values == "True" else False

    cola_protocol, control_port, _ = get_device_config(args.device_type)

    runSavePermanentlyDemo(args.ip_address, cola_protocol,
                           control_port, args.device_type, restore_original)
