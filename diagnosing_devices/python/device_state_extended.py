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


def runDiagnosticsDemoExtended(ip_address: str, cola_protocol: str, control_port: int):
    # Create a Control object for the device
    device_control = Control(ip_address, cola_protocol, control_port)
    # Open a connection to the device
    device_control.open()

    print("\n***Status Overview***")
    print()
    print("Device Information:")
    print(
        f"Manufacturer: {device_control.getManufacturer()}, Firmware Version: {device_control.getFirmwareVersion()}")

    device_type, sdd_version = device_control.getIdent()
    print(f"Device Type: {device_type}, SDD Version: {sdd_version}")

    print(
        f"Order Number: {device_control.getOrderNumber()}, Serial Number: {device_control.getSerialNumber()}")

    print()
    print("Device Status:")
    print("Temperature Level:", device_control.getTempLevel())
    print("Illumination Active:", device_control.getIlluminationActive())
    print("OpVoltageStatus:", device_control.getOpVoltageStatus())
    print("Digital IO Status:", device_control.getDigitalIOStatus())
    print("Image Acquisition (Frontend Mode):",
          device_control.getFrontendMode())

    print()
    print("Service Information:")
    print("Power On Count:", device_control.getPowerOnCnt())

    # Get operating hours and daily operating hours
    op_hours = device_control.getOpHours()
    daily_op_hours = device_control.getDailyOpHours()

    # Convert to hh:mm format
    op_hours_hh_mm = f"{int(op_hours):02d}:{int((op_hours - int(op_hours)) * 60):02d}"
    daily_op_hours_hh_mm = f"{int(daily_op_hours):02d}:{int((daily_op_hours - int(daily_op_hours)) * 60):02d}"

    # Print in hh:mm format
    print("Operating Hours:", op_hours_hh_mm, "hh:mm")
    print("Up Time:", daily_op_hours_hh_mm, "hh:mm")

    print()
    print("Operating Voltage:")
    _, current_voltage, minimal_voltage, maximal_voltage = device_control.getElectricalMonitoring()
    print(f"Current Operating Voltage: {current_voltage:.2f} V")
    print(f"Minimal Voltage (since start): {minimal_voltage:.2f} V")
    print(f"Maximal Voltage (since start): {maximal_voltage:.2f} V")

    _, _, min_allowed_op_voltage, max_allowed_op_voltage = device_control.getElectricalLimits()
    print(
        f"The required operating voltage is between: {min_allowed_op_voltage:.2f} V and {max_allowed_op_voltage:.2f} V")

    print()
    print("Temperatures:")
    print(
        f"Current System Temperature: {device_control.getSysTemperatureCurrentValue():.2f}°C")

    temperature_names = device_control.getTemperatureNames()
    temperature_values = device_control.getTemperatureValues()
    for name, value in zip(temperature_names, temperature_values):
        print(f"{name}: {value}°C")

    print()
    print("Digital In- and Output:")
    print("Thermal Overload:", device_control.getDoutOverload())

    doutPinErrors = device_control.getDoutPinError()
    for pin, error in doutPinErrors.items():
        print(f"{pin} short ciruit error: {error}")

    print()
    print("Ethernet statistics")
    print("Ethernet speed", device_control.getEtherIPSpeedDuplex())

    if "Visionary-S" in device_type:
        stats = device_control.getBlobServerStatistics()
        for stat in stats:
            if stat['Level'] == 0 and stat['Var'] == 'Sending':
                print('Number of frames:', stat['NumImages'])
                print('Number of errors:', stat['NumErrors'])
                break

    print()
    print("Error Log:")
    log = device_control.getMessageLog("MSinfo")
    print(f"{'First Time':<20} | {'Last Time':<20} | {'Description':<50} | {'Info':<30} | {'State':<10} | {'Occurrences':<12} | {'ID':<5}")
    print('-'*147)

    for error in log:
        first_time = error['FirstTime_OpSecs']
        last_time = error['LastTime_OpSecs']
        description = decode_error_code(error['ErrorId'], device_type)
        info = error['ExtInfo'].decode('utf-8')
        state = error['ErrorState']
        occurrences = error['NumberOccurance']
        id = error['ErrorId']

        print(f"{first_time:<20} | {last_time:<20} | {description:<50} | {info:<30} | {state:<10} | {occurrences:<12} | {id:<5}")

    print()

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

    runDiagnosticsDemoExtended(args.ip_address, cola_protocol, control_port)
