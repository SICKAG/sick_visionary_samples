#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse
import os
from time import sleep

from base.python.Control import Control
from base.python.Stream import Streaming
from base.python.Streaming import Data
from base.python.Streaming.BlobServerConfiguration import BlobClientConfig
from base.python.Usertypes import (FrontendMode, InputFunctionType,
                                   IOFunctionType)
from shared.python.config import (Configuration, read_configuration,
                                  write_configuration)
from shared.python.data_processing import processSensorData
from shared.python.devices_config import get_device_config
from shared.python.ioports import DioPortNames


def runExternalTriggerDemo(ip_address: str, transport_protocol: str, receiver_ip: str,
                           cola_protocol: str, control_port: int, streaming_port: int,
                           device_type: str, count: int, output_prefix: str, port_names: DioPortNames, write_files: bool):
    pcl_dir = None
    img_dir = None
    if write_files:
        # directory to save the output in
        pcl_dir = 'VisionaryToPointCloud'
        img_dir = 'VisionaryImages'
        os.makedirs(pcl_dir, exist_ok=True)
        os.makedirs(img_dir, exist_ok=True)

    # Create a Control object for the device
    device_control = Control(ip_address, cola_protocol, control_port)

    # Open a connection to the device
    device_control.open()

    # Login as authorized client
    device_control.login(Control.USERLEVEL_AUTH_CLIENT, 'CLIENT')

    old_config = read_configuration(device_control, port_names)
    print("Old Config:", old_config)

    new_config = Configuration()

    # the expected frontend mode for external trigger operation
    # differs between Visionary-T Mini and the rest.
    if device_type == "Visionary-T Mini":
        new_config.frontend_mode = FrontendMode.Stopped
    else:
        new_config.frontend_mode = FrontendMode.ExternalTrigger

    new_config.trigger_in_fct = InputFunctionType.Trigger
    new_config.trigger_in_fct_2 = IOFunctionType.Trigger
    new_config.busyOutFct = IOFunctionType.TriggerBusy

    print("New config:", new_config)

    # write the new configuration
    write_configuration(device_control, port_names, new_config)

    # streaming settings:
    streaming_settings = BlobClientConfig(device_control)
    streaming_device = None

    if transport_protocol == "TCP":
        # configure the data stream, the methods immediately write the setting to the device
        # set protocol and device port
        streaming_settings.setTransportProtocol(
            streaming_settings.PROTOCOL_TCP)
        streaming_settings.setBlobTcpPort(streaming_port)
        # start streaming
        streaming_device = Streaming(ip_address, streaming_port)
        streaming_device.openStream()

    elif transport_protocol == "UDP":
        # settings
        streaming_settings.setTransportProtocol(
            streaming_settings.PROTOCOL_UDP)  # UDP
        streaming_settings.setBlobUdpReceiverPort(streaming_port)
        streaming_settings.setBlobUdpReceiverIP(receiver_ip)
        streaming_settings.setBlobUdpControlPort(streaming_port)
        streaming_settings.setBlobUdpMaxPacketSize(1024)
        streaming_settings.setBlobUdpIdleTimeBetweenPackets(
            10)  # in milliseconds
        streaming_settings.setBlobUdpHeartbeatInterval(0)
        streaming_settings.setBlobUdpHeaderEnabled(True)
        streaming_settings.setBlobUdpFecEnabled(
            False)  # forward error correction
        streaming_settings.setBlobUdpAutoTransmit(True)
        streaming_device = Streaming(
            ip_address, streaming_port, protocol=transport_protocol)
        streaming_device.openStream((receiver_ip, streaming_port))

    # logout after settings have been done
    device_control.logout()

    # Depending on the PC we might be too fast for the device configuration
    # Just wait a short time. This should only be necessary after stop
    # (to make sure stop really propagated and you don't get a pending frame)
    # or after a configure to make sure configuration has finished
    # tag::precautionary_stop[]
    sleep(0.1)
    # end::precautionary_stop[]

    # tag::wait_for_frame[]
    # wait for external trigger
    sensor_data = Data.Data()
    interrupted = False
    for i in range(count):
        frame_number = None
        print("Waiting for the trigger, press ctrl-C to abort")
        while not interrupted:
            try:
                streaming_device.getFrame()
                whole_frame = streaming_device.frame
                sensor_data.read(whole_frame, convertToMM=False)
                if sensor_data.depthmap.frameNumber != frame_number:
                    processSensorData(sensor_data, device_type,
                                      img_dir, output_prefix, pcl_dir, write_files)
                frame_number = sensor_data.depthmap.frameNumber
                break
            except Exception:
                continue  # Continue the loop if a timeout occurs
            except KeyboardInterrupt:
                print("Interrupted by user")
                interrupted = True
                break
    # end::wait_for_frame[]

    # tag::restore_config[]
    # Login as authorized client
    device_control.login(Control.USERLEVEL_AUTH_CLIENT, 'CLIENT')
    # restore the old configuration
    write_configuration(device_control, port_names, old_config)
    print("Restored old configuration.")
    # end::restore_config[]

    # tag::close_streaming[]
    device_control.login(Control.USERLEVEL_AUTH_CLIENT, 'CLIENT')
    streaming_device.closeStream()
    if transport_protocol == "UDP":
        # restoring back to TCP mode
        streaming_settings.setTransportProtocol(
            streaming_settings.PROTOCOL_TCP)
    streaming_settings.setBlobTcpPort(2114)
    # end::close_streaming[]

    # tag::logout_and_close[]
    device_control.logout()
    device_control.close()
    # end::logout_and_close[]
    print("Logout and close")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="This script demonstrates how to read system health variables.")
    parser.add_argument('-i', '--ipAddress', required=False, type=str,
                        default="192.168.1.10", help="The ip address of the device.")
    parser.add_argument('-t', '--transport_protocol', required=False, choices=['TCP', 'UDP'],
                        default="TCP", help="The transport protocol.")
    parser.add_argument('-r', '--receiver_ip', required=False, type=str,
                        default="192.168.1.2", help="The ip address of the receiving PC (UDP only).")
    parser.add_argument('-d', '--device_type', required=False, type=str,
                        default="Visionary-T Mini", choices=["Visionary-S", "Visionary-T Mini"],
                        help="Visionary product type.")
    parser.add_argument('-s', '--streaming_port', required=False, type=int,
                        default=2114, help="The port of the data channel.")
    parser.add_argument('-n', '--count', required=False, type=int, default=10,
                        help="Acquire number frames and stop.")
    parser.add_argument('-o', "--output_prefix", required=False, type=str, default="",
                        help="prefix for the output files.")
    parser.add_argument('-x', '--triggerInputPin', required=False, type=str,
                        default=None, help="Trigger input I/O pin; default is SENS_IN1 for a Visionary-S and INOUT1 for a Visionary-T Mini.")
    parser.add_argument('-b', '--triggerBusyPin', required=False, type=str,
                        default=None, help="Trigger busy I/O pin; default is none for a Visionary-S and INOUT2 for a Visionary-T Mini.")
    parser.add_argument('-w', "--write_files", required=False, type=str, choices=["True", "False"],
                        default="True", help="Write the files to storage if True.")
    args = parser.parse_args()

    device_type = args.device_type

    port_names = DioPortNames()

    if args.triggerInputPin:
        port_names.trigger_in_name = args.triggerInputPin
    else:
        if device_type == "Visionary-S":
            port_names.trigger_in_name = "SENS_IN1"
        elif device_type == "Visionary-T Mini":
            port_names.trigger_in_name = "INOUT1"

    if args.triggerBusyPin:
        port_names.busy_out_name = args.triggerBusyPin
    else:
        if device_type == "Visionary-T Mini":
            port_names.busy_out_name = "INOUT2"

    cola_protocol, control_port, _ = get_device_config(device_type)

    write_files = True if args.write_files == "True" else False

    runExternalTriggerDemo(args.ipAddress, args.transport_protocol, args.receiver_ip,
                           cola_protocol, control_port, args.streaming_port, device_type,
                           args.count, args.output_prefix, port_names, write_files)
