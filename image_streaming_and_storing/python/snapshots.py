#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse
import os
import time

from base.python.Control import Control
from base.python.Stream import Streaming
from base.python.Streaming import Data
from base.python.Streaming.BlobServerConfiguration import BlobClientConfig
from shared.python.data_processing import processSensorData
from shared.python.devices_config import get_device_config
from base.python.Usertypes import FrontendMode


def runSnapshotsDemo(ip_address: str, transport_protocol: str, receiver_ip: str,
                     cola_protocol: str, control_port: int, streaming_port: int, device_type: str,
                     number_frames: int, output_prefix: str, poll_period_ms: int, write_files: bool):
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

    # tag::login[]
    # access the device via a set account to change settings
    device_control.login(Control.USERLEVEL_SERVICE, 'CUST_SERV')
    # end::login[]

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
    
    # tag::stop_frontend[]
    # Stop image acquisition (works always, also when already stopped)
    device_control.setFrontendMode(FrontendMode.Stopped)
    # end::stop_frontend[]

    # logout after settings have been done
    device_control.logout()

    # tag::avoid_overrun[]
    poll_period_span = poll_period_ms / 1000.0  # Convert milliseconds to seconds
    last_snap_time = time.time()
    # end::avoid_overrun[]

    sensor_data = Data.Data()

    # trigger dummy snapshot acquistion to restart frontend 
    # (a stopped frontend needs to warm up for 16 frames to achieve specified TOF precision, these frames will be dropped internally)
    device_control.singleStep()
    streaming_device.getFrame()

    # acquire a single snapshot
    for i in range(number_frames):

        # tag::avoid_overrun[]
        # make sure we don't overrun the device
        # (otherwise snapshot requests would be dropped by the device)
        time_since_last_snap = time.time() - last_snap_time

        if time_since_last_snap < poll_period_span:
            time_to_wait = poll_period_span - time_since_last_snap
            time.sleep(time_to_wait)
        # end::avoid_overrun[]

        # tag::acquire_snapshots[]
        # now we are not too fast and can trigger a snapshot
        last_snap_time = time.time()
        device_control.singleStep()
        streaming_device.getFrame()
        whole_frame = streaming_device.frame
        sensor_data.read(whole_frame, convertToMM=False)
        processSensorData(sensor_data, device_type,
                          img_dir, output_prefix, pcl_dir, write_files)
        # end::acquire_snapshots[]

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
    # Reset the image acquisition to default mode
    device_control.setFrontendMode(FrontendMode.Continuous)
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
    parser.add_argument('-p', '--poll_period_ms', required=False, type=int,
                        default=500, help="Poll period for snapshot in ms.")
    parser.add_argument('-n', '--count', required=False, type=int, default=10,
                        help="Acquire number frames and stop.")
    parser.add_argument('-o', "--output_prefix", required=False, type=str, default="",
                        help="prefix for the output files.")
    parser.add_argument('-w', "--write_files", required=False, type=str, choices=["True", "False"],
                        default="True", help="Write the files to storage if True.")
    args = parser.parse_args()

    cola_protocol, control_port, _ = get_device_config(args.device_type)

    write_files = True if args.write_files == "True" else False

    runSnapshotsDemo(args.ipAddress, args.transport_protocol, args.receiver_ip,
                     cola_protocol, control_port, args.streaming_port, args.device_type,
                     args.count, args.output_prefix, args.poll_period_ms, write_files)
