#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse
import os

from python_base.Control import Control
from python_base.Stream import Streaming
from python_base.Streaming import Data
from python_base.Streaming.BlobServerConfiguration import BlobClientConfig
from shared.python.data_processing import processSensorData
from shared.python.devices_config import get_device_config
from shared.python.frame_buffer_limits import (estimate_frame_size,
                                               get_safe_buffer_limit)
from python_base.Usertypes import FrontendMode


def runContinuousStreamingDemo(ip_address: str, transport_protocol: str, receiver_ip: str,
                               cola_protocol: str, control_port: int, streaming_port: int,
                               device_type: str, count: int, output_prefix: str, write_files: bool,
                               pointcloud_binary: bool, pointcloud_output: str):
    pcl_dir = None
    img_dir = None
    if write_files:
        # directory to save the output in
        pcl_dir = 'VisionaryToPointCloud'
        img_dir = 'VisionaryImages'
        os.makedirs(pcl_dir, exist_ok=True)
        os.makedirs(img_dir, exist_ok=True)

    # tag::open_control_channel[]
    device_control = Control(ip_address, cola_protocol, control_port)
    # Connect to devices control channel
    device_control.open()
    # end::open_control_channel[]

    # tag::login[]
    # Login to the device for access rights to certain methods
    device_control.login(Control.USERLEVEL_SERVICE, 'CUST_SERV')
    # end::login[]

    # streaming settings:
    streaming_settings = BlobClientConfig(device_control)
    streaming_device = None

    # tag::tcp_settings[]
    if transport_protocol == "TCP":
        # configure the data stream
        # the methods immediately write the setting to the device
        # set protocol and device port
        streaming_settings.setTransportProtocol(
            streaming_settings.PROTOCOL_TCP)
        streaming_settings.setBlobTcpPort(streaming_port)
        # start streaming
        streaming_device = Streaming(ip_address, streaming_port)
        streaming_device.openStream()
    # end::tcp_settings[]

    # tag::udp_settings[]
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
    # end::udp_settings[]

    if streaming_device is None:
        raise ValueError("Unsupported transport protocol: {}".format(transport_protocol))
    
    # tag::start_acquisition[]
    # start the image acquisition and continuously receive frames
    device_control.setFrontendMode(FrontendMode.Continuous)
    # end::start_acquisition[]
    
    # logout after settings have been done
    device_control.logout()

    # handle and drop one dummy frame only for Visionary-T Mini
    # (frontend needs to warm up to achieve specified TOF precision)
    if device_type == "Visionary-T Mini":
        streaming_device.getFrame()

    # tag::capture_loop[]
    sensor_data = Data.Data()
    captured_frames = []
    safe_buffer_limit = count
    memory_limit_checked = False
    memory_limit_applied = False
    try:
        number_frames = count
        while number_frames > 0:
            streaming_device.getFrame()
            print("Received frame number: {}".format(count - number_frames + 1))
            whole_frame = streaming_device.frame
            if whole_frame is None:
                number_frames -= 1
                continue
            if hasattr(whole_frame, "copy"):
                frame_copy = whole_frame.copy()
            else:
                frame_copy = bytes(whole_frame)

            captured_frames.append(frame_copy)

            if not memory_limit_checked:
                safe_buffer_limit = get_safe_buffer_limit(count, estimate_frame_size(frame_copy))
                memory_limit_checked = True
                memory_limit_applied = safe_buffer_limit < count
                if memory_limit_applied:
                    print("Limiting buffered capture to {} frames to avoid excessive RAM usage.".format(
                        safe_buffer_limit))

            if memory_limit_applied and len(captured_frames) >= safe_buffer_limit:
                print("Stopping capture after {} buffered frames because the safe in-memory limit was reached.".format(
                    safe_buffer_limit))
                break

            number_frames -= 1

    except KeyboardInterrupt:
        print("Terminating")

    if write_files:
        for frame_counter, frame in enumerate(captured_frames, start=1):
            print("====================================")
            print("Processing frame number: {}".format(frame_counter))
            sensor_data.read(frame, convertToMM=False)
            processSensorData(sensor_data, device_type,
                            img_dir, output_prefix, pcl_dir, write_files,
                            pointcloud_binary, pointcloud_output)
    # end::capture_loop[]

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
        description="This script demonstrates how to continuously stream and process frames from a device using TCP or UDP.")
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
    parser.add_argument('-w', "--write_files", required=False, type=str, choices=["True", "False"],
                        default="True", help="Write the files to storage if True.")
    parser.add_argument('--pointcloud_format', required=False, type=str, choices=['ascii', 'binary'],
                        default='ascii', help="Point cloud format for PCD/PLY: ascii or binary.")
    parser.add_argument('--pointcloud_output', required=False, type=str, choices=['pcd', 'ply', 'both'],
                        default='pcd', help="Point cloud output type: pcd, ply, or both.")
    args = parser.parse_args()

    cola_protocol, control_port, _ = get_device_config(args.device_type)

    write_files = True if args.write_files == "True" else False
    pointcloud_binary = True if args.pointcloud_format == "binary" else False

    runContinuousStreamingDemo(args.ipAddress, args.transport_protocol, args.receiver_ip,
                               cola_protocol, control_port, args.streaming_port,
                               args.device_type, args.count, args.output_prefix, write_files,
                               pointcloud_binary, args.pointcloud_output)
