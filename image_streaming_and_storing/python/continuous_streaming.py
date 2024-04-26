#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse
import os
import socket
import time
from time import sleep

from base.python.Control import Control
from base.python.PointCloud.PointCloud import (convertToPointCloud,
                                               convertToPointCloudOptimized,
                                               writePointCloudToPCD,
                                               writePointCloudToPLY)
from base.python.Stream import Streaming
from base.python.Streaming import Data
from base.python.Streaming.BlobServerConfiguration import BlobClientConfig
from shared.python.devices_config import get_device_config
from shared.python.framewrite import writeFrame


def runContinuousStreamingDemo(ip_address: str, transport_protocol: str, receiver_ip: str,
                               cola_protocol: str, control_port: int, streaming_port: int,
                               device_type: str, count: int, output_prefix: str, write_files: bool):
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

    # Stop image acquisition (works always, also when already stopped)
    # Further you should always stop the device before reconfiguring it
    # tag::precautionary_stop[]
    device_control.stopStream()
    # end::precautionary_stop[]

    # Depending on the PC we might be too fast for the device configuration
    # Just wait a short time. This should only be necessary after stop
    # (to make sure stop really propagated and you don't get a pending frame)
    # or after a configure to make sure configuration has finished
    # tag::precautionary_stop[]
    sleep(0.1)
    # end::precautionary_stop[]

    # Login to the device for access rights to certain methods
    device_control.login(Control.USERLEVEL_SERVICE, 'CUST_SERV')

    # streaming settings:
    streaming_settings = BlobClientConfig(device_control)
    streaming_device = None

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
        # open the datagram socket
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bind the socket to the port
        # use empty hostname to listen on all adapters
        server_address = (receiver_ip, streaming_port)
        udp_socket.bind(server_address)

        udp_socket.settimeout(1)  # 1sec
        # 4 Megabyte of buffer size
        udp_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)

    # logout after settings have been done
    device_control.logout()

    # start the image acquisition and continuously receive frames
    # tag::start_acquisition[]
    device_control.startStream()
    # end::start_acquisition[]

    # tag::capture_loop[]
    sensor_data = Data.Data()
    try:
        number_frames = count
        while number_frames > 0:
            if transport_protocol == "TCP":
                streaming_device.getFrame()
                whole_frame = streaming_device.frame
                sensor_data.read(whole_frame, convertToMM=False)
                print("Data Timestamp [YYYY-MM-DD HH:MM:SS.mm] = %04u-%02u-%02u %02u:%02u:%02u.%03u" % (
                    sensor_data.getDecodedTimestamp()))
                if sensor_data.hasDepthMap:
                    frame_number = sensor_data.depthmap.frameNumber
                    print("Data contains depth map data:")
                    if write_files:
                        print("=== Write PNG file: Frame number: {}".format(
                            frame_number))
                        writeFrame(device_type, sensor_data,
                                   os.path.join(img_dir, output_prefix))
                        print("=== Converting image to pointcloud")

                        # Non optimized
                        start_time = time.time()
                        world_coordinates, dist_data = convertToPointCloud(sensor_data.depthmap.distance,
                                                                           sensor_data.depthmap.intensity,
                                                                           sensor_data.depthmap.confidence,
                                                                           sensor_data.cameraParams, sensor_data.xmlParser.stereo)
                        end_time = time.time()
                        execution_time = end_time - start_time
                        print(
                            f"convertToPointCloud took: {execution_time:.3}s")

                        # Optimized
                        is_stereo = True if device_type == "Visionary-S" else False
                        start_time = time.time()
                        point_cloud = convertToPointCloudOptimized(sensor_data.depthmap.distance,
                                                                   sensor_data.depthmap.confidence,
                                                                   sensor_data.cameraParams, is_stereo)
                        end_time = time.time()
                        execution_time = end_time - start_time
                        print(
                            f"convertToPointCloudOptimized took: {execution_time:.3}s")

                        # Write output of the non optimized function to PLY
                        writePointCloudToPLY(os.path.join(
                            pcl_dir, "world_coordinates{}.ply".format(frame_number)), world_coordinates)

                        # Write output of the optimized function to PCD
                        writePointCloudToPCD(os.path.join(
                            pcl_dir, "world_coordinates{}.pcd".format(frame_number)), point_cloud.reshape(-1, point_cloud.shape[-1]))
            elif transport_protocol == "UDP":
                byte_arr = []
                myData, server = udp_socket.recvfrom(1024)
                print(f"========== new BLOB received ==========")
                print(f"Blob number: {((myData[1] << 8) | (myData[0]))}")
                print("server IP: {}".format(server[0]))
                # this is the port the server opens to transmit the data
                print("server port: {}".format(server[1]))
                print("========================================")
                # FIN Flag of Statemap in header is set when new BLOB begins
                while (myData[6].to_bytes(1, byteorder='big') != b'\x80'):
                    byte_arr.append(myData[14:])
                    print(
                        f"Fragment number: {((myData[2] << 8) | (myData[3]))}")
                    myData, server = udp_socket.recvfrom(1024)
                print(f"Fragment number: {((myData[2] << 8) | (myData[3]))}")
                byte_arr.append(myData[14:])  # Payload begins at byteindex 14
            number_frames -= 1
    except KeyboardInterrupt:
        print("Terminating")
    # end::capture_loop[]

    # tag::stop_acquisition[]
    device_control.stopStream()
    # end::stop_acquisition[]

    # tag::close_streaming[]
    device_control.login(Control.USERLEVEL_AUTH_CLIENT, 'CLIENT')
    if transport_protocol == "TCP":
        streaming_device.closeStream()
        streaming_settings.setBlobTcpPort(2114)
    elif transport_protocol == "UDP":
        udp_socket.close()
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
    parser.add_argument('-w', "--write_files", required=False, type=str, choices=["True", "False"],
                        default="True", help="Write the files to storage if True.")
    args = parser.parse_args()

    cola_protocol, control_port, _ = get_device_config(args.device_type)

    write_files = True if args.write_files == "True" else False

    runContinuousStreamingDemo(args.ipAddress, args.transport_protocol, args.receiver_ip,
                               cola_protocol, control_port, args.streaming_port,
                               args.device_type, args.count, args.output_prefix, write_files)
