#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import configparser

import cv2
import numpy as np

from base.python.Streaming.Data import Data


class TagAndName:
    def __init__(self, tag, filename):
        self.tag = tag
        self.filename = filename


def writeMeta(visionary_type: str, data: 'Data', inifilename: str, mapdescs: list):
    # Create a ConfigParser object
    config = configparser.ConfigParser()

    # Check if file can be opened for writing
    with open(inifilename, 'w') as metafile:
        # Write the meta data to the .ini file
        config.add_section('ident')
        config.set('ident', 'visionarytype', visionary_type)

        config.add_section('frame')
        # tag::frame_meta_data[]
        config.set('frame', 'framenumber', str(data.changedCounter))
        config.set('frame', 'timestamp', str(data.parsing_time_s))
        # end::frame_meta_data[]

        # tag::frame_geometry[]
        config.set('frame', 'width', str(data.xmlParser.imageWidth))
        config.set('frame', 'height', str(data.xmlParser.imageHeight))
        # end::frame_geometry[]

        # tag::intrinsics[]
        config.add_section('intrinsics')
        config.set('intrinsics', 'cx', str(data.xmlParser.cx))
        config.set('intrinsics', 'cy', str(data.xmlParser.cy))
        config.set('intrinsics', 'fx', str(data.xmlParser.fx))
        config.set('intrinsics', 'fy', str(data.xmlParser.fy))
        # end::intrinsics[]

        # tag::lens_distortion[]
        config.add_section('lensdistortion')
        config.set('lensdistortion', 'k1', str(data.xmlParser.k1))
        config.set('lensdistortion', 'k2', str(data.xmlParser.k2))
        config.set('lensdistortion', 'p1', str(data.xmlParser.p1))
        config.set('lensdistortion', 'p2', str(data.xmlParser.p2))
        config.set('lensdistortion', 'k3', str(data.xmlParser.k3))
        # end::lens_distortion[]

        # tag::f2rc[]
        config.add_section('cam2world')
        config.set('cam2world', 'f2rc', str(data.xmlParser.f2rc))
        # end::f2rc[]

        # tag::cam2world[]
        cam2worldMatrix_str = ' '.join(
            map(str, data.cameraParams.cam2worldMatrix))
        config.set('cam2world', 'cam2worldMatrix', cam2worldMatrix_str)
        # end::cam2world[]

        config.add_section('maps')
        for mapDesc in mapdescs:
            config.set('maps', mapDesc.tag, mapDesc.filename)

        # Write the configuration to the .ini file
        config.write(metafile)


def writeFrame(visionary_type: str, data: Data, file_prefix: str = ""):

    frame_number = data.depthmap.frameNumber
    width = data.cameraParams.width
    height = data.cameraParams.height

    frame_prefix = str(frame_number)

    mapdescs = []

    if visionary_type == 'Visionary-T Mini':
        # tag::visionary_t_mini_maps[]
        # intensity
        intensity_data = np.array(
            data.depthmap.intensity, dtype=np.uint16).reshape((height, width))
        cv2.imwrite(file_prefix + frame_prefix + "-int.png",
                    intensity_data, [cv2.IMWRITE_PNG_COMPRESSION, 0])
        tagAndName = TagAndName("int", frame_prefix + "-int.png")
        mapdescs.append(tagAndName)

        # distance
        distance_data = np.array(
            data.depthmap.distance, dtype=np.uint16).reshape((height, width))
        cv2.imwrite(file_prefix + frame_prefix + "-dist.png",
                    distance_data, [cv2.IMWRITE_PNG_COMPRESSION, 0])
        tagAndName = TagAndName("dist", frame_prefix + "-dist.png")
        mapdescs.append(tagAndName)

        # confidence
        confidence_data = np.array(
            data.depthmap.confidence, dtype=np.uint16).reshape((height, width))
        cv2.imwrite(file_prefix + frame_prefix + "-conf.png",
                    confidence_data, [cv2.IMWRITE_PNG_COMPRESSION, 0])
        tagAndName = TagAndName("conf", frame_prefix + "-conf.png")
        mapdescs.append(tagAndName)
        # end::visionary_t_mini_maps[]

    elif visionary_type == 'Visionary-S':
        # tag::visionary_s_maps[]
        # rgba
        rgba_data = np.uint32(np.reshape(data.depthmap.intensity, (512, 640)))
        rgba_data = np.frombuffer(rgba_data, np.uint8)
        rgba_data = np.reshape(rgba_data, (512, 640, 4))
        bgra_data = cv2.cvtColor(rgba_data, cv2.COLOR_RGBA2BGRA)
        cv2.imwrite(file_prefix + frame_prefix + "-bgra.png",
                    bgra_data, [cv2.IMWRITE_PNG_COMPRESSION, 0])
        tagAndName = TagAndName("bgra", frame_prefix + "-bgra.png")
        mapdescs.append(tagAndName)

        # z
        zmap_data = np.array(
            data.depthmap.distance, dtype=np.uint16).reshape((height, width))
        cv2.imwrite(file_prefix + frame_prefix + "-z.png",
                    zmap_data, [cv2.IMWRITE_PNG_COMPRESSION, 0])
        tagAndName = TagAndName("z", frame_prefix + "-z.png")
        mapdescs.append(tagAndName)

        # state
        state_data = np.array(data.depthmap.confidence,
                              dtype=np.uint16).reshape((height, width))
        cv2.imwrite(file_prefix + frame_prefix + "-state.png",
                    state_data, [cv2.IMWRITE_PNG_COMPRESSION, 0])
        tagAndName = TagAndName("state", frame_prefix + "-state.png")
        mapdescs.append(tagAndName)
        # end::visionary_s_maps[]

    writeMeta(visionary_type, data, file_prefix +
              frame_prefix + ".ini", mapdescs)
