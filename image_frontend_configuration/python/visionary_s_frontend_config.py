#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse
import struct
import time

from base.python.Control import Control
from base.python.Usertypes import AcquisitionModeStereo
from shared.python.devices_config import get_device_config


def run_configure_frontend_demo(ip_address: str, cola_protocol: str, control_port: int):
    # tag::connect_and_login[]
    device_control = Control(ip_address, cola_protocol, control_port)
    device_control.open()
    device_control.login(Control.USERLEVEL_AUTH_CLIENT, "CLIENT")
    # end::connect_and_login[]

    # -----------------------------------------------
    # This section demonstrates how to use the auto exposure functions by invoking the method
    # 'TriggerAutoExposureParameterized'. It shows the effect that auto exposure has on the integration time.
    # Additionally it shows how the region of interest (ROI) can be set.
    # NOTE: The sample is based on the AcquisitionModeStereo = NORMAL.

    # tag::set_acquisition_mode[]
    new_acquisition_mode_stereo = AcquisitionModeStereo.NORMAL
    device_control.setAcquisitionModeStereo(new_acquisition_mode_stereo.value)

    get_acquisition_mode_stereo = device_control.getAcquisitionModeStereo()
    acquisition_mode_stereo = AcquisitionModeStereo(
        get_acquisition_mode_stereo)
    print(f"\nRead AcquisitionModeStereo: {acquisition_mode_stereo.name}")
    # end::set_acquisition_mode[]

    # tag::set_ROI[]
    left = 160
    right = 480
    top = 128
    bottom = 384
    device_control.setAutoExposure3DROI(left, right, top, bottom)
    device_control.setAutoExposureColorROI(left, right, top, bottom)
    # NOTE: The user is responisble to make sure that the region he sets the ROI to, is actually white.
    device_control.setAutoWhiteBalanceROI(left, right, top, bottom)
    # end::set_ROI[]

    # Read current integration time values (before auto exposure was triggered)
    # ATTENTION: This sample is based on the NORMAL acquisition mode; other modes may refer to other integration time
    # variables
    print("//-----------------------------------------------")
    print("Read integration time before autoexposure")
    integration_time = device_control.getIntegrationTimeUs()
    print(f"Read IntegrationTimeUS: {integration_time}")
    integration_time_us_color = device_control.getIntegrationTimeUsColor()
    print(f"Read IntegrationTimeUSColor: {integration_time_us_color}")

    # Info: For White Balance exists no SOPAS variable; the changes are done internally in the device and applied to
    # the image. If you open SOPAS and you are running this sample in parallel you can see how the image changes.

    # tag::invoke_autoExposure[]
    for i in range(3):
        auto_type = i
        auto_exposure_response = device_control.startAutoExposureParameterized(
            struct.pack(">HB", 1, auto_type))
        if not auto_exposure_response:
            print(
                f"ERROR: Invoking 'TriggerAutoExposureParameterized' fails! (autoExposureResponse: {auto_exposure_response}")
        # Wait until auto exposure method is finished
        auto_exp_param_running = True
        start_time = time.time()
        time_now = start_time
        while auto_exp_param_running:
            auto_exp_param_running = device_control.getAutoExposureParameterizedRunning()
            time_now = time.time()
            # 10 sec (time after auto exposure method should be finished)
            if (time_now - start_time) <= 10:
                time.sleep(1)
            else:
                print(
                    f"TIMEOUT: auto exposure function (Param: {auto_type}) needs longer than expected!")

    # end::invoke_autoExposure[]
    # Read changed integration time values (after auto exposure was triggered)
    print("//-----------------------------------------------")
    print("Read integration time after autoexposure (integration time changed indirectly by autoexposure)")
    integration_time = device_control.getIntegrationTimeUs()
    print(f"Read IntegrationTimeUS: {integration_time}")

    integration_time_us_color = device_control.getIntegrationTimeUsColor()
    print(f"Read IntegrationTimeUSColor: {integration_time_us_color}")

    # -----------------------------------------------
    # This section shows how to change the integration time directly
    print("//-----------------------------------------------")
    print("Section: Set integration time directly")

    # tag::read_integrationTime[]
    integration_time = device_control.getIntegrationTimeUs()
    print(f"Read IntegrationTimeUS: {integration_time}")
    # end::read_integrationTime[]

    # tag::set_integrationTime[]
    device_control.setIntegrationTimeUs(3000)
    integration_time = device_control.getIntegrationTimeUs()
    print(f"Set IntegrationTimeUS: {integration_time}")
    # end::set_integrationTime[]
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

    cola_protocol, control_port, _ = get_device_config("Visionary-S")

    run_configure_frontend_demo(args.ip_address, cola_protocol, control_port)
