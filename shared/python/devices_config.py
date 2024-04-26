#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

from typing import Tuple

def get_device_config(device_type: str) -> Tuple[str, int, int]:
    """
    This function returns the configuration details for a given device type.

    Parameters:
    device_type (str): The type of the device. It should be either "Visionary-S" or "Visionary-T Mini".

    Returns:
    Tuple[str, int, int]: A tuple containing the cola protocol (str), control port (int), and sul version (int) for the given device type.
    """
    device_types = {
        "Visionary-S": {"cola_protocol": "ColaB", "control_port": 2112, "sul_version": 1},
        "Visionary-T Mini": {"cola_protocol": "Cola2", "control_port": 2122, "sul_version": 2}
    }

    cola_protocol = device_types[device_type]["cola_protocol"]
    control_port = device_types[device_type]["control_port"]
    sul_version = device_types[device_type]["sul_version"]
    return cola_protocol, control_port, sul_version
