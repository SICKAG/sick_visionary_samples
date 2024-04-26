#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

from dataclasses import dataclass
from base.python.Usertypes import FrontendMode, InputFunctionType, IOFunctionType
from base.python.Control import Control
from .ioports import readDioFunction, writeDioFunction, DioPortNames


@dataclass
class Configuration:
    frontend_mode: FrontendMode = None
    trigger_in_fct: InputFunctionType = None
    trigger_in_fct_2: IOFunctionType = None
    busy_out_fct: IOFunctionType = None

    def __str__(self):
        return (f"\n\tfrontend_mode={FrontendMode(self.frontend_mode).name if self.frontend_mode is not None else 'None'},\n"
                f"\ttrigger_in_fct={InputFunctionType(self.trigger_in_fct).name if self.trigger_in_fct is not None else 'None'},\n"
                f"\ttrigger_in_fct_2={IOFunctionType(self.trigger_in_fct_2).name if self.trigger_in_fct_2 is not None else 'None'},\n"
                f"\tbusy_out_fct={IOFunctionType(self.busy_out_fct).name if self.busy_out_fct is not None else 'None'}\n"
                f")"
                )


def read_configuration(device_control: Control, port_names: DioPortNames) -> Configuration:
    configuration = Configuration()
    configuration.frontend_mode = device_control.getFrontendModeEnum()

    if port_names.trigger_in_name:
        configuration.trigger_in_fct = readDioFunction(
            device_control, port_names.trigger_in_name)

    if port_names.busy_out_name:
        configuration.busy_out_fct = readDioFunction(
            device_control, port_names.busy_out_name)

    return configuration


def write_configuration(device_control: Control, ports: DioPortNames, new_config: Configuration):
    # write frontend mode
    device_control.setFrontendMode(new_config.frontend_mode)
    if ports.trigger_in_name:
        # write I/O ports
        writeDioFunction(device_control, ports.trigger_in_name, new_config)
    elif ports.busy_out_name:
        writeDioFunction(device_control, ports.trigger_in_name, new_config)
