#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import struct

from base.python.Usertypes import InputFunctionType, IOFunctionType


class DioPortNames:
    """
    Names of the used digital ports.

    The names of the ports used for the trigger and busy signal are stored in this struct.
    An empty string means that the port is not used.
    """

    def __init__(self, trigger_in_name: str = '', busy_out_name: str = ''):
        self.trigger_in_name = trigger_in_name
        self.busy_out_name = busy_out_name


def getInOutFunctionVarName(trigger_name: str) -> str:
    if trigger_name == "INOUT1":
        return "DIO1Fnc"
    elif trigger_name == "INOUT2":
        return "DIO2Fnc"
    elif trigger_name == "INOUT3":
        return "DIO3Fnc"
    elif trigger_name == "INOUT4":
        return "DIO4Fnc"
    elif trigger_name == "INOUT5":
        return "DIO5Fnc"
    elif trigger_name == "INOUT6":
        return "DIO6Fnc"


def getInFunctionVarName(trigger_name: str) -> str:
    if trigger_name == "SENS_IN1":
        return "SENS_IN1Func"
    elif trigger_name == "SENS_IN2":
        return "SENS_IN2Func"
    else:
        raise ValueError()


def readDioFunction(device_control, trigger_name):
    # try whether our name is an input port
    try:
        p_var_name = getInFunctionVarName(trigger_name)
        resp = device_control.readVariable(p_var_name.encode())
        input_function_type = struct.unpack('>B', resp)[0]
        return InputFunctionType(input_function_type)
    # if not, it must be an in/out port
    except ValueError:
        p_var_name = getInOutFunctionVarName(trigger_name)
        resp = device_control.readVariable(p_var_name.encode())
        io_function_type = struct.unpack('>B', resp)[0]
        return IOFunctionType(io_function_type)


def writeDioFunction(device_control, trigger_name, new_config):
    # try whether our name is an input port
    try:
        pVarName = getInFunctionVarName(trigger_name)
        device_control.writeVariable(pVarName.encode(), struct.pack(
            'B', new_config.trigger_in_fct.value))
    # if not, it must be an in/out port
    except ValueError:
        pVarName = getInOutFunctionVarName(trigger_name)
        device_control.writeVariable(pVarName.encode(), struct.pack(
            'B', new_config.trigger_in_fct_2.value))
