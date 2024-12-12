#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import argparse
import struct
import sys
import traceback
from typing import Tuple

from base.python.Control import Control
from base.python.Usertypes import UserLevel
from shared.python.devices_config import get_device_config

from .crypto_utils import createEncryptedMessage


def getChallenge(device_control: Control, sul_version: int, user_level: int) -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    """
    This function gets the challenge and salt from the device based on the provided SUL version and user level.

    Args:
      device_control (Control): An instance of the Control class for device control.
      sul_version (int): Secure User Level Version, either 1 or 2.
      user_level (int): The user level. This is used to generate the challenge if the SUL version is not 1.

    Returns:
      Tuple[Tuple[int, ...], Tuple[int, ...]]: A tuple containing the challenge and salt tuples.
      The salt is an empty tuple if the SUL version is 1.
    """
    challenge = ()
    salt = ()
    if sul_version == 1:
        rx = device_control.invokeMethod(b"GetChallenge")
        data = struct.unpack_from('>B16B', rx)
        status = data[0]
        challenge = data[1:]
    else:
        rx = device_control.invokeMethod(
            b"GetChallenge", struct.pack('>B', user_level))
        data = struct.unpack('>B16B16B', rx)
        status = data[0]
        challenge = data[1:17]
        salt = data[17:]
    return challenge, salt


def changePasswordForUserLevelLegacy(device_control: Control, user_level: UserLevel, old_password: str, new_password: str) -> bool:
    """
    This function changes the password for a specific user level on a visionary device using the legacy method.

    Args:
        device_control (Control): An instance of the Control class for device control.
        user_level (int): The user level for which the password needs to be changed.
        new_password (str): The new password that will replace the old one.

    Returns:
        bool: True if the password was successfully changed, False otherwise.
    """
    try:
        # tag::set_password_command[]
        device_control.changeUserLevelPassword(user_level.value, new_password)
        print(
            f"Changed legacy password hash for user level {user_level.name}. PASSWORD: {new_password}")
        return True
        # end::set_password_command[]
    except Exception as e:
        print(e)
        return False


def changePasswordForUserLevelSecure(device_control: Control, user_level: UserLevel, old_password: str, new_password: str, sul_version: int) -> bool:
    """
    This function changes the password for a given user level on a device.

    Parameters:
    device_control (Control): The control interface for the device.
    user_level (UserLevel): The user level for which the password is to be changed.
    old_password (str): The old password.
    new_password (str): The new password.
    sul_version (int): The version of the Secure User Level (SUL) protocol to use.

    Returns:
    bool: True if the password was changed successfully, False otherwise.
    """
    # tag::change_password_command[]
    # get challenge from device
    challenge, salt = getChallenge(
        device_control, sul_version, user_level.value)
    # create the old salt string as specified in the documentation
    old_salt_str = '' if not salt else ":" + bytes(salt).decode("latin-1")
    # create an encrypted message from the old password, the new password, the user level and the old salt
    encrypted_message = createEncryptedMessage(user_level.name, old_password,
                                               new_password, old_salt_str, sul_version)
    try:
        # Write the packed byte struct and call the Method ChangePassword
        device_control.invokeMethod(b'ChangePassword', struct.pack(">H", len(
            encrypted_message)) + encrypted_message + struct.pack('>B', user_level.value))
        print(
            f"Changed secure hash for user level {user_level.name}. PASSWORD: {new_password}")
        return True
    # end::change_password_command[]
    except Exception as e:
        print(e)
        traceback.print_exc()
        return False


def changePasswordForUserLevel(device_control: Control, user_level: UserLevel, old_password: str, new_password: str, device_type: str):
    """
    Changes the password for a given user level on a specific device.

    Parameters:
    device_control (Control): The control object for the device.
    user_level (UserLevel): The user level for which the password needs to be changed.
    old_password (str): The old password.
    new_password (str): The new password.
    device_type (str): The type of the device.

    Returns:
    bool: True if the password change was successful, False otherwise.
    """
    # check if device is SUL1/2 or Legacy and call the correct functions for password change
    if device_type == "Visionary-T Mini":
        return changePasswordForUserLevelSecure(
            device_control, user_level, old_password, new_password, sul_version=2)
    # for Visionary-S we have to change the password using the legacy method and the secure method using SUL1
    else:
        return changePasswordForUserLevelLegacy(
            device_control, user_level, old_password, new_password) and changePasswordForUserLevelSecure(
            device_control, user_level, old_password, new_password, sul_version=1)


def runChangePasswordDemo(ip_address: str, cola_protocol: str, control_port: int, device_type: str,
                          sul_version: int, user_level: UserLevel, old_password: str, new_password: str):

    # tag::control_connection[]
    device_control = Control(ip_address, cola_protocol, control_port)
    device_control.open()
    # end::control_connection[]

    # tag::login_old_password[]
    device_control.login(user_level.value, old_password)
    # end::login_old_password[]
    print(
        f"Successful login: Userlvl: {user_level.name} | Password {old_password}\n")

    # tag::change_password[]
    if changePasswordForUserLevel(device_control, user_level, old_password, new_password, device_type):
        device_control.logout()
    else:
        print("Failed to change password.")
        device_control.close()
        sys.exit()
    # end::change_password[]

    # We try to login to the userlevel with the old password.
    # We expect an error to occur since we changed the password.
    # tag::wrong_password[]
    try:
        print("\n1. Login with old password.")
        device_control.login(user_level.value, old_password)
    except Exception as e:
        print(
            f"Failed login: Userlvl:{user_level.name} | Password:{old_password}\n")
    # end::wrong_password[]

    # tag::new_password_login[]
    print("2. Login with new password.")
    device_control.login(user_level.value, new_password)
    print(
        f"Successful login: Userlvl:{user_level.name} | Password:{new_password}\n")
    # end::new_password_login[]

    # tag::reset_password[]
    print("Reset to default password:")
    if changePasswordForUserLevel(device_control, user_level, new_password, old_password, device_type):
        print("Resetting password succeeded\n")
    else:
        print("Failed to reset password.")
    # end::reset_password[]

    # tag::logout_and_close[]
    device_control.logout()
    device_control.close()
    # end::logout_and_close[]
    print(f"Logout user level {user_level.name} from device")
    print("Closed the connection to the Visionary device")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="This script demonstrates how to change the device password.")
    parser.add_argument('-i', '--ip_address', required=False, type=str,
                        default="192.168.1.10", help="The ip address of the device.")
    parser.add_argument('-t', '--type', required=False, type=str,
                        default="Visionary-T Mini", choices=["Visionary-S", "Visionary-T Mini"],
                        help="Visionary product type.")
    parser.add_argument('-u', '--user_level', required=False, type=str,
                        default="Service", choices=["Run", "Operator", "Maintenance", "AuthorizedClient", "Service"],
                        help="Read/write variable or method invocation depends on the least user level")
    parser.add_argument('-o', '--old_password', required=False, type=str,
                        default="CUST_SERV", help="The current user level password. Default CUST_SERV for user level Service")
    parser.add_argument('-n', '--new_password', required=False, type=str,
                        default="CUST_SERV_1", help="The new password for the current user level.")
    args = parser.parse_args()

    cola_protocol, control_port, sul_version = get_device_config(args.type)

    user_level: UserLevel = UserLevel[args.user_level]

    runChangePasswordDemo(args.ip_address, cola_protocol, control_port, args.type,
                          sul_version, user_level, args.old_password, args.new_password)
