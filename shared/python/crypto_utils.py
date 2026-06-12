# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

import hashlib
import hmac
import os

from Cryptodome.Cipher import AES


def calcSHA256Hash(data):
    """
    Calculate the SHA-256 hash of a given data.

    Parameters:
    data (str or bytes): The data to be hashed. If it's a string, it will be encoded to bytes using 'latin-1' encoding.

    Returns:
    bytes: The SHA-256 hash of the input data.
    """
    if isinstance(data, str):
        data = data.encode('latin-1')
    m = hashlib.sha256()
    m.update(data)
    return m.digest()


def encryptWithAES128(key, iv, data, sul_version: int):
    """
    Encrypts the given data using AES-128 encryption.

    Parameters:
    key (bytes): The encryption key. This should be a 16-byte string.
    iv (bytes): The initialization vector. This should be a 16-byte string.
    data (str or bytes): The data to be encrypted. If it's a string, it will be encoded to bytes using 'latin-1' encoding.
    sul_version (int): If SUL1 (Visionary-S), PKCS7 padding will be applied to the data before encryption.

    Returns:
    bytes: The encrypted data.
    """
    if isinstance(data, str):
        data = data.encode('latin-1')

    def pad_pkcs7(x, y): return x + (y - len(x) % y) * \
        chr(y - len(x) % y).encode("latin-1")
    # NO padding for SUL2 since new_salt is appended instead
    if sul_version == 1:
        data = pad_pkcs7(data, len(key))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encryptedNewPwdHash = cipher.encrypt(data)
    return encryptedNewPwdHash


def createEncryptedMessage(user_level_name: str, old_password: str, new_password: str, old_salt: str, sul_version: int):
    """
    Creates an encrypted message using the user's level name, old password, new password, old salt, and SUL version.

    Parameters:
    user_level_name (str): The user's level name.
    old_password (str): The user's old password.
    new_password (str): The user's new password.
    old_salt (str): The salt of the old password stored in the device.
    sul_version (int): The SUL version. If it's 2, a new salt is generated.

    Returns:
    bytes: The encrypted message which includes the HMAC data and the generated HMAC.
    """
    new_salt = ""
    if sul_version == 2:
        new_salt = ":" + os.urandom(16).decode('latin-1')
    old_password_str = user_level_name + ":SICK Sensor:" + old_password + old_salt
    old_password_hash = calcSHA256Hash(old_password_str)
    new_password_str = user_level_name + ":SICK Sensor:" + new_password + new_salt
    new_password_hash = calcSHA256Hash(new_password_str)
    # key is the first 16bytes of the oldPwHash
    key = old_password_hash[0:16]
    # iv is 16bytes of random data
    iv = os.urandom(16)
    encrypted_new_password_hash = encryptWithAES128(key, iv, new_password_hash + new_salt[1:17].encode(
        'latin-1'), sul_version)
    hmac_data = iv + encrypted_new_password_hash
    generated_hmac = hmac.new(
        old_password_hash, hmac_data, digestmod=hashlib.sha256).digest()
    bytes_to_send = hmac_data + generated_hmac
    return bytes_to_send
