//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include "DecodeError.h"
#include <bitset>

/**
 * @brief Decodes an error code into a human-readable string.
 *
 * This function takes an error code and a device type as input, extracts the subsystem and error name from the error
 * code, and returns the corresponding error message from the appropriate dictionary.
 *
 * @param error_code The error code to decode. This is a 32-bit integer where different bits represent different pieces
 * of information about the error.
 * @param device_type The type of the device that generated the error. This is used to select the appropriate dictionary
 * for decoding the error message.
 *
 * @return A string containing the decoded error message.
 */
std::string decodeErrorCode(std::uint32_t error_code, std::string device_type)
{
  // Extract the subsystem and error name
  uint8_t  error_name = error_code & 0xFF;         // last 8 bits
  uint16_t sub_system = (error_code >> 8) & 0x3FF; // 10 bits before the last 8 bits

  if (device_type.find("Visionary-T Mini") != std::string::npos)
  {
    return ERROR_DICT_VISIONARY_T_MINI.at(sub_system).at(error_name);
  }
  else
  {
    return ERROR_DICT_VISIONARY_S.at(sub_system).at(error_name);
  }
}
