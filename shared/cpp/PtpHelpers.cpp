//
// Copyright (c) 2026 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include "PtpHelpers.h"

#include <sick_visionary_cpp_base/CoLaParameterReader.h>
#include <sick_visionary_cpp_base/CoLaParameterWriter.h>

const char* ptpStateToString(std::uint8_t state)
{
  switch (state)
  {
    case 0:
      return "INITIALIZING";
    case 1:
      return "FAULTY";
    case 2:
      return "DISABLED";
    case 3:
      return "LISTENING";
    case 4:
      return "PRE_MASTER";
    case 5:
      return "MASTER";
    case 6:
      return "PASSIVE";
    case 7:
      return "UNCALIBRATED";
    case 8:
      return "SLAVE";
    case 9:
      return "UNKNOWN";
    default:
      return "Invalid state";
  }
}

std::string getPtpState(visionary::VisionaryControl& visionaryControl)
{
  using namespace visionary;
  CoLaCommand getPtpStateCommand =
    CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "ptpState").build();
  CoLaCommand getPtpStateResponse = visionaryControl.sendCommand(getPtpStateCommand);
  if (getPtpStateResponse.getError() != CoLaError::OK)
  {
    return "Error: read failed";
  }

  const std::uint8_t ptpState = CoLaParameterReader(getPtpStateResponse).readUSInt();
  return ptpStateToString(ptpState);
}