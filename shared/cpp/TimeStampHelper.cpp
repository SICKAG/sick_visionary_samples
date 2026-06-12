//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include "TimeStampHelper.h"
#include <sick_visionary_cpp_base/CoLaParameterReader.h>
#include <sick_visionary_cpp_base/CoLaParameterWriter.h>

ExitCode printDeviceTime(visionary::VisionaryControl& visionaryControl)
{
  using namespace visionary;
  // Get device time before synchronization
  CoLaCommand getDeviceTimeCmnd         = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "DeviceTime").build();
  CoLaCommand getDeviceTimeCmndResponse = visionaryControl.sendCommand(getDeviceTimeCmnd);
  if (getDeviceTimeCmndResponse.getError() != CoLaError::OK)
  {
    std::printf("Failed to get Device Time\n");
    return ExitCode::eParamError;
  }
  else
  {
    std::uint64_t deviceTime = CoLaParameterReader(getDeviceTimeCmndResponse).readULInt();
    // Convert milliseconds to seconds
    std::time_t timeInSeconds = deviceTime / 1000;

    // Convert to tm structure in UTC
    std::tm* tm = std::gmtime(&timeInSeconds);

    // Print the formatted date
    std::printf("Formatted date: %02d:%02d:%04d %02d:%02d:%02d\n",
                tm->tm_mday,
                tm->tm_mon + 1,
                tm->tm_year + 1900,
                tm->tm_hour,
                tm->tm_min,
                tm->tm_sec);
    return ExitCode::eOk;
  }
}