//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include "frontendmodes.h"

#include <stdexcept>

#include <sick_visionary_cpp_base/CoLaError.h>
#include <sick_visionary_cpp_base/CoLaParameterReader.h>
#include <sick_visionary_cpp_base/CoLaParameterWriter.h>

#include "checkcola.h"

namespace visionary {

FrontendMode readFrontendMode(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl)
{
  CoLaCommand getFrontendModeCommand  = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "frontendMode").build();
  CoLaCommand getFrontendModeResponse = rVisionaryControl->sendCommand(getFrontendModeCommand);

  checkReadResponse(getFrontendModeResponse, "frontendMode");

  CoLaParameterReader frontendModeReader(getFrontendModeResponse);
  const std::uint8_t  frontendMode = frontendModeReader.readUSInt();

  return FrontendMode(frontendMode);
}

void writeFrontendMode(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, FrontendMode mode)
{
  CoLaCommand setFrontendModeCommand = CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "frontendMode")
                                         .parameterUSInt(static_cast<std::uint8_t>(mode))
                                         .build();
  CoLaCommand setFrontendModeResponse = rVisionaryControl->sendCommand(setFrontendModeCommand);

  checkWriteResponse(setFrontendModeResponse, "frontendMode");
}

} // namespace visionary
