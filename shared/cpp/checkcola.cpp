//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include "checkcola.h"

#include <stdexcept>
#include <string>

#include <sick_visionary_cpp_base/CoLaCommand.h>
#include <sick_visionary_cpp_base/CoLaError.h>

namespace visionary {

void checkReadResponse(const CoLaCommand& response, const std::string& variableName)
{
  if (response.getError() != CoLaError::OK)
  {
    throw std::runtime_error("Failed to read " + variableName + ": " + decodeError(response.getError()));
  }
}

void checkWriteResponse(const CoLaCommand& response, const std::string& variableName)
{
  if (response.getError() != CoLaError::OK)
  {
    throw std::runtime_error("Failed to write " + variableName + ": " + decodeError(response.getError()));
  }
}

void checkInvokeResponse(const CoLaCommand& response, const std::string& methodName)
{
  if (response.getError() != CoLaError::OK)
  {
    throw std::runtime_error("Failed to invoke " + methodName + ": " + decodeError(response.getError()));
  }
}

} // namespace visionary
