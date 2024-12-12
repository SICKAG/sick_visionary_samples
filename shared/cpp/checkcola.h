//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#ifndef SHARED_CHECKCOLA_H_INCLUDED
#define SHARED_CHECKCOLA_H_INCLUDED

#include <string>

#include <sick_visionary_cpp_base/CoLaCommand.h>

namespace visionary {

/// Checks the response of a CoLa read command.
///
/// \param[in] response      the response to check.
/// \param[in] variableName  the name of the variable that was read.
///
/// If the response indicates an error, a std::runtime_error is thrown.
void checkReadResponse(const CoLaCommand& response, const std::string& variableName);

/// Checks the response of a CoLa write command.
///
/// \param[in] response      the response to check.
/// \param[in] variableName  the name of the variable that was written.
///
/// If the response indicates an error, a std::runtime_error is thrown.
void checkWriteResponse(const CoLaCommand& response, const std::string& variableName);

/// Checks the response of a CoLa method invocation.
///
/// \param[in] response      the response to check.
/// \param[in] methodName    the name of the method that was invoked.
///
/// If the response indicates an error, a std::runtime_error is thrown.
void checkInvokeResponse(const CoLaCommand& response, const std::string& methodName);

} // namespace visionary

#endif // SHARED_CHECKCOLA_H_INCLUDED
