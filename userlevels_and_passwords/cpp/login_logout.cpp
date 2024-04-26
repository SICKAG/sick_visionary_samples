//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <string>

#include <iostream>
#include <sstream>

#include <CoLaParameterReader.h>
#include <CoLaParameterWriter.h>
#include <VisionaryControl.h>
#include <VisionaryType.h>

#include "exitcodes.h"

static ExitCode runDemo(visionary::VisionaryType visionaryType, const std::string& ipAddress)
{
  using namespace visionary;

  VisionaryControl visionaryControl(visionaryType);

  //-----------------------------------------------
  // Connect to devices control channel of the visionary device
  // tag::control_connection[]
  if (!visionaryControl.open(ipAddress))
  {
    std::fprintf(stderr, "Failed to open control connection to device.\n");
    return ExitCode::eCommunicationError;
  }
  std::fprintf(stdout, "Opened connection to the Visionary device %s\n", ipAddress.c_str());
  // end::control_connection[]

  // Initially read the variable "SysTemperatureWarningMargin" and store its original value.
  // tag::read_variable[]
  CoLaCommand getWarnMargin =
    CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "SysTemperatureWarningMargin").build();
  CoLaCommand getWarnMarginResponse = visionaryControl.sendCommand(getWarnMargin);
  // end::read_variable[]
  if (getWarnMarginResponse.getError() != CoLaError::OK)
  {
    std::fprintf(
      stderr, "Failure when initially reading SysTemperatureWarningMargin: %d\n", getWarnMarginResponse.getError());
    return ExitCode::eParamError;
  }
  std::int16_t originalWarnMargin = CoLaParameterReader(getWarnMarginResponse).readInt();
  std::fprintf(stdout, "Current SysTemperatureWarningMargin: %d°C\n", originalWarnMargin);

  // This section demonstrates what would happen if there is an attempt to write a variable which needs SERVICE access
  // level - but without any login. It is expected, that a CoLaError is reported, actually VARIABLE_WRITE_ACCESS_DENIED
  // is expected to occur in this case.
  // tag::write_variable[]
  CoLaCommand setWarnMargin = CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "SysTemperatureWarningMargin")
                                .parameterInt(originalWarnMargin - 1)
                                .build();
  CoLaCommand setWarnMarginResponse = visionaryControl.sendCommand(setWarnMargin);
  // end::write_variable[]
  if (setWarnMarginResponse.getError() != CoLaError::OK)
  {
    if (setWarnMarginResponse.getError() == CoLaError::VARIABLE_WRITE_ACCESS_DENIED)
    {
      std::fprintf(stdout,
                   "Without login, the variable SysTemperatureWarningMargin could not be written as expected\n");
    }
    else
    {
      std::fprintf(
        stderr, "Unexpected failure when writing SysTemperatureWarningMargin: %d\n", setWarnMarginResponse.getError());
      return ExitCode::eParamError;
    }
  }

  // Now we will login/authenticate as user level "SERVICE" to obtain the needed access rights to write
  // SysTemperatureWarningMargin variable.
  // tag::login[]
  const std::string defaultSecret = "CUST_SERV";
  if (!visionaryControl.login(IAuthentication::UserLevel::SERVICE, defaultSecret))
  {
    std::fprintf(stderr, "Failed to login - maybe the default password for SERVICE was changed\n");
    return ExitCode::eAuthenticationError;
  }
  // end::login[]
  std::fprintf(stdout, "Login with user level SERVICE was successful\n");

  // Now writing to SysTemperatureWarningMargin must succeed
  setWarnMarginResponse = visionaryControl.sendCommand(setWarnMargin);
  if (setWarnMarginResponse.getError() != CoLaError::OK)
  {
    std::fprintf(stderr,
                 "Failure when writing SysTemperatureWarningMargin with user level SERVICE: %d\n",
                 setWarnMarginResponse.getError());
    return ExitCode::eParamError;
  }
  else
  {
    std::fprintf(stdout, "Successfully written new value to variable SysTemperatureWarningMargin\n");
  }

  // Now read the SysTemperatureWarningMargin variable again to see the updated value
  getWarnMarginResponse = visionaryControl.sendCommand(getWarnMargin);
  if (getWarnMarginResponse.getError() != CoLaError::OK)
  {
    std::fprintf(stderr, "Failure when reading SysTemperatureWarningMargin: %d\n", getWarnMarginResponse.getError());
    return ExitCode::eParamError;
  }
  else
  {
    std::fprintf(
      stdout, "Updated SysTemperatureWarningMargin: %d°C\n", CoLaParameterReader(getWarnMarginResponse).readInt());
  }

  // Finally restore the original value for SysTemperatureWarningMargin variable
  setWarnMargin = CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "SysTemperatureWarningMargin")
                    .parameterInt(originalWarnMargin)
                    .build();
  setWarnMarginResponse = visionaryControl.sendCommand(setWarnMargin);
  if (setWarnMarginResponse.getError() != CoLaError::OK)
  {
    std::fprintf(stderr, "Failure when writing SysTemperatureWarningMargin: %d\n", setWarnMarginResponse.getError());
    return ExitCode::eParamError;
  }
  else
  {
    std::fprintf(stdout,
                 "Successfully written original value (%d°C) to variable SysTemperatureWarningMargin\n",
                 originalWarnMargin);
  }

  //tag::logout_and_disconnect[]
  visionaryControl.logout();
  visionaryControl.close();
  // end::logout_and_disconnect[]
  std::fprintf(stdout, "Logout user level SERVICE from device\n");
  std::fprintf(stdout, "Closed the connection to the Visionary device\n");

  return ExitCode::eOk;
}

int main(int argc, char* argv[])
{
  std::string              deviceIpAddr("192.168.1.10");
  visionary::VisionaryType visionaryType(visionary::VisionaryType::eVisionaryTMini);

  bool showHelpAndExit = false;

  ExitCode exitCode = ExitCode::eOk;

  for (int i = 1; i < argc; ++i)
  {
    std::istringstream argstream(argv[i]);

    if (argstream.get() != '-')
    {
      showHelpAndExit = true;
      exitCode        = ExitCode::eParamError;
      break;
    }
    switch (argstream.get())
    {
      case 'h':
        showHelpAndExit = true;
        break;
      case 'i':
        argstream >> deviceIpAddr;
        break;
      case 't':
      {
        std::string visionaryTypeName;
        argstream >> visionaryTypeName;
        try
        {
          visionaryType = visionary::VisionaryType::fromString(visionaryTypeName);
        }
        catch (const std::invalid_argument& e)
        {
          std::cerr << e.what() << ": '" << visionaryTypeName << "'" << std::endl;
          showHelpAndExit = true;
          exitCode        = ExitCode::eParamError;
        }
      }
      break;
      default:
        showHelpAndExit = true;
        break;
    }
  }

  if (showHelpAndExit)
  {
    std::cout << argv[0] << " [option]*" << std::endl;
    std::cout << "where option is one of" << std::endl;
    std::cout << "-h          show this help and exit" << std::endl;
    std::cout << "-i<IP>      connect to the device with IP address <IP>; default is " << deviceIpAddr << std::endl;
    std::cout << "-t<typename> visionary product type; default is '" << visionaryType.toString() << std::endl;

    std::cout << "Visionary product types:\n";
    for (const auto& name : visionary::VisionaryType::getNames())
    {
      std::cout << "  " << name << '\n';
    }

    return static_cast<int>(exitCode);
  }

  exitCode = runDemo(visionaryType, deviceIpAddr);

  std::cout << "exit code " << static_cast<int>(exitCode) << std::endl;

  return static_cast<int>(exitCode);
}
