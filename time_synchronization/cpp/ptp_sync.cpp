//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <string>

#include <iostream>
#include <sstream>
#include <thread>

#include <sick_visionary_cpp_base/CoLaParameterWriter.h>
#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <sick_visionary_cpp_base/VisionaryType.h>

#include "PtpHelpers.h"
#include "TimeStampHelper.h"
#include "exitcodes.h"

static ExitCode runPtpDemo(visionary::VisionaryType visionaryType, const std::string& ipAddress)
{
  using namespace visionary;

  VisionaryControl visionaryControl(visionaryType);

  // Connect to devices control channel of the visionary device
  if (!visionaryControl.open(ipAddress))
  {
    std::fprintf(stderr, "Open control connection failed.\n");
    return ExitCode::eCommunicationError;
  }
  std::printf("Opened connection to Visionary device: %s\n", ipAddress.c_str());

  // Get device time before synchronization
  std::printf("Device time before time synchronization: ");
  printDeviceTime(visionaryControl);

  // Read PTP state before enabling PTP
  std::printf("PTP State: %s\n", getPtpState(visionaryControl).c_str());

  // Ask user about PTP Master
  std::string userInput;
  std::printf("Working PTP Master is connected to the network? [Y/N]: ");
  std::getline(std::cin, userInput);

  // Convert to uppercase for consistency
  std::transform(userInput.begin(), userInput.end(), userInput.begin(), ::toupper);

  if (userInput == "Y" || userInput == "y")
  {
    // Login
    if (!visionaryControl.login(IAuthentication::UserLevel::AUTHORIZED_CLIENT, "CLIENT"))
    {
      std::fprintf(stderr, "Login failed.\n");
      return ExitCode::eAuthenticationError;
    }
    
    // PTP settings
    // Set device to PTP Slave
    CoLaCommand setPtpModeCommmand = CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "ptpMode")
                                       .parameterUSInt(2)
                                       .build(); // 0 = AUTO, 1 = MASTER, 2 = SLAVE
    CoLaCommand setPtpModeCommmandResponse = visionaryControl.sendCommand(setPtpModeCommmand);
    if (setPtpModeCommmandResponse.getError() != CoLaError::OK)
    {
      std::fprintf(stderr, "Set PTP Mode failed.\n");
      return ExitCode::eParamError;
    }
    else
    {
      std::printf("Set PTP Mode: SLAVE\n");
    }

    /// Enable PTP
    CoLaCommand enablePtpCommand =
      CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "timeSyncMode").parameterUSInt(2).build(); // 0 = NONE, 1 = Ptp, 2 = PTP 
    CoLaCommand enablePtpCommandResponse = visionaryControl.sendCommand(enablePtpCommand);
    if (enablePtpCommandResponse.getError() != CoLaError::OK)
    {
      std::fprintf(stderr, "Enable PTP time sync failed.\n");
      return ExitCode::eParamError;
    }
    else
    {
      std::printf("Enabled PTP (timeSyncMode)\n");
    }
    visionaryControl.logout();

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    std::printf("PTP State: %s\n", getPtpState(visionaryControl).c_str());

    std::printf("Waiting 5 seconds for the PTP state update.\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    
    // Get device time after synchronization
    std::printf("Device time after time synchronization\n");
    printDeviceTime(visionaryControl);
    }

    // Disable PTP
    if (!visionaryControl.login(IAuthentication::UserLevel::AUTHORIZED_CLIENT, "CLIENT"))
    {
      std::fprintf(stderr, "Login failed.\n");
      return ExitCode::eAuthenticationError;
    }
    CoLaCommand disablePtpCommand =
        CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "timeSyncMode").parameterUSInt(0).build();
    CoLaCommand disablePtpCommandResponse = visionaryControl.sendCommand(disablePtpCommand);
    if (disablePtpCommandResponse.getError() != CoLaError::OK)
    {
      std::fprintf(stderr, "Disable PTP time sync failed\n");
      return ExitCode::eParamError;
    }
    else
    {
      std::printf("Disabled PTP (timeSyncMode)\n");
    }

    visionaryControl.logout();
    visionaryControl.close();
    std::printf("Logout and closed connection.\n");
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
      default:
        showHelpAndExit = true;
        break;
    }
  }

  if (showHelpAndExit)
  {
    std::cout << argv[0] << " [option]*"
              << "\n";
    std::cout << "where option is one of"
              << "\n";
    std::cout << "-h          show this help and exit"
              << "\n";
    std::cout << "-i<IP>      connect to the device with IP address <IP>; default is " << deviceIpAddr << "\n";
    return static_cast<int>(exitCode);
  }

  exitCode = runPtpDemo(visionaryType, deviceIpAddr);

  std::cout << "exit code " << static_cast<int>(exitCode) << "\n";

  return static_cast<int>(exitCode);
}
