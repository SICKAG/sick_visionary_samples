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

#include <sick_visionary_cpp_base/CoLaParameterReader.h>
#include <sick_visionary_cpp_base/CoLaParameterWriter.h>
#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <sick_visionary_cpp_base/VisionaryType.h>

#include "TimeStampHelper.h"
#include "exitcodes.h"

static ExitCode runNtpDemo(visionary::VisionaryType visionaryType,
                           const std::string&       ipAddress,
                           const std::string&       serverIp,
                           const uint16_t           serverPort)
{
  using namespace visionary;

  VisionaryControl visionaryControl(visionaryType);

  // Connect to devices control channel of the visionary device
  if (!visionaryControl.open(ipAddress))
  {
    std::fprintf(stderr, "Failed to open control connection to device\n");
    return ExitCode::eCommunicationError;
  }
  std::printf("Opened connection to Visionary device: %s\n", ipAddress.c_str());

  // Get device time before synchronization
  std::printf("Device time before time synchronization: ");
  printDeviceTime(visionaryControl);

  // Ask user about NTP Master
  std::string userInput;
  std::printf("\nWorking NTP Master is connected to the network? [Y/N]: ");
  std::getline(std::cin, userInput);

  // Convert to uppercase for consistency
  std::transform(userInput.begin(), userInput.end(), userInput.begin(), ::toupper);

  if (userInput == "Y" || userInput == "y")
  {
    // Login
    if (!visionaryControl.login(IAuthentication::UserLevel::AUTHORIZED_CLIENT, "CLIENT"))
    {
      std::fprintf(stderr, "Login failed\n");
      return ExitCode::eAuthenticationError;
    }

    // NTP settings
    CoLaCommand setNtpServerAddressCmnd = CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "ntpClientServerAddress")
                                            .parameterFlexString(serverIp)
                                            .build();
    CoLaCommand setNtpServerAddressCmndResponse = visionaryControl.sendCommand(setNtpServerAddressCmnd);
    if (setNtpServerAddressCmndResponse.getError() != CoLaError::OK)
    {
      std::fprintf(stderr, "Set NTP server address failed.\n");
      return ExitCode::eParamError;
    }
    else
    {
      std::printf("Set ntpClientServerAddress\n");
    }

    /// Set NTP server port
    CoLaCommand setNtpServerPortCmnd =
      CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "ntpClientServerPort").parameterUInt(serverPort).build();
    CoLaCommand setNtpServerPortCmndResponse = visionaryControl.sendCommand(setNtpServerPortCmnd);
    if (setNtpServerPortCmndResponse.getError() != CoLaError::OK)
    {
      std::fprintf(stderr, "Set NTP server port failed\n");
      return ExitCode::eParamError;
    }
    else
    {
      std::printf("Set ntpClientServerPort\n");
    }

    /// Enable NTP
    CoLaCommand enableNtpCommand = CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "timeSyncMode")
                                     .parameterUSInt(1)
                                     .build(); // 0 = NONE, 1 = NTP, 2 = PTP
    CoLaCommand enableNtpCommandResponse = visionaryControl.sendCommand(enableNtpCommand);
    if (enableNtpCommandResponse.getError() != CoLaError::OK)
    {
      std::fprintf(stderr, "Enable NTP time sync failed\n");
      return ExitCode::eParamError;
    }
    else
    {
      std::printf("Set timeSyncMode to NTP\n");
    }
    visionaryControl.logout();

    std::printf("Sleep for 5 seconds.\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));

    // Get device time after synchronization
    std::printf("Device time after time synchronization\n");
    printDeviceTime(visionaryControl);
  }
  
  /// Disable NTP
  if (!visionaryControl.login(IAuthentication::UserLevel::AUTHORIZED_CLIENT, "CLIENT"))
  {
    std::fprintf(stderr, "Login failed\n");
    return ExitCode::eAuthenticationError;
  }
  CoLaCommand disableNtpCommand =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "timeSyncMode").parameterUSInt(0).build();
  CoLaCommand disableNtpCommandResponse = visionaryControl.sendCommand(disableNtpCommand);
  if (disableNtpCommandResponse.getError() != CoLaError::OK)
  {
    std::fprintf(stderr,"Disable NTP time sync failed\n");
    return ExitCode::eParamError;
  }
  else
  {
    std::printf("Disabled NTP timeSyncMode\n");
  }
  
  visionaryControl.logout();
  visionaryControl.close();
  std::printf("Logout and closed connection.\n");
  return ExitCode::eOk;
}

int main(int argc, char* argv[])
{
  std::string   deviceIpAddr("192.168.1.10");
  std::string   serverIpAddr("192.168.136.100");
  std::uint16_t serverPort{123};

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
      case 's':
        argstream >> serverIpAddr;
        break;
      case 'p':
        argstream >> serverPort;
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
    std::cout << "-s<sIP>     connect to the NTP server with IP address <sIP>; default is " << serverIpAddr << "\n";
    std::cout << "-p<Prt>     connect to the NTP server with port <Prt>; default is " << serverPort << "\n";

    return static_cast<int>(exitCode);
  }

  exitCode = runNtpDemo(visionaryType, deviceIpAddr, serverIpAddr, serverPort);

  std::cout << "exit code " << static_cast<int>(exitCode) << "\n";

  return static_cast<int>(exitCode);
}
