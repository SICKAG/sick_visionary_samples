//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include <iostream>
#include <sstream>

#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <sick_visionary_cpp_base/VisionaryType.h>

#include "exitcodes.h"

static ExitCode runHelloSensor(visionary::VisionaryType visionaryType, const std::string& ipAddress)
{
  // tag::control_connection[]
  using namespace visionary;
  VisionaryControl visionaryControl(visionaryType);
  if (!visionaryControl.open(ipAddress))
  {
    std::printf("Failed to open control connection to device.\n");
    return ExitCode::eCommunicationError;
  }
  // end::control_connection[]

  // tag::get_deviceIdent[]
  DeviceIdent deviceIdent = visionaryControl.getDeviceIdent();
  std::printf("Device Name: '%s', Device Version: '%s'\n", deviceIdent.name.c_str(), deviceIdent.version.c_str());
  // end::get_deviceIdent[]

  return ExitCode::eOk;
}

int main(int argc, char* argv[])
{
  /// Default values:
  /// IP:        "192.168.1.10"
  /// Type: "Visionary-T_Mini"

  std::string              deviceIpAddr("192.168.1.10");
  visionary::VisionaryType visionaryType(visionary::VisionaryType::eVisionaryTMini);

  bool     showHelpAndExit = false;
  ExitCode exitCode        = ExitCode::eOk;

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
    std::cout << argv[0] << " [option]*" << "\n";
    std::cout << "where option is one of" << "\n";
    std::cout << "-h           show this help and exit" << "\n";
    std::cout << "-i<IP>       connect to the device with IP address <IP>; default is 192.168.1.10" << "\n";
    std::cout << "-t<typename> visionary product type; default is '" << visionaryType.toString() << "\n";
    std::cout << "Visionary product types:\n";
    for (const auto& name : visionary::VisionaryType::getNames())
    {
      std::cout << "  " << name << '\n';
    }

    return static_cast<int>(exitCode);
  }

  exitCode = runHelloSensor(visionaryType, deviceIpAddr);

  std::cout << "exit code " << static_cast<int>(exitCode) << "\n";

  return static_cast<int>(exitCode);
}
