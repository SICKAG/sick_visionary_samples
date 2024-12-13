//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include <chrono>
#include <iostream>
#include <sstream>
#include <thread>

#include <sick_visionary_cpp_base/CoLaParameterReader.h>
#include <sick_visionary_cpp_base/CoLaParameterWriter.h>
#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <sick_visionary_cpp_base/VisionaryType.h>

#include "exitcodes.h"
#include "usertypes.h"

static ExitCode runConfigureFrontend(visionary::VisionaryType visionaryType, const std::string& ipAddress)
{
  using namespace visionary;
  VisionaryControl visionaryControl(visionaryType);
  if (!visionaryControl.open(ipAddress))
  {
    std::printf("Failed to open control connection to device.\n");
    return ExitCode::eCommunicationError;
  }
  if (!visionaryControl.login(IAuthentication::UserLevel::AUTHORIZED_CLIENT, "CLIENT"))
  {
    std::printf("Failed to log into the device.\n");
    return ExitCode::eAuthenticationError;
  }

  //-----------------------------------------------
  // Configure Binning Option
  std::printf("//-----------------------------------------------\n");
  std::printf("//Section: Configure binningOption\n");

  // tag::set_binningOption[]
  UserTypes::BinningOption newBinningOpiton(1);
  CoLaCommand              setBinningOptionCommand =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "binningOption").parameterUSInt(newBinningOpiton).build();
  CoLaCommand setBinningOptionResponse = visionaryControl.sendCommand(setBinningOptionCommand);
  std::printf("Set binningOption = %s\n", newBinningOpiton.to_str().c_str());
  // end::set_binningOption[]
  if (setBinningOptionResponse.getError() != CoLaError::OK)
  {
    std::printf("Failed to set binningOption\n");
    return ExitCode::eParamError;
  }
  else
  {
    // tag::read_binningOption[]
    std::printf("Successfully set binningOption\n");
    CoLaCommand  getBinningOption = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "binningOption").build();
    CoLaCommand  getBinningOptionResponse  = visionaryControl.sendCommand(getBinningOption);
    std::uint8_t binningOptionEnum         = CoLaParameterReader(getBinningOptionResponse).readUSInt();
    UserTypes::BinningOption binningOption = UserTypes::BinningOption(binningOptionEnum);
    std::printf("Read binningOption = %s\n", binningOption.to_str().c_str());
    // end::read_binningOption[]
  }

  //-----------------------------------------------
  // Set Frame Period

  std::printf("//-----------------------------------------------\n");
  std::printf("// Section: Configure framePeriodUs\n");

  // tag::set_framePeriod[]
  std::uint32_t newFramePeriodUs = 60000;
  std::printf("Set FramePeriodUs = %d\n", newFramePeriodUs);
  CoLaCommand setFramePeriodUsCommand =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "framePeriodUs").parameterUDInt(newFramePeriodUs).build();
  CoLaCommand setFramePeriodUsResponse = visionaryControl.sendCommand(setFramePeriodUsCommand);
  // end::set_framePeriod[]
  if (setFramePeriodUsResponse.getError() != CoLaError::OK)
  {
    std::printf("Failed to set framePeriodUs\n");
    return ExitCode::eParamError;
  }
  else
  {
    // tag::read_framePeriod[]
    std::printf("Successfully set framePeriodUs\n");
    CoLaCommand getFramePeriodUsCommand  = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "framePeriodUs").build();
    CoLaCommand getFramePeriodUsResponse = visionaryControl.sendCommand(getFramePeriodUsCommand);
    std::uint32_t FramePeriodUs          = CoLaParameterReader(getFramePeriodUsResponse).readUDInt();
    std::printf("Read FramePeriodUs = %d\n", FramePeriodUs);
    // end::read_framePeriod[]
  }

  //-----------------------------------------------
  // tag::logout_and_disconnect[]
  if (!visionaryControl.logout())
  {
    std::printf("Failed to logout\n");
    return ExitCode::eAuthenticationError;
  }
  // end::logout_and_disconnect[]

  return ExitCode::eOk;
}

int main(int argc, char* argv[])
{
  /// Default values:
  /// IP:        "192.168.1.10"
  /// Type: "Visionary-S"

  std::string              deviceIpAddr("192.168.1.10");
  visionary::VisionaryType visionaryType(visionary::VisionaryType::eVisionaryTMini);

  bool showHelpAndExit   = false;
  bool executeExtTrigger = false;

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
    std::cout << argv[0] << " [option]*" << "\n";
    std::cout << "where option is one of" << "\n";
    std::cout << "-h           show this help and exit" << "\n";
    std::cout << "-i<IP>       connect to the device with IP address <IP>; default is 192.168.1.10" << "\n";

    return static_cast<int>(exitCode);
  }

  exitCode = runConfigureFrontend(visionaryType, deviceIpAddr);

  std::cout << "exit code " << static_cast<int>(exitCode) << "\n";

  return static_cast<int>(exitCode);
}
