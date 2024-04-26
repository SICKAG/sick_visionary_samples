//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include <iostream>
#include <memory>
#include <sstream>

#include "CoLaParameterReader.h"
#include "CoLaParameterWriter.h"
#include <VisionaryControl.h>
#include <VisionaryType.h>

#include "exitcodes.h"

// tag::writeEeprom[]
int writeEeprom(std::shared_ptr<visionary::VisionaryControl> visionaryControl)
{
  using namespace visionary;
  CoLaCommand writeEepromCommand = CoLaParameterWriter(CoLaCommandType::METHOD_INVOCATION, "mEEwriteall").build();
  CoLaCommand writeEepromCommandResponse = visionaryControl->sendCommand(writeEepromCommand);
  bool        result                     = CoLaParameterReader(writeEepromCommandResponse).readBool();
  return result;
}
// end::writeEeprom[]

static ExitCode runSavePermanentlyDemo(visionary::VisionaryType visionaryType,
                                       const std::string&       ipAddress,
                                       bool                     restoreValues)
{
  using namespace visionary;
  std::shared_ptr<VisionaryControl> visionaryControl = std::make_shared<VisionaryControl>(visionaryType);
  if (!visionaryControl->open(ipAddress))
  {
    std::printf("Failed to open control connection to device.\n");
    return ExitCode::eCommunicationError;
  }
  if (!visionaryControl->login(IAuthentication::UserLevel::AUTHORIZED_CLIENT, "CLIENT"))
  {
    std::printf("Failed to log into the device.\n");
    return ExitCode::eAuthenticationError;
  }

  if (visionaryType.toString() == "Visionary-S")
  {
    if (!restoreValues)
    {
      // read_integrationTime
      CoLaCommand getIntegrationTimeUsCommand =
        CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "integrationTimeUs").build();
      auto getIntegrationTimeUsResponse = visionaryControl->sendCommand(getIntegrationTimeUsCommand);
      auto integrationTimeUs            = CoLaParameterReader(getIntegrationTimeUsResponse).readUDInt();
      std::printf("Read integrationTimeUs: %d µs\n", integrationTimeUs);

      // set_integrationTime
      std::uint32_t newIntegrationTimeUs = 3000; // µs
      CoLaCommand   setIntegrationTimeUsCommand =
        CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "integrationTimeUs")
          .parameterUDInt(newIntegrationTimeUs)
          .build();
      auto setIntegrationTimeUsResponse = visionaryControl->sendCommand(setIntegrationTimeUsCommand);
      std::printf("Set integrationTimeUs to %d µs\n", newIntegrationTimeUs);

      // call writeEeprom to permanently save the changed parameters
      int result = writeEeprom(visionaryControl);
      if (result)
      {
        std::printf("Permanently changed IntegrationTimeUs to %d µs\n", newIntegrationTimeUs);
      }
      else
      {
        std::printf("Failed to save parameter permanently.");
      }
    }
    else
    {
      // tag::restore_default[]
      std::uint32_t defaultIntegrationTimeUs = 1000;
      CoLaCommand   setDefaultIntegrationTimeUsCommand =
        CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "integrationTimeUs")
          .parameterUDInt(defaultIntegrationTimeUs)
          .build();
      auto setDefaultIntegrationTimeUsResponse = visionaryControl->sendCommand(setDefaultIntegrationTimeUsCommand);
      std::printf("Set integrationTimeUs to %d µs\n", defaultIntegrationTimeUs);

      int result = writeEeprom(visionaryControl);
      if (result)
      {
        std::printf("Restored IntegrationTimeUs to default of %d µs\n", defaultIntegrationTimeUs);
      }
      else
      {
        std::printf("Failed to restore default value for IntegrationTimeUs.");
      }
      // end::restore_default[]
    }
  }

  else if (visionaryType.toString() == "Visionary-T_Mini")
  {
    if (!restoreValues)
    {
      // Read framePeriodUs
      CoLaCommand getFramePeriodUsCommand =
        CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "framePeriodUs").build();
      auto getFramePeriodUsResponse = visionaryControl->sendCommand(getFramePeriodUsCommand);
      auto framePeriodUs            = CoLaParameterReader(getFramePeriodUsResponse).readUDInt();
      std::printf("Read framePeriodUs: %d µs\n", framePeriodUs);

      // Set FramePeriodUS
      std::uint32_t new_frame_period_us     = 60000; // µs
      CoLaCommand   setFramePeriodUsCommand = CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "framePeriodUs")
                                              .parameterUDInt(new_frame_period_us)
                                              .build();
      auto setFramePeriodUsResponse = visionaryControl->sendCommand(setFramePeriodUsCommand);
      std::printf("Set FramePeriodUS to %d µs\n", new_frame_period_us);

      // Call writeEeprom to permanently save the changed parameters
      int result = writeEeprom(visionaryControl);
      if (result)
      {
        std::printf("Permanently changed FramePeriodUS to %d µs\n", new_frame_period_us);
      }
      else
      {
        std::printf("Failed to save parameter permanently.");
      }
    }
    else
    {
      // Restore original framePeriodUs
      std::uint32_t default_frame_period_us      = 40000; // µs
      CoLaCommand setDefaultFramePeriodUsCommand = CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "framePeriodUs")
                                                     .parameterUDInt(default_frame_period_us)
                                                     .build();
      auto setDefaultFramePeriodUsResponse = visionaryControl->sendCommand(setDefaultFramePeriodUsCommand);
      std::printf("Set framePeriodUs to %d µs\n", default_frame_period_us);

      int result = writeEeprom(visionaryControl);
      if (result)
      {
        std::printf("Restored framePeriodUs to default of %d µs\n", default_frame_period_us);
      }
      else
      {
        std::printf("Failed to restore default value for FramePeriodUs.");
      }
    }
  }

  // tag::logout_and_disconnect[]
  if (!visionaryControl->logout())
  {
    std::printf("Failed to logout\n");
    return ExitCode::eAuthenticationError;
  }
  // end::logout_and_disconnect[]

  return ExitCode::eOk;
}

int main(int argc, char* argv[])
{
  std::string              deviceIpAddr("192.168.1.10");
  bool                     restoreValues = false;
  visionary::VisionaryType visionaryType(visionary::VisionaryType::eVisionaryTMini);
  bool                     showHelpAndExit = false;

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
      case 'd':
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
      case 'r':
      {
        std::string arg;
        argstream >> arg;
        restoreValues = (arg == "true" ? true : false);
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
    std::cout << "-h           show this help and exit" << std::endl;
    std::cout << "-i<IP>       connect to the device with IP address <IP>; default is 192.168.1.10" << std::endl;
    std::cout << "-d<device_type>    visionary product type; default is '" << visionaryType.toString() << "'\n";
    std::cout << "-r<restore values> Restores the permanetly changed value to its default value: "
              << (restoreValues ? "true" : "false") << "'\n";

    return static_cast<int>(exitCode);
  }

  exitCode = runSavePermanentlyDemo(visionaryType, deviceIpAddr, restoreValues);

  std::cout << "exit code " << static_cast<int>(exitCode) << std::endl;

  return static_cast<int>(exitCode);
}