//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include <cinttypes>
#include <cstdint>
#include <iostream>
#include <sstream>

#include <CoLaParameterReader.h>
#include <CoLaParameterWriter.h>
#include <VisionaryControl.h>
#include <VisionaryType.h>

#include "exitcodes.h"

static ExitCode runSystemLog(visionary::VisionaryType visionaryType, const std::string& ipAddress)
{
  // tag::control_connection[]
  using namespace visionary;

  // Generate Visionary instance
  VisionaryControl visionaryControl(visionaryType);

  // Connect to devices control channel
  if (!visionaryControl.open(ipAddress))
  {
    std::printf("Failed to open control connection to device.\n");
    return ExitCode::eCommunicationError;
  }
  // end::control_connection[]

  //-----------------------------------------------
  // tag::build_and_send_command[]
  // Read info messages variable
  CoLaCommand getMessagesCommand = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "MSinfo").build();
  CoLaCommand messagesResponse   = visionaryControl.sendCommand(getMessagesCommand);
  if (messagesResponse.getError() != CoLaError::OK)
  {
    std::printf("Failed to read variable MSinfo\n");
    return ExitCode::eParamError;
  }
  // end::build_and_send_command[]

  // tag::parse_response[]
  // Read message array, length of array is always 25 items (see MSinfo in PDF).
  CoLaParameterReader reader(messagesResponse);
  for (int i = 0; i < 25; i++) // Read 25 items
  {
    std::uint32_t errorId    = reader.readUDInt();
    std::uint32_t errorState = reader.readUDInt();

    // Read ErrTimeType struct members for FirstTime
    std::uint16_t firstTime_PwrOnCount = reader.readUInt();
    std::uint32_t firstTime_OpSecs     = reader.readUDInt();
    std::uint32_t firstTime_TimeOccur  = reader.readUDInt();

    // Read ErrTimeType struct members for LastTime
    std::uint16_t lastTime_PwrOnCount = reader.readUInt();
    std::uint32_t lastTime_OpSecs     = reader.readUDInt();
    std::uint32_t lastTime_TimeOccur  = reader.readUDInt();

    std::uint16_t numberOccurrences = reader.readUInt();
    std::uint16_t errReserved       = reader.readUInt();
    std::string   extInfo           = reader.readFlexString();

    // Write all non-empty info messages to the console
    if (errorId != 0)
    {
      std::printf("Info message [0x%032" PRIx32 "], extInfo: %s, number of occurrences: %" PRIu16 "\n",
                  errorId,
                  extInfo.c_str(),
                  numberOccurrences);
    }
  }
  // end::parse_response[]

  // tag::control_disconnect[]
  visionaryControl.close();
  // end::control_disconnect[]
  return ExitCode::eOk;
}

int main(int argc, char* argv[])
{
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
    std::cout << "-d<device type> visionary product type; default is '" << visionaryType.toString() << std::endl;

    std::cout << "Visionary product types:\n";
    for (const auto& name : visionary::VisionaryType::getNames())
    {
      std::cout << "  " << name << '\n';
    }

    return static_cast<int>(exitCode);
  }

  exitCode = runSystemLog(visionaryType, deviceIpAddr);

  std::cout << "exit code " << static_cast<int>(exitCode) << std::endl;

  return static_cast<int>(exitCode);
}
