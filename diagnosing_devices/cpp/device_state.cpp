//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include <cinttypes>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

#include <sick_visionary_cpp_base/CoLaParameterReader.h>
#include <sick_visionary_cpp_base/CoLaParameterWriter.h>
#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <sick_visionary_cpp_base/VisionaryType.h>

#include "exitcodes.h"
#include "usertypes.h"

static ExitCode runSystemLog(visionary::VisionaryType visionaryType, const std::string& ipAddress)
{
  using namespace visionary;

  // Generate Visionary instance
  VisionaryControl visionaryControl(visionaryType);

  // Connect to devices control channel
  if (!visionaryControl.open(ipAddress))
  {
    std::printf("Failed to open control connection to device.\n");
    return ExitCode::eCommunicationError;
  }

  // tag::tempLvl_command[]
  // Read Temperature Level
  CoLaCommand getTempLvl         = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "TmpLvl").build();
  CoLaCommand getTempLvlResponse = visionaryControl.sendCommand(getTempLvl);
  // end::tempLvl_command[]
  // tag::read_tempLvl[]
  if (getTempLvlResponse.getError() != CoLaError::OK)
  {
    std::printf("Failed to read Temperature Level\n");
    return ExitCode::eParamError;
  }
  else
  {
    // returns Int enum of type ThreeLevels
    std::uint8_t           tmpLvlEnum = CoLaParameterReader(getTempLvlResponse).readUSInt();
    UserTypes::ThreeLevels tmpLvl     = UserTypes::ThreeLevels(tmpLvlEnum);
    std::printf("Read Temperature Level = %s\n", tmpLvl.to_string().c_str());
  }
  // end::read_tempLvl[]

  // Read system temperature parameter
  CoLaCommand getSysTemp = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "SysTemperatureCurrentValue").build();
  CoLaCommand sysTempResponse = visionaryControl.sendCommand(getSysTemp);
  if (sysTempResponse.getError() != CoLaError::OK)
  {
    std::printf("Failed to read System temperature\n");
    return ExitCode::eParamError;
  }
  else
  {
    std::int16_t sysTemp = CoLaParameterReader(sysTempResponse).readInt();
    std::printf("Read System temperature = %.1f degree Celsius\n", sysTemp / 10.0);
  }

  // tag::opVoltage_command[]
  // Read operating voltage status
  CoLaCommand getOpVol      = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "OpVoltageStatus").build();
  CoLaCommand opVolResponse = visionaryControl.sendCommand(getOpVol);
  // end::opVoltage_command[]
  // tag::read_opVoltage[]
  if (opVolResponse.getError() != CoLaError::OK)
  {
    std::printf("Failed to read Operating Voltage Status\n");
    return ExitCode::eParamError;
  }
  else
  {
    // returns Int enum of type ThreeLevels
    std::uint8_t           opVolEnum   = CoLaParameterReader(opVolResponse).readUSInt();
    UserTypes::ThreeLevels opVolStatus = UserTypes::ThreeLevels(opVolEnum);
    std::printf("Read Operating voltage status = %s\n", opVolStatus.to_string().c_str());
  }
  // end::read_opVoltage[]

  visionaryControl.close();
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
    std::cout << argv[0] << " [option]*" << "\n";
    std::cout << "where option is one of" << "\n";
    std::cout << "-h           show this help and exit" << "\n";
    std::cout << "-i<IP>       connect to the device with IP address <IP>; default is 192.168.1.10" << "\n";
    std::cout << "-d<device type> visionary product type; default is '" << visionaryType.toString() << "\n";

    std::cout << "Visionary product types:\n";
    for (const auto& name : visionary::VisionaryType::getNames())
    {
      std::cout << "  " << name << '\n';
    }

    return static_cast<int>(exitCode);
  }

  exitCode = runSystemLog(visionaryType, deviceIpAddr);

  std::cout << "exit code " << static_cast<int>(exitCode) << "\n";

  return static_cast<int>(exitCode);
}
