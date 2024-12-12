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

static ExitCode runConfigureFrontend(visionary::VisionaryType visionaryType, const std::string& ipAddress)
{
  // tag::connect_and_login[]
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
  // end::connect_and_login[]

  //-----------------------------------------------
  // Auto Exposure functions:
  // This section demonstrates how to use the auto exposure functions by invoking the method
  // 'TriggerAutoExposureParameterized'. It shows the effect that auto exposure has on the integration time.
  // Additionally it shows how the region of interest (ROI) can be set.
  // NOTE: The sample is based on the AcquisitionModeStereo = NORMAL. */
  std::printf("//-----------------------------------------------\n");
  std::printf("Change integration time indirectly by invoking auto exposure\n");

  // tag::set_acquisition_mode[]
  std::uint8_t acquisitionModeStereo = 0; // 0 = NORMAL
  CoLaCommand  setAcquisitionModeStereoCommand =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "acquisitionModeStereo")
      .parameterUSInt(acquisitionModeStereo)
      .build();
  CoLaCommand setAcquisitionModeStereoResponse = visionaryControl.sendCommand(setAcquisitionModeStereoCommand);
  // end::set_acquisition_mode[]

  // tag::set_ROI[]
  std::uint32_t left   = 160;
  std::uint32_t right  = 480;
  std::uint32_t top    = 128;
  std::uint32_t bottom = 384;

  // Set ROI for Auto Exposure 3D
  CoLaCommand setAutoExposureROICommand = CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "autoExposureROI")
                                            .parameterUDInt(left)
                                            .parameterUDInt(right)
                                            .parameterUDInt(top)
                                            .parameterUDInt(bottom)
                                            .build();
  CoLaCommand setAutoExposureROIResponse = visionaryControl.sendCommand(setAutoExposureROICommand);
  // end::set_ROI[]

  // Set ROI for Auto Exposure RGB
  CoLaCommand setAutoExposureColorROICommand =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "autoExposureColorROI")
      .parameterUDInt(left)
      .parameterUDInt(right)
      .parameterUDInt(top)
      .parameterUDInt(bottom)
      .build();
  CoLaCommand setAutoExposureColorROIResponse = visionaryControl.sendCommand(setAutoExposureColorROICommand);

  // Set ROI for Auto White Balance
  // NOTE: The user is responisble to make sure that the region he sets the ROI to, is actually white.
  CoLaCommand setAutoWhiteBalanceROICommand =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "autoWhiteBalanceROI")
      .parameterUDInt(left)
      .parameterUDInt(right)
      .parameterUDInt(top)
      .parameterUDInt(bottom)
      .build();
  CoLaCommand setAutoWhiteBalanceROIResponse = visionaryControl.sendCommand(setAutoWhiteBalanceROICommand);

  // Read current integration time values (before auto exposure was triggered)
  // ATTENTION: This sample is based on the NORMAL acquisition mode; other modes may refer to other integration time
  // variables
  CoLaCommand getIntegrationTimeUsCommand =
    CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "integrationTimeUs").build();
  CoLaCommand   getIntegrationTimeUsResponse = visionaryControl.sendCommand(getIntegrationTimeUsCommand);
  std::uint32_t integrationTimeUs            = CoLaParameterReader(getIntegrationTimeUsResponse).readUDInt();
  std::printf("Read integrationTimeUs = %d\n", integrationTimeUs);

  CoLaCommand getIntegrationTimeUsColorCommand =
    CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "integrationTimeUsColor").build();
  CoLaCommand   getIntegrationTimeUsColorResponse = visionaryControl.sendCommand(getIntegrationTimeUsColorCommand);
  std::uint32_t integrationTimeUsColor            = CoLaParameterReader(getIntegrationTimeUsColorResponse).readUDInt();
  std::printf("Read integrationTimeUsColor = %d\n", integrationTimeUsColor);

  // Info: For White Balance exists no SOPAS variable; the changes are done internally in the device and applied to
  // the image. If you open SOPAS and you are running this sample in parallel you can see how the image changes.

  // tag::invoke_autoExposure[]
  for (uint8_t autoType = 0; autoType < 3;
       autoType++) // 0 = Auto Exposure 3D, 1 = Auto Exposure RGB, 2 = Auto White Balance
  {
    std::printf("Invoke method 'TriggerAutoExposureParameterized' (Param: %d) ...\n", autoType);

    CoLaCommand invokeAutoExposureCommand =
      CoLaParameterWriter(CoLaCommandType::METHOD_INVOCATION, "TriggerAutoExposureParameterized")
        .parameterUInt(1)
        .parameterUSInt(autoType)
        .build();
    CoLaCommand autoExposureResponse = visionaryControl.sendCommand(invokeAutoExposureCommand);

    if (autoExposureResponse.getError() != CoLaError::OK)
    {
      std::printf("ERROR: Invoking 'TriggerAutoExposureParameterized' fails! (autoExposureResponse: %d)\n",
                  CoLaParameterReader(autoExposureResponse).readBool());
    }

    // Wait until auto exposure method is finished
    bool      autoExpParamRunning = true;
    long long startTime           = std::chrono::system_clock::now().time_since_epoch().count();
    long long timeNow             = startTime;
    while (autoExpParamRunning)
    {
      CoLaCommand getAutoExpParamRunningCommand =
        CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "autoExposureParameterizedRunning").build();
      CoLaCommand autoExpParamRunningResponse = visionaryControl.sendCommand(getAutoExpParamRunningCommand);
      autoExpParamRunning                     = CoLaParameterReader(autoExpParamRunningResponse).readBool();

      timeNow = std::chrono::system_clock::now().time_since_epoch().count();
      if ((timeNow - startTime)
          <= 10000000000) // 10 sec = 10 000 000 000 ns (time after auto exposure method should be finished)
      {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
      else
      {
        std::printf("TIMEOUT: auto exposure function (Param: %d) needs longer than expected!\n", autoType);
      }
    }
  }
  // end::invoke_autoExposure[]

  // Read changed integration time values (after auto exposure was triggered)
  getIntegrationTimeUsCommand  = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "integrationTimeUs").build();
  getIntegrationTimeUsResponse = visionaryControl.sendCommand(getIntegrationTimeUsCommand);
  integrationTimeUs            = CoLaParameterReader(getIntegrationTimeUsResponse).readUDInt();
  std::printf("Read integrationTimeUs = %d\n", integrationTimeUs);

  getIntegrationTimeUsColorCommand =
    CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "integrationTimeUsColor").build();
  getIntegrationTimeUsColorResponse = visionaryControl.sendCommand(getIntegrationTimeUsColorCommand);
  integrationTimeUsColor            = CoLaParameterReader(getIntegrationTimeUsColorResponse).readUDInt();
  std::printf("Read integrationTimeUsColor = %d\n", integrationTimeUsColor);

  //-----------------------------------------------
  // This section demonstrates how to set the integrationTime directly
  // ATTENTION: This sample is based on the NORMAL acquisition mode; other modes may refer to other integration time
  // variables
  std::printf("\n//-----------------------------------------------\n");
  std::printf("Set integration time directly\n");

  // tag::set_integrationTime[]
  std::uint32_t newIntegrationTimeUs = 2000;
  std::printf("Setting Integration time to %d\n", newIntegrationTimeUs);
  CoLaCommand setIntegrationTimeUsCommand = CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "integrationTimeUs")
                                              .parameterUDInt(newIntegrationTimeUs)
                                              .build();
  CoLaCommand setIntegrationTimeUsResponse = visionaryControl.sendCommand(setIntegrationTimeUsCommand);
  // end::set_integrationTime[]

  if (setIntegrationTimeUsResponse.getError() != CoLaError::OK)
  {
    std::printf("Failed to write the integration time\n");
    return ExitCode::eParamError;
  }
  else
  {
    // tag::read_integrationTime[]
    CoLaCommand getIntegrationTimeUsCommand =
      CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, "integrationTimeUs").build();
    getIntegrationTimeUsResponse = visionaryControl.sendCommand(getIntegrationTimeUsCommand);
    integrationTimeUs            = CoLaParameterReader(getIntegrationTimeUsResponse).readUDInt();
    std::printf("Read new integrationTimeUs = %d\n", integrationTimeUs);
    // end::read_integrationTime[]
  }

  //-----------------------------------------------
  // Logout from device after reading variables.
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
  visionary::VisionaryType visionaryType(visionary::VisionaryType::eVisionaryS);

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
