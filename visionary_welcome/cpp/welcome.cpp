//
// Copyright (c) 2023,2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>

#include <iostream>
#include <sstream>

#include <chrono>
#include <thread>

#include <sick_visionary_cpp_base/CoLaParameterWriter.h>
#include <sick_visionary_cpp_base/FrameGrabberBase.h>
#include <sick_visionary_cpp_base/PointCloudPlyWriter.h>
#include <sick_visionary_cpp_base/PointXYZ.h>
#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <sick_visionary_cpp_base/VisionaryType.h>

#include "exitcodes.h"
#include "framewrite.h"
#include "frontendmodes.h"

static ExitCode runWelcomeDemo(visionary::VisionaryType visionaryType, const std::string& ipAddress)
{
  using namespace visionary;
  std::shared_ptr<VisionaryControl> visionaryControl = std::make_shared<VisionaryControl>(visionaryType);

  if (!visionaryControl->open(ipAddress))
  {
    std::fprintf(stderr, "Failed to open control connection to device.\n");

    return ExitCode::eControlCommunicationError;
  }

  // Login to the device for access rights to certain methods
  visionaryControl->login(IAuthentication::UserLevel::SERVICE, "CUST_SERV");
  // Always stop the frontend before using stepAcquisition
  writeFrontendMode(visionaryControl, FrontendMode::eStopped);
  // Logout after configuration
  if (!visionaryControl->logout())
  {
    std::printf("Failed to logout\n");
    return ExitCode::eAuthenticationError;
  }

  // create a frame grabber suitable for the Visionary type used in visionaryControl
  auto pFrameGrabber = visionaryControl->createFrameGrabber();
  // the data handler pointer will later contain the frame data
  auto pDataHandler = visionaryControl->createDataHandler();

  // acquire a single snapshot
  if (!visionaryControl->stepAcquisition())
  {
    std::fprintf(stderr, "Failed to trigger a snapshot\n");

    return ExitCode::eControlCommunicationError;
  }

  // the snapshot has possibly already arrived, so parameter onlyNewer is false
  if (!pFrameGrabber->genGetNextFrame(pDataHandler, false, std::chrono::milliseconds(1200)))
  {
    std::fprintf(stderr, "Frame timeout for snapshot\n");

    return ExitCode::eFrameTimeout;
  }
  else
  {
    std::printf("Frame received in snapshot mode, frame #%" PRIu32 "\n", pDataHandler->getFrameNum());
    // write the frame to disk
    writeFrame(visionaryType, *pDataHandler, "");
    // Convert data to a point cloud
    std::vector<PointXYZ> pointCloud;
    pDataHandler->generatePointCloud(pointCloud);
    pDataHandler->transformPointCloud(pointCloud);
    // Write point cloud to PLY
    const std::string framePrefix  = std::to_string(pDataHandler->getFrameNum());
    std::string       plyFilePath  = framePrefix + "-pointcloud.ply";
    const char*       cPlyFilePath = plyFilePath.c_str();
    std::printf("Writing frame to %s\n", cPlyFilePath);
    if (visionaryType == VisionaryType::eVisionaryS)
      PointCloudPlyWriter::WriteFormatPLY(cPlyFilePath, pointCloud, pDataHandler->getRGBAMap(), true);
    else
      PointCloudPlyWriter::WriteFormatPLY(cPlyFilePath, pointCloud, pDataHandler->getIntensityMap(), true);
    std::printf("Finished writing frame to %s\n", cPlyFilePath);
  }

  // Another login to change frontend parameters
  if (!visionaryControl->login(IAuthentication::UserLevel::AUTHORIZED_CLIENT, "CLIENT"))
  {
    std::printf("Failed to log into the device.\n");
    return ExitCode::eAuthenticationError;
  }
  if (visionaryType.toString() == "Visionary-S")
  {
    // set_integrationTime
    CoLaCommand setIntegrationTimeUsCommand =
      CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "integrationTimeUs").parameterUDInt(3000).build();
    auto setIntegrationTimeUsResponse = visionaryControl->sendCommand(setIntegrationTimeUsCommand);
    std::cout << "Set integration time to 3000 micro seconds." << "\n";
  }
  else if (visionaryType.toString() == "Visionary-T_Mini")
  {
    // Set FramePeriodUS
    CoLaCommand setFramePeriodUsCommand =
      CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "framePeriodUs").parameterUDInt(60000).build();
    auto setFramePeriodUsResponse = visionaryControl->sendCommand(setFramePeriodUsCommand);
    std::cout << "Set frame period to 60000 micro seconds." << "\n";
  }

  if (!visionaryControl->logout())
  {
    std::printf("Failed to logout\n");
    return ExitCode::eAuthenticationError;
  }

  // acquire a single snapshot
  if (!visionaryControl->stepAcquisition())
  {
    std::fprintf(stderr, "Failed to trigger a snapshot\n");

    return ExitCode::eControlCommunicationError;
  }

  // the snapshot has possibly already arrived, so parameter onlyNewer is false
  if (!pFrameGrabber->genGetNextFrame(pDataHandler, false, std::chrono::milliseconds(2000)))
  {
    std::fprintf(stderr, "Frame timeout for snapshot\n");

    return ExitCode::eFrameTimeout;
  }
  else
  {
    std::printf("Frame received in snapshot mode, frame #%" PRIu32 "\n", pDataHandler->getFrameNum());
    // write the frame to disk
    writeFrame(visionaryType, *pDataHandler, "");
    // Convert data to a point cloud
    std::vector<PointXYZ> pointCloud;
    pDataHandler->generatePointCloud(pointCloud);
    pDataHandler->transformPointCloud(pointCloud);
    // Write point cloud to PLY
    const std::string framePrefix  = std::to_string(pDataHandler->getFrameNum());
    std::string       plyFilePath  = framePrefix + "-pointcloud.ply";
    const char*       cPlyFilePath = plyFilePath.c_str();
    std::printf("Writing frame to %s\n", cPlyFilePath);
    if (visionaryType == VisionaryType::eVisionaryS)
      PointCloudPlyWriter::WriteFormatPLY(cPlyFilePath, pointCloud, pDataHandler->getRGBAMap(), true);
    else
      PointCloudPlyWriter::WriteFormatPLY(cPlyFilePath, pointCloud, pDataHandler->getIntensityMap(), true);
    std::printf("Finished writing frame to %s\n", cPlyFilePath);
  }

  // Before exiting the sample we reset the frontendmode to "Continuous" and delete the framegrabber
  if (!visionaryControl->login(IAuthentication::UserLevel::AUTHORIZED_CLIENT, "CLIENT"))
  {
    std::printf("Failed to log into the device.\n");
    return ExitCode::eAuthenticationError;
  }
  
  writeFrontendMode(visionaryControl, FrontendMode::eContinuous);
  // delete the frame grabber
  pFrameGrabber.reset();

  visionaryControl->logout();
  visionaryControl->close();
  std::printf("Logout and close.\n");

  return ExitCode::eOk;
}

int main(int argc, char* argv[])
{
  std::string deviceIpAddr{"192.168.1.10"};
  std::string filePrefix{""};

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
          // NOLINTNEXTLINE(performance-avoid-endl)
          std::cerr << e.what() << ": '" << visionaryTypeName << "'" << std::endl;
          showHelpAndExit = true;
          exitCode        = ExitCode::eParamError;
        }
        break;
      }
      default:
        showHelpAndExit = true;
        break;
    }
  }

  if (showHelpAndExit)
  {
    std::cout << "\nUsage: " << argv[0] << " [option]*\n";

    std::cout << "where option is one of\n";
    std::cout << "-h              show this help and exit\n";
    std::cout << "-i<IP>          connect to the device with IP address <IP>; default is " << deviceIpAddr << '\n';
    std::cout << "-d<device type> visionary product type; default is '" << visionaryType.toString() << "'\n";

    std::cout << "\nVisionary product types:\n";
    for (const auto& name : visionary::VisionaryType::getNames())
    {
      std::cout << "  " << name << '\n';
    }

    return static_cast<int>(exitCode);
  }

  exitCode = runWelcomeDemo(visionaryType, deviceIpAddr);

  std::cout << "exit code " << static_cast<int>(exitCode) << '\n';

  return static_cast<int>(exitCode);
}
