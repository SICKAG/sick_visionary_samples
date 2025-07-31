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

#include <sick_visionary_cpp_base/CoLaCommand.h>
#include <sick_visionary_cpp_base/CoLaParameterReader.h>
#include <sick_visionary_cpp_base/CoLaParameterWriter.h>
#include <sick_visionary_cpp_base/FrameGrabberBase.h>
#include <sick_visionary_cpp_base/NetLink.h>
#include <sick_visionary_cpp_base/PointCloudPlyWriter.h>
#include <sick_visionary_cpp_base/PointXYZ.h>
#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <sick_visionary_cpp_base/VisionaryType.h>

#include "checkcola.h"
#include "exitcodes.h"
#include "ioports.h"

#include "BlobServerConfig.h"
#include "UdpParsing.h"
#include "framewrite.h"
#include "frontendmodes.h"

// Device configuration values for external triggering
//
// The configuration of the device is read and stored in this struct.
//
// The kind of ports used for the trigger can differ (input-only or in/out)
// so we provide both a triggerInName/TriggerInFct and a triggerIoName/triggerIoFct.
// Only one of them will be used, depending on the port type.
struct Configuration
{
  visionary::FrontendMode      frontendMode;
  visionary::InputFunctionType triggerInFct;
  visionary::IOFunctionType    triggerInFct2;
  visionary::IOFunctionType    busyOutFct;
};

// Names of the used digital ports.
//
// The names of the ports used for the trigger and busy signal are stored in this struct.
// An empty string means that the port is not used.
struct DioPortNames
{
  std::string triggerInName;
  std::string busyOutName;
};

static Configuration readConfiguration(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl,
                                       const DioPortNames&                          portNames)
{
  using namespace visionary;

  Configuration configuration{};

  configuration.frontendMode = readFrontendMode(rVisionaryControl);

  if (!portNames.triggerInName.empty())
  {
    // try whether our name is an input port
    try
    {
      const auto port            = getInPortFromName(portNames.triggerInName);
      configuration.triggerInFct = readDioFunction(rVisionaryControl, port);
    }
    catch (const std::invalid_argument&)
    {
      // if not, it must be an in/out port
      const auto port             = getInOutPortFromName(portNames.triggerInName);
      configuration.triggerInFct2 = readDioFunction(rVisionaryControl, port);
    }
  }

  if (!portNames.busyOutName.empty())
  {
    const auto port          = getInOutPortFromName(portNames.busyOutName);
    configuration.busyOutFct = readDioFunction(rVisionaryControl, port);
  }

  return configuration;
}

static void writeConfiguration(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl,
                               const Configuration&                         configuration,
                               const DioPortNames&                          portNames)
{
  using namespace visionary;

  writeFrontendMode(rVisionaryControl, configuration.frontendMode);

  if (!portNames.triggerInName.empty())
  {
    // try whether our name is an input port
    try
    {
      const auto port = getInPortFromName(portNames.triggerInName);
      writeDioFunction(rVisionaryControl, port, configuration.triggerInFct);
    }
    catch (const std::invalid_argument&)
    {
      // if not, it must be an in/out port
      const auto port = getInOutPortFromName(portNames.triggerInName);
      writeDioFunction(rVisionaryControl, port, configuration.triggerInFct2);
    }
  }

  if (!portNames.busyOutName.empty())
  {
    const auto port = getInOutPortFromName(portNames.busyOutName);
    writeDioFunction(rVisionaryControl, port, configuration.busyOutFct);
  }
}

static ExitCode runExternalTriggerDemo(visionary::VisionaryType visionaryType,
                                       const std::string&       transportProtocol,
                                       const std::string&       ipAddress,
                                       const std::string&       receiverIp,
                                       std::uint16_t            streamingPort,
                                       unsigned                 numberOfFrames,
                                       const std::string&       filePrefix,
                                       bool                     storeData,
                                       const DioPortNames&      portNames)

{
  using namespace visionary;

  ExitCode exitcode = ExitCode::eOk;

  std::shared_ptr<VisionaryControl> visionaryControl = std::make_shared<VisionaryControl>(visionaryType);

  // Open a connection to the device
  if (!visionaryControl->open(ipAddress))
  {
    std::fprintf(stderr, "Failed to open control connection to device.\n");
    return ExitCode::eControlCommunicationError;
  }

  // Login as authorized client
  if (!visionaryControl->login(IAuthentication::UserLevel::AUTHORIZED_CLIENT, "CLIENT"))
  {
    std::fprintf(stderr, "Failed to log into device\n");
    return ExitCode::eAuthenticationError;
  }

  std::shared_ptr<visionary::NetLink> udpSocket;
  if (transportProtocol == "TCP")
  {
    // configure the data stream
    // the methods immediately write the setting to the device
    // set protocol and device port
    setTransportProtocol(visionaryControl, transportProtocol); // TCP
    setBlobTcpPort(visionaryControl, streamingPort);
  }
  else if (transportProtocol == "UDP")
  {
    // streaming settings
    setTransportProtocol(visionaryControl, transportProtocol); // UDP
    setBlobUdpReceiverPort(visionaryControl, streamingPort);
    setBlobUdpControlPort(visionaryControl, streamingPort);
    setBlobUdpMaxPacketSize(visionaryControl, 1024);
    setBlobUdpReceiverIP(visionaryControl, receiverIp);
    setBlobUdpIdleTimeBetweenPackets(visionaryControl, 10); // in milliseconds
    setBlobUdpHeartbeatInterval(visionaryControl, 0);
    setBlobUdpHeaderEnabled(visionaryControl, true);
    setBlobUdpFecEnabled(visionaryControl, false); // forward error correction
    setBlobUdpAutoTransmit(visionaryControl, true);

    // open the datagram socket
    // Create a new UdpSocket object
    // prefix 24 assumption -> problem: 192.168.136.100/16 valid device IP 192.168.136.255 in this case socket will be
    // in broadcast mode using prefix 0 -> netmask 0.0.0.0 only broadcast = global broadcast 255.255.255.255 - OK
    udpSocket = std::make_shared<visionary::NetLink>(receiverIp, 0, streamingPort, ipAddress);
  }

  Configuration oldConfiguration{};

  try
  {
    oldConfiguration = readConfiguration(visionaryControl, portNames);

    Configuration newConfiguation{};
    // the expected frontend mode for external trigger operation
    // differs between Visionary-T Mini and the rest.
    if (visionaryType == VisionaryType::eVisionaryTMini)
    {
      newConfiguation.frontendMode = FrontendMode::eStopped;
    }
    else
    {
      newConfiguation.frontendMode = FrontendMode::eExternalTrigger;
    }
    newConfiguation.triggerInFct  = InputFunctionType::eTrigger;
    newConfiguation.triggerInFct2 = IOFunctionType::eTrigger;
    newConfiguation.busyOutFct    = IOFunctionType::eTriggerBusy;
    writeConfiguration(visionaryControl, newConfiguation, portNames);
  }
  catch (const std::runtime_error& e)
  {
    std::cerr << "Failed to read or write configuration: " << e.what() << std::endl;

    if (!visionaryControl->logout())
    {
      std::cerr << "Failed to logout from device" << std::endl;
    }

    return ExitCode::eControlCommunicationError;
  }

  if (!visionaryControl->logout())
  {
    std::fprintf(stderr, "Failed to logout from device\n");
    return ExitCode::eControlCommunicationError;
  }

  // create a frame grabber suitable for the Visionary type used in visionaryControl
  // tag::create_frame_grabber[]
  std::shared_ptr<VisionaryData>    pDataHandler  = nullptr;
  std::unique_ptr<FrameGrabberBase> pFrameGrabber = nullptr;

  if (transportProtocol == "TCP")
  {
    //-----------------------------------------------
    // create a frame grabber suitable for the Visionary type used in visionaryControl
    pFrameGrabber = visionaryControl->createFrameGrabber();
    // the data handler pointer will later contain the frame data
    pDataHandler = visionaryControl->createDataHandler();
  }
  // end::create_frame_grabber[]

  for (unsigned i = 0; i < numberOfFrames; ++i)
  {
    std::printf("Waiting for the trigger, press ctrl-C to abort\n");

    if (transportProtocol == "TCP")
    {
      // the trigger might have already been received, so we pass onlyNewer = false
      // and wait until a new frame is received
      // (if the get frame times out, we just continue waiting since we don't know
      // when the trigger will activated)
      // tag::wait_for_frame[]
      while (!pFrameGrabber->genGetNextFrame(pDataHandler, false))
        ;

      // finally we got a frame
      std::printf("Frame received in external trigger mode, frame #%" PRIu32 "\n", pDataHandler->getFrameNum());
      // end::wait_for_frame[]
      if (storeData)
      {
        // write the frame to a file
        writeFrame(visionaryType, *pDataHandler, filePrefix);

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
    }
    else if (transportProtocol == "UDP")
    {
      pDataHandler = visionaryControl->createDataHandler();

      std::map<std::uint16_t, ITransport::ByteBuffer> fragmentMap;
      ITransport::ByteBuffer                          buffer;
      int                                             received;
      std::size_t                                     maxBytesToReceive = 1024;
      std::uint16_t                                   lastFrameNum      = 0;

      // Receive from UDP Socket
      buffer.resize(maxBytesToReceive);
      received = udpSocket->read(buffer);

      std::cout << "========== new BLOB received ==========" << "\n";
      std::cout << "Blob number: " << ((buffer[0] << 8) | buffer[1]) << "\n";
      std::cout << "server IP: " << ipAddress << "\n";
      std::cout << "========================================" << "\n";

      // FIN Flag of Statemap in header is set when new BLOB begins
      while (buffer[6] != 0x80)
      {
        std::uint16_t fragmentNumber = (static_cast<std::uint16_t>(buffer[2]) << 8) | buffer[3];
        if (fragmentNumber - lastFrameNum > 1)
          printf(
            "Lost %d frames between Frames: %d %d \n", fragmentNumber - lastFrameNum, lastFrameNum, fragmentNumber);
        lastFrameNum = fragmentNumber;
        ITransport::ByteBuffer fragment(
          buffer.begin() + 14, buffer.end() - 1); // Payload begins at byteindex 14, Last element contains checksum
        fragmentMap[fragmentNumber] = fragment;
        // std::cout << "Fragment number: " << fragmentNumber << "\n";
        received = udpSocket->read(buffer);
      }
      int fragmentNumber = (buffer[2] << 8) | buffer[3];
      // std::cout << "Fragment number: " << fragmentNumber << "\n";
      ITransport::ByteBuffer last_fragment(buffer.begin() + 14, buffer.end() - 1);
      fragmentMap[fragmentNumber] = last_fragment;

      auto completeBlob = reassembleFragments(fragmentMap);

      parseUdpBlob(completeBlob, pDataHandler);

      std::printf("Frame received in continuous mode, frame #%" PRIu32 "\n", pDataHandler->getFrameNum());

      if (storeData)
      {
        // write the frame to disk
        writeFrame(visionaryType, *pDataHandler, filePrefix);

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
    }
  }

  visionaryControl->login(IAuthentication::UserLevel::SERVICE, "CUST_SERV");
  if (transportProtocol == "TCP")
  {
    // delete the frame grabber
    // this operation is blocking, since the frame grabber thread is joined which takes up to 5s
    // (actually since the acquisition is still running, the thread will wake up and join only one frame time of ~33ms)
    // tag::release_frame_grabber[]
    pFrameGrabber.reset();
    setBlobTcpPort(visionaryControl, 2114);
    // end::release_frame_grabber[]
  }

  else if (transportProtocol == "UDP")
  {
    // reset to TCP
    setTransportProtocol(visionaryControl, "TCP");
    setBlobTcpPort(visionaryControl, 2114);
  }

  try
  {
    writeConfiguration(visionaryControl, oldConfiguration, portNames);
  }
  catch (const std::runtime_error& e)
  {
    std::cerr << "Failed to write configuration: " << e.what() << std::endl;

    if (!visionaryControl->logout())
    {
      std::cerr << "Failed to logout from device" << std::endl;
    }

    return ExitCode::eControlCommunicationError;
  }

  if (!visionaryControl->logout())
  {
    std::fprintf(stderr, "Failed to logout from device\n");
    return ExitCode::eControlCommunicationError;
  }

  visionaryControl->close();

  return exitcode;
}

int main(int argc, char* argv[])
{
  std::string   transportProtocol{"TCP"};
  std::string   deviceIpAddr{"192.168.1.10"};
  std::string   receiverIp{"192.168.1.2"};
  std::string   filePrefix{""};
  std::uint16_t streamingPort = 2114;
  unsigned      cnt           = 1u;
  bool          storeData     = true;

  DioPortNames portNames{};

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
      case 't':
        argstream >> transportProtocol;
        break;
      case 'i':
        argstream >> deviceIpAddr;
        break;
      case 'r':
        argstream >> receiverIp;
        break;
      case 'n':
        argstream >> cnt;
        break;
      case 'o':
        argstream >> filePrefix;
        break;
      case 's':
        argstream >> streamingPort;
        break;
      case 'b':
        argstream >> portNames.busyOutName;
        break;
      case 'x':
        argstream >> portNames.triggerInName;
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
      }
      break;
      case 'w':
      {
        std::string arg;
        argstream >> arg;
        storeData = (arg == "true" ? true : false);
      }
      break;
      default:
        showHelpAndExit = true;
        break;
    }
  }

  switch (visionaryType)
  {
    case visionary::VisionaryType::eVisionaryS:
      if (portNames.triggerInName.empty())
      {
        portNames.triggerInName = "SENS_IN1";
      }
      break;
    case visionary::VisionaryType::eVisionaryTMini:
      if (portNames.triggerInName.empty())
      {
        portNames.triggerInName = "INOUT1";
      }
      if (portNames.busyOutName.empty())
      {
        portNames.busyOutName = "INOUT2";
      }
      break;
  }

  if (showHelpAndExit)
  {
    std::cout << "\nUsage: " << argv[0] << " [option]*\n";
    std::cout << "where option is one of:\n";
    std::cout << "  -h                          show this help and exit\n";
    std::cout << "  -t<transport protocol>      The transport protocol either TCP or UDP; default is "
              << transportProtocol << '\n';
    std::cout << "  -i<IP>                      connect to the device with IP address <IP>; default is " << deviceIpAddr
              << '\n';
    std::cout << "  -r<receiver IP>             The IP address of the receiving PC (UDP only); default is "
              << receiverIp << '\n';
    std::cout << "  -s<streaming port>          The port of the data channel.; default is " << streamingPort << '\n';
    std::cout << "  -d<device type>             visionary product type; default is '" << visionaryType.toString()
              << "'\n";
    std::cout << "  -n<cnt>                     acquire <cnt> frames and stop; default is " << cnt << '\n';
    std::cout << "-x<pin>         trigger input I/O pin; default is SENS_IN1 for a Visionary-S and INOUT1 for a "
                 "Visionary-T Mini\n";
    std::cout << "-b<pin>         trigger busy I/O pin; default is none for a Visionary-S and INOUT2 for a "
                 "Visionary-T Mini\n";
    std::cout << "  -o<file prefix>             prefix for the output files; default is '" << filePrefix << "'\n";
    std::cout << "  -w<write files>             write data to files if true; default is '"
              << (storeData ? "true" : "false") << "'\n";

    std::cout << "\nVisionary product types:\n";
    for (const auto& name : visionary::VisionaryType::getNames())
    {
      std::cout << "  " << name << '\n';
    }
    std::cout << "exit code " << static_cast<int>(exitCode) << '\n';
    return static_cast<int>(exitCode) << '\n';
  }

  exitCode = runExternalTriggerDemo(
    visionaryType, transportProtocol, deviceIpAddr, receiverIp, streamingPort, cnt, filePrefix, storeData, portNames);

  std::cout << "exit code " << static_cast<int>(exitCode) << '\n';

  return static_cast<int>(exitCode);
}
