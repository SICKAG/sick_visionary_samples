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

#include <sick_visionary_cpp_base/FrameGrabberBase.h>
#include <sick_visionary_cpp_base/NetLink.h>
#include <sick_visionary_cpp_base/PointCloudPlyWriter.h>
#include <sick_visionary_cpp_base/PointXYZ.h>
#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <sick_visionary_cpp_base/VisionaryType.h>

#include "BlobServerConfig.h"
#include "exitcodes.h"
#include "frontendmodes.h"

#include "UdpParsing.h"
#include "framewrite.h"

static ExitCode runSnapshotsDemo(visionary::VisionaryType visionaryType,
                                 const std::string&       transportProtocol,
                                 const std::string&       ipAddress,
                                 const std::string&       receiverIp,
                                 std::uint16_t            streamingPort,
                                 unsigned                 numberOfFrames,
                                 const std::string&       filePrefix,
                                 bool                     storeData,
                                 unsigned                 pollPeriodMs)
{
  // tag::open_control_channel[]
  using namespace visionary;

  std::shared_ptr<VisionaryControl> visionaryControl = std::make_shared<VisionaryControl>(visionaryType);

  // Connect to devices control channel
  if (!visionaryControl->open(ipAddress))
  {
    std::fprintf(stderr, "Failed to open control connection to device.\n");

    return ExitCode::eControlCommunicationError;
  }
  // end::open_control_channel[]

  // tag::login[]
  // Login/ logout always need to form blocks, as a login changes the camera mode to “config” (no active streaming)
  // and logging out resets the mode to “RUN” (streaming).
  visionaryControl->login(IAuthentication::UserLevel::SERVICE, "CUST_SERV");
  // end::login[]

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
    udpSocket = std::make_shared<visionary::NetLink>(receiverIp, 24, streamingPort, ipAddress);
  }

  // tag::stop_frontend[]
  // set FrontendMode::eStopped to switch to software trigger
  writeFrontendMode(visionaryControl, FrontendMode::eStopped);
  // end::stop_frontend[]

  // returns to RUN mode (streaming)
  visionaryControl->logout();

  const std::chrono::milliseconds pollPeriodSpan{pollPeriodMs};

  auto lastSnapTime = std::chrono::steady_clock::now();

  std::shared_ptr<VisionaryData>    pDataHandler  = nullptr;
  std::unique_ptr<FrameGrabberBase> pFrameGrabber = nullptr;

  if (transportProtocol == "TCP")
  {
    //-----------------------------------------------
    // create a frame grabber suitable for the Visionary type used in visionaryControl
    // tag::create_frame_grabber[]
    pFrameGrabber = visionaryControl->createFrameGrabber();

    // the data handler pointer will later contain the frame data
    pDataHandler = visionaryControl->createDataHandler();
    // end::create_frame_grabber[]
  }

  // trigger dummy snapshot acquistion to restart frontend (a stopped frontend needs to warm up for 16 frames to achieve specified TOF precision, these frames will be dropped internally)
  visionaryControl->stepAcquisition();
  if(!pFrameGrabber->genGetNextFrame(pDataHandler, false, std::chrono::milliseconds(2000)))
    std::fprintf(stderr, "get next frame timeout");

  //-----------------------------------------------
  // acquire a single snapshot
  for (int i = 0; i < numberOfFrames; ++i)
  {
    // make sure we don't overrun the device
    // (otherwise snapshot requests would be dropped by the device)
    // tag::avoid_overrun[]
    const auto timeSinceLastSnap = std::chrono::steady_clock::now() - lastSnapTime;

    if (timeSinceLastSnap < pollPeriodSpan)
    {
      auto timeToWait = pollPeriodSpan - timeSinceLastSnap;
      std::this_thread::sleep_for(timeToWait);
    }
    // end::avoid_overrun[]

    // now we are not too fast and can trigger a snapshot
    // tag::acquire_snapshots[]
    lastSnapTime = std::chrono::steady_clock::now();
    if (!visionaryControl->stepAcquisition())
    {
      std::fprintf(stderr, "Failed to trigger a snapshot\n");

      return ExitCode::eControlCommunicationError;
    }

    if (transportProtocol == "TCP")
    {
      // the snapshot has possibly already arrived, so parameter onlyNewer is false
      if (!pFrameGrabber->genGetNextFrame(pDataHandler))
      {
        std::fprintf(stderr, "Frame timeout for snapshot\n");

        return ExitCode::eFrameTimeout;
      }
      else
      {
        std::printf("Frame received in snapshot mode, frame #%" PRIu32 "\n", pDataHandler->getFrameNum());
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
    // end::acquire_snapshots[]
  }

  visionaryControl->login(IAuthentication::UserLevel::SERVICE, "CUST_SERV");
  if (transportProtocol == "TCP")
  {
    // delete the frame grabber
    // this operation is blocking, since the frame grabber thread is joined which takes up to 5s
    // (actually since the acquisition is still running, the thread will wake up and join only one frame time of ~33ms)
    // tag::release_frame_grabber[]
    pFrameGrabber.reset();
    // end::release_frame_grabber[]
    setBlobTcpPort(visionaryControl, 2114);
  }
  else if (transportProtocol == "UDP")
  {
    // reset to TCP
    setTransportProtocol(visionaryControl, "TCP");
    setBlobTcpPort(visionaryControl, 2114);
  }
  // Reset the frontendmode
  writeFrontendMode(visionaryControl, FrontendMode::eContinuous);
  // tag::close_control_channel[]
  visionaryControl->logout();
  visionaryControl->close();
  // end::close_control_channel[]

  return ExitCode::eOk;
}

int main(int argc, char* argv[])
{
  std::string   transportProtocol{"TCP"};
  std::string   deviceIpAddr{"192.168.1.10"};
  std::string   receiverIp{"192.168.1.2"};
  std::string   filePrefix{""};
  std::uint16_t streamingPort = 2114;
  unsigned      cnt           = 5u;
  unsigned      pollperiodMs  = 500u;
  bool          storeData     = true;

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
      case 'p':
        argstream >> pollperiodMs;
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
    std::cout << "  -p<pollperiod>                poll period for snapshot in ms; default is " << pollperiodMs << '\n';
    std::cout << "  -o<file prefix>             prefix for the output files; default is '" << filePrefix << "'\n";
    std::cout << "  -w<write files>             write data to files if true; default is '"
              << (storeData ? "true" : "false") << "'\n";

    std::cout << "\nVisionary product types:\n";
    for (const auto& name : visionary::VisionaryType::getNames())
    {
      std::cout << "  " << name << '\n';
    }

    return static_cast<int>(exitCode);
  }

  exitCode = runSnapshotsDemo(visionaryType,
                              transportProtocol,
                              deviceIpAddr,
                              receiverIp,
                              streamingPort,
                              cnt,
                              filePrefix,
                              storeData,
                              pollperiodMs);

  std::cout << "exit code " << static_cast<int>(exitCode) << '\n';

  return static_cast<int>(exitCode);
}
