//
// Copyright (c) 2023,2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <iostream>
#include <sstream>

#include <chrono>
#include <thread>

#include <sick_visionary_cpp_base/FrameGrabber.h>
#include <sick_visionary_cpp_base/NetLink.h>
#include <sick_visionary_cpp_base/PointCloudPlyWriter.h>
#include <sick_visionary_cpp_base/PointXYZ.h>
#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <sick_visionary_cpp_base/VisionaryType.h>

#include "BlobServerConfig.h"
#include "UdpParsing.h"
#include "exitcodes.h"
#include "framewrite.h"

#include <cassert>

static ExitCode runContinuousStreamingDemo(visionary::VisionaryType visionaryType,
                                           const std::string&       transportProtocol,
                                           const std::string&       ipAddress,
                                           const std::string&       receiverIp,
                                           std::uint16_t            streamingPort,
                                           unsigned                 numberOfFrames,
                                           const std::string&       filePrefix,
                                           bool                     storeData)
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

  //-----------------------------------------------
  // Stop image acquisition (works always, also when already stopped)
  // Further you should always stop the device before reconfiguring it
  // tag::precautionary_stop[]
  if (!visionaryControl->stopAcquisition())
  {
    std::fprintf(stderr, "Failed to stop acquisition.\n");

    return ExitCode::eControlCommunicationError;
  }

  // end::precautionary_stop[]
  // Depending on the PC we might be too fast for the device configuration
  // Just wait a short time. This should only be necessary after stop
  // (to make sure stop really propagated and you don't get a pending frame)
  // or after a configure to make sure configuration has finished
  // tag::precautionary_stop[]
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  // end::precautionary_stop[]

  // Login to the device for access rights to certain methods
  visionaryControl->login(IAuthentication::UserLevel::SERVICE, "CUST_SERV");
  std::shared_ptr<visionary::NetLink> udpSocket;

  // tag::tcp_settings[]
  if (transportProtocol == "TCP")
  {
    // configure the data stream
    // the methods immediately write the setting to the device
    // set protocol and device port
    setTransportProtocol(visionaryControl, transportProtocol); // TCP
    setBlobTcpPort(visionaryControl, streamingPort);
  }
  // end::tcp_settings[]

  // tag::udp_settings[]
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
  // end::udp_settings[]

  // login / logout always need to form blocks because login chnages to config mode (no streaming active) and logout
  // returns to RUN mode (streaming)
  visionaryControl->logout();

  // start the image acquisition and continuously receive frames
  // tag::start_acquisition[]
  if (!visionaryControl->startAcquisition())
  {
    std::fprintf(stderr, "Failed to start acquisition.\n");

    return ExitCode::eControlCommunicationError;
  }
  // end::start_acquisition[]

  std::shared_ptr<VisionaryData>    pDataHandler  = nullptr;
  std::unique_ptr<FrameGrabberBase> pFrameGrabber = nullptr;

  if (transportProtocol == "TCP")
  {
    //-----------------------------------------------
    // create a frame grabber suitable for the Visionary type used in visionaryControl
    // tag::create_frame_grabber[]
    pFrameGrabber = visionaryControl->createFrameGrabber();
    pDataHandler  = visionaryControl->createDataHandler();
    // end::create_frame_grabber[]
  }

  //-----------------------------------------------
  
  for (unsigned i = 0u; i < numberOfFrames; ++i)
  {
    // tag::tcp_acquisition[]
    if (transportProtocol == "TCP")
    {
      if (!pFrameGrabber->genGetNextFrame(pDataHandler))
      {
        visionaryControl->stopAcquisition();

        std::fprintf(stderr, "Frame timeout in continuous mode after %u frames\n", i);

        return ExitCode::eFrameTimeout;
      }
      else
      {
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
    // end::tcp_acquisition[]
    else if (transportProtocol == "UDP")
    {
      // tag::udp_acquisition[]
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
        received                    = udpSocket->read(buffer);
      }
      int                    fragmentNumber = (buffer[2] << 8) | buffer[3];
      ITransport::ByteBuffer last_fragment(buffer.begin() + 14, buffer.end() - 1);
      fragmentMap[fragmentNumber] = last_fragment;

      auto completeBlob = reassembleFragments(fragmentMap);

      parseUdpBlob(completeBlob, pDataHandler);
      // end::udp_acquisition[]

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

  //-----------------------------------------------
  // tag::stop_acquisition[]
  if (!visionaryControl->stopAcquisition())
  {
    std::fprintf(stderr, "Failed to stop acquisition.\n");

    return ExitCode::eControlCommunicationError;
  }
  // end::stop_acquisition[]

  if (transportProtocol == "TCP")
  {
    // delete the frame grabber
    // this operation is blocking, since the frame grabber thread is joined which takes up to 5s
    // (actually since the acquisition is still running, the thread will wake up and join only one frame time of ~33ms)
    // tag::release_frame_grabber[]
    pFrameGrabber.reset();
    // end::release_frame_grabber[]
  }

  else if (transportProtocol == "UDP")
  {
    visionaryControl->login(IAuthentication::UserLevel::SERVICE, "CUST_SERV");
    // reset to TCP
    setTransportProtocol(visionaryControl, "TCP");
    setBlobTcpPort(visionaryControl, 2114);
    visionaryControl->logout();
  }
  // tag::close_control_channel[]
  visionaryControl->close();
  // end::close_control_channel[]
  std::cout << "Logout and close.\n";

  return ExitCode::eOk;
}

int main(int argc, char* argv[])
{
  std::string   transportProtocol{"TCP"};
  std::string   deviceIpAddr{"192.168.1.10"};
  std::string   receiverIp{"192.168.1.2"};
  std::string   filePrefix{""};
  std::uint16_t streamingPort = 2114;
  unsigned      cnt           = 10u;
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

  exitCode = runContinuousStreamingDemo(
    visionaryType, transportProtocol, deviceIpAddr, receiverIp, streamingPort, cnt, filePrefix, storeData);

  std::cout << "exit code " << static_cast<int>(exitCode) << '\n';

  return static_cast<int>(exitCode);
}
