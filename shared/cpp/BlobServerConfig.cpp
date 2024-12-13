//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include "BlobServerConfig.h"
#include <sick_visionary_cpp_base/CoLaCommand.h>
#include <sick_visionary_cpp_base/CoLaError.h>
#include <sick_visionary_cpp_base/CoLaParameterWriter.h>
#include <iostream>

using namespace visionary;

bool setTransportProtocol(std::shared_ptr<VisionaryControl> visionaryControl, const std::string& transportProtocol)
{
  int eProtocol;
  if (transportProtocol == "TCP")
  {
    eProtocol = 0;
  }
  else if (transportProtocol == "UDP")
  {
    eProtocol = 1;
  }
  CoLaCommand setBlobTransportProtocolAPI =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "BlobTransportProtocolAPI").parameterUSInt(eProtocol).build();
  CoLaCommand setBlobTransportProtocolAPIResponse = visionaryControl->sendCommand(setBlobTransportProtocolAPI);
  if (setBlobTransportProtocolAPIResponse.getError() != CoLaError::OK)
  {
    std::fprintf(
      stderr, "Failure writing BlobTransportProtocolAPI: %d\n", setBlobTransportProtocolAPIResponse.getError());
    return false;
  }
  else
  {
    return true;
  }
}

bool setBlobUdpReceiverPort(std::shared_ptr<VisionaryControl> visionaryControl, std::uint16_t receiverPort)
{
  if (receiverPort >= 1025 && receiverPort <= 65535)
  {
    CoLaCommand setBlobUdpReceiverPortAPI =
      CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "BlobUdpReceiverPortAPI")
        .parameterUInt(receiverPort)
        .build();
    CoLaCommand setBlobUdpReceiverPortAPIResponse = visionaryControl->sendCommand(setBlobUdpReceiverPortAPI);
    if (setBlobUdpReceiverPortAPIResponse.getError() != CoLaError::OK)
    {
      std::fprintf(
        stderr, "Failure writing BlobUdpReceiverPortAPI: %d\n", setBlobUdpReceiverPortAPIResponse.getError());
      return false;
    }
    else
    {
      return true;
    }
  }
  else
  {
    std::cout << "ERROR: the receiver port must be a value between 1025 and 65535!" << "\n";
    return false;
  }
}

bool setBlobUdpControlPort(std::shared_ptr<VisionaryControl> visionaryControl, std::uint16_t controlPort)
{
  if (controlPort >= 1025 && controlPort <= 65535)
  {
    CoLaCommand setBlobUdpControlPortAPI =
      CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "BlobUdpControlPortAPI").parameterUInt(controlPort).build();
    CoLaCommand setBlobUdpControlPortAPIResponse = visionaryControl->sendCommand(setBlobUdpControlPortAPI);
    if (setBlobUdpControlPortAPIResponse.getError() != CoLaError::OK)
    {
      std::fprintf(stderr, "Failure writing BlobUdpControlPortAPI: %d\n", setBlobUdpControlPortAPIResponse.getError());
      return false;
    }
    else
    {
      return true;
    }
  }
  else
  {
    std::cout << "ERROR: the udp control port must be a value between 1025 and 65535!" << "\n";
    return false;
  }
}

bool setBlobTcpPort(std::shared_ptr<VisionaryControl> visionaryControl, std::uint16_t tcpPort)
{
  if (tcpPort >= 1025 && tcpPort <= 65535)
  {
    CoLaCommand setBlobTcpPortAPI =
      CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "BlobTcpPortAPI").parameterUInt(tcpPort).build();
    CoLaCommand setBlobTcpPortAPIResponse = visionaryControl->sendCommand(setBlobTcpPortAPI);
    if (setBlobTcpPortAPIResponse.getError() != CoLaError::OK)
    {
      std::fprintf(stderr, "Failure writing BlobTcpPortAPI: %d\n", setBlobTcpPortAPIResponse.getError());
      return false;
    }
    else
    {
      return true;
    }
  }
  else
  {
    std::cout << "ERROR: the tcp control port must be a value between 1025 and 65535!" << "\n";
    return false;
  }
}

bool setBlobUdpMaxPacketSize(std::shared_ptr<VisionaryControl> visionaryControl, std::uint16_t maxPacketSize)
{
  if (maxPacketSize >= 100 && maxPacketSize <= 65535)
  {
    CoLaCommand setBlobUdpMaxPacketSizeAPI =
      CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "BlobUdpMaxPacketSizeAPI")
        .parameterUInt(maxPacketSize)
        .build();
    CoLaCommand setBlobUdpMaxPacketSizeAPIResponse = visionaryControl->sendCommand(setBlobUdpMaxPacketSizeAPI);
    if (setBlobUdpMaxPacketSizeAPIResponse.getError() != CoLaError::OK)
    {
      std::fprintf(stderr, "Failure writing BlobTcpPortAPI: %d\n", setBlobUdpMaxPacketSizeAPIResponse.getError());
      return false;
    }
    else
    {
      return true;
    }
  }
  else
  {
    std::cout << "ERROR: the UDp max packet size must be a value between 100 and 65535!" << "\n";
    return false;
  }
}

bool setBlobUdpIdleTimeBetweenPackets(std::shared_ptr<VisionaryControl> visionaryControl,
                                      std::uint16_t                     timeBetweenPackets)
{
  if (timeBetweenPackets >= 0 && timeBetweenPackets <= 10000)
  {
    CoLaCommand setBlobUdpIdleTimeBetweenPacketsAPI =
      CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "BlobUdpIdleTimeBetweenPacketsAPI")
        .parameterUInt(timeBetweenPackets)
        .build();
    CoLaCommand setBlobUdpIdleTimeBetweenPacketsAPIResponse =
      visionaryControl->sendCommand(setBlobUdpIdleTimeBetweenPacketsAPI);
    if (setBlobUdpIdleTimeBetweenPacketsAPIResponse.getError() != CoLaError::OK)
    {
      std::fprintf(stderr,
                   "Failure writing BlobUdpIdleTimeBetweenPacketsAPI: %d\n",
                   setBlobUdpIdleTimeBetweenPacketsAPIResponse.getError());
      return false;
    }
    else
    {
      return true;
    }
  }
  else
  {
    std::cout << "ERROR: the value for the time between packets must be a value between 0 and 10000!" << "\n";
    return false;
  }
}

bool setBlobUdpReceiverIP(std::shared_ptr<VisionaryControl> visionaryControl, const std::string& receiverIP)
{
  CoLaCommand setBlobUdpReceiverIP = CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "BlobUdpReceiverIPAPI")
                                       .parameterFlexString(receiverIP)
                                       .build();
  CoLaCommand setBlobUdpReceiverIPResponse = visionaryControl->sendCommand(setBlobUdpReceiverIP);
  if (setBlobUdpReceiverIPResponse.getError() != CoLaError::OK)
  {
    std::fprintf(stderr, "Failure writing BlobUdpReceiverIPAPI: %d\n", setBlobUdpReceiverIPResponse.getError());
    return false;
  }
  else
  {
    return true;
  }
}

bool setBlobUdpHeartbeatInterval(std::shared_ptr<VisionaryControl> visionaryControl, std::uint32_t heartBeatInterval)
{
  if (heartBeatInterval >= 0 && heartBeatInterval <= 10000000)
  {
    CoLaCommand setBlobUdpHeartbeatInterval =
      CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "BlobUdpHeartbeatInterval")
        .parameterUDInt(heartBeatInterval)
        .build();
    CoLaCommand setBlobUdpHeartbeatIntervalResponse = visionaryControl->sendCommand(setBlobUdpHeartbeatInterval);
    if (setBlobUdpHeartbeatIntervalResponse.getError() != CoLaError::OK)
    {
      std::fprintf(
        stderr, "Failure writing BlobUdpHeartbeatInterval: %d\n", setBlobUdpHeartbeatIntervalResponse.getError());
      return false;
    }
    else
    {
      return true;
    }
  }
  else
  {
    std::cout << "ERROR: the TCP port must be a value between 0 and 10000000!" << "\n";
    return false;
  }
}

bool setBlobUdpHeaderEnabled(std::shared_ptr<VisionaryControl> visionaryControl, bool headerEnabled)
{
  CoLaCommand setBlobUdpHeaderEnabled =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "BlobUdpHeaderEnabled").parameterBool(headerEnabled).build();
  CoLaCommand setBlobUdpHeaderEnabledResponse = visionaryControl->sendCommand(setBlobUdpHeaderEnabled);
  if (setBlobUdpHeaderEnabledResponse.getError() != CoLaError::OK)
  {
    std::fprintf(stderr, "Failure writing BlobUdpHeaderEnabled: %d\n", setBlobUdpHeaderEnabledResponse.getError());
    return false;
  }
  else
  {
    return true;
  }
}

bool setBlobUdpAutoTransmit(std::shared_ptr<VisionaryControl> visionaryControl, bool autoTransmit)
{
  CoLaCommand setBlobUdpAutoTransmit =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "BlobUdpAutoTransmit").parameterBool(autoTransmit).build();
  CoLaCommand setBlobUdpAutoTransmitResponse = visionaryControl->sendCommand(setBlobUdpAutoTransmit);
  if (setBlobUdpAutoTransmitResponse.getError() != CoLaError::OK)
  {
    std::fprintf(stderr, "Failure writing BlobUdpAutoTransmit: %d\n", setBlobUdpAutoTransmitResponse.getError());
    return false;
  }
  else
  {
    return true;
  }
}

bool setBlobUdpFecEnabled(std::shared_ptr<VisionaryControl> visionaryControl, bool fecEnabled)
{
  CoLaCommand setBlobUdpFecEnabled =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, "BlobUdpFECEnabled").parameterBool(fecEnabled).build();
  CoLaCommand setBlobUdpFecEnabledResponse = visionaryControl->sendCommand(setBlobUdpFecEnabled);
  if (setBlobUdpFecEnabledResponse.getError() != CoLaError::OK)
  {
    std::fprintf(stderr, "Failure writing BlobUdpFECEnabled: %d\n", setBlobUdpFecEnabledResponse.getError());
    return false;
  }
  else
  {
    return true;
  }
}
