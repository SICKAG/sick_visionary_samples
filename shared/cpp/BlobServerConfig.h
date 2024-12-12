//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#pragma once

#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <memory>
#include <string>

using namespace visionary;

bool setTransportProtocol(std::shared_ptr<VisionaryControl> visionaryControl, const std::string& transportProtocol);
bool setBlobUdpReceiverPort(std::shared_ptr<VisionaryControl> visionaryControl, std::uint16_t receiverPort);
bool setBlobUdpControlPort(std::shared_ptr<VisionaryControl> visionaryControl, std::uint16_t controlPort);
bool setBlobTcpPort(std::shared_ptr<VisionaryControl> visionaryControl, std::uint16_t tcpPort);
bool setBlobUdpMaxPacketSize(std::shared_ptr<VisionaryControl> visionaryControl, std::uint16_t maxPacketSize);
bool setBlobUdpIdleTimeBetweenPackets(std::shared_ptr<VisionaryControl> visionaryControl,
                                      std::uint16_t                     timeBetweenPackets);
bool setBlobUdpReceiverIP(std::shared_ptr<VisionaryControl> visionaryControl, const std::string& receiverIP);
bool setBlobUdpHeartbeatInterval(std::shared_ptr<VisionaryControl> visionaryControl, std::uint32_t heartBeatInterval);
bool setBlobUdpHeaderEnabled(std::shared_ptr<VisionaryControl> visionaryControl, bool headerEnabled);
bool setBlobUdpAutoTransmit(std::shared_ptr<VisionaryControl> visionaryControl, bool autoTransmit);
bool setBlobUdpFecEnabled(std::shared_ptr<VisionaryControl> visionaryControl, bool fecEnabled);
