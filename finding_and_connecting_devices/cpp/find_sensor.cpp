//
// Copyright (c) 2023 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <VisionaryAutoIP.h>

#include "exitcodes.h"

static ExitCode runScanDemo(const std::string& hostIp, std::uint8_t prefixLength)
{
  // tag::device_discovery[]
  using namespace visionary;
  VisionaryAutoIP ipScan(hostIp, prefixLength);
  // end::device_discovery[]

  // tag::ip_scan[]
  // scan for devices
  std::vector<DeviceInfo> deviceList = ipScan.scan();

  // print device info for every found device
  for (auto it : deviceList)
  {
    std::cout << "Device name:  " << it.deviceIdent << std::endl
              << "SerialNumber: " << it.serialNumber << std::endl
              << "MAC Address:  " << it.macAddress << std::endl
              << "IP Address:   " << it.ipAddress << std::endl
              << "Network Mask: " << it.networkMask << std::endl
              << "CoLa port:    " << it.colaPort << std::endl
              << "CoLa version: " << static_cast<uint16_t>(it.colaVersion) << std::endl;
  }

  std::cout << '\n' << "Number of found devices: " << deviceList.size() << std::endl;
  // end::ip_scan[]

  return ExitCode::eOk;
}

int main(int argc, char* argv[])
{
  using namespace visionary;

  std::string interfaceIpAddr;

  bool     showHelpAndExit = false;
  ExitCode exitCode        = ExitCode::eOk;

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
        argstream >> interfaceIpAddr;
        break;
      default:
        showHelpAndExit = true;
        exitCode        = ExitCode::eParamError;
        break;
    }
  }

  std::replace(interfaceIpAddr.begin(), interfaceIpAddr.end(), '/', ' ');
  std::istringstream ipStream(interfaceIpAddr);
  std::string        ip;
  std::uint16_t      prefix{0u};
  if (ipStream >> ip >> prefix)
  {
    showHelpAndExit |= prefix > 32;
  }
  else
  {
    showHelpAndExit = true;
  }

  if (showHelpAndExit)
  {
    std::cout << argv[0] << " [option]*" << std::endl;
    std::cout << "where option is one of" << std::endl;
    std::cout << "-h          show this help and exit" << std::endl;
    std::cout << "-i<IP>      ip address of the interface on which the scan is performed." << std::endl
              << "            It is expected to be in a CIDR manner, " << std::endl
              << "            i.e., using ip address and the length of network prefix seperated by /. " << std::endl
              << "            For example, -i192.168.1.100/24" << std::endl
              << "            Note the range of prefix is [0, 32]. " << std::endl;

    return static_cast<int>(exitCode);
  }

  exitCode = runScanDemo(ip, static_cast<uint8_t>(prefix));

  std::cout << "exit code " << static_cast<int>(exitCode) << std::endl;

  return static_cast<int>(exitCode);
}