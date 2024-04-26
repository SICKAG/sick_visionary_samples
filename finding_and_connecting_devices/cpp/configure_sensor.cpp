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

static ExitCode runAssignDemo(const std::string&     destinationMac,
                              visionary::ColaVersion colaVer,
                              const std::string&     interfaceIpAddr,
                              const std::uint8_t     prefixLen,
                              const std::string&     ipAddr,
                              const std::string&     ipMask,
                              const std::string&     ipGateway,
                              bool                   dhcp,
                              unsigned int           timeout)
{
  using namespace visionary;

  // assume target ip is in host network
  VisionaryAutoIP ipScan(interfaceIpAddr, prefixLen);

  // tag::ip_assign[]
  // Assign IP address
  bool successful = ipScan.assign(destinationMac, colaVer, ipAddr, ipMask, ipGateway, dhcp, timeout);
  // end::ip_assign[]

  if (successful)
  {
    std::cout << "Successfully assigned ip address" << std::endl;
    return ExitCode::eOk;
  }

  std::cout << "Ip address could not be successfully assigned" << std::endl;
  return ExitCode::eCommunicationError;
}

int main(int argc, char* argv[])
{
  using namespace visionary;

  constexpr unsigned    DEF_BROADCAST_TIMEOUT = 5000u;
  constexpr ColaVersion DEF_PROTOCOL_TYPE     = ColaVersion::COLA_2;
  constexpr char        DEF_DEFAULT_GATEWAY[] = "0.0.0.0";

  std::string  destinationMac;
  std::string  interfaceIpAddr;
  std::string  ipAddr;
  std::string  ipMask;
  ColaVersion  colaVersion = DEF_PROTOCOL_TYPE;
  bool         dhcp        = false;
  std::string  ipGateway   = DEF_DEFAULT_GATEWAY;
  unsigned int timeoutMs   = DEF_BROADCAST_TIMEOUT;

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
      case 'o':
        argstream >> destinationMac;
        break;
      case 'c':
      {
        int colaVersionInput = DEF_PROTOCOL_TYPE;
        argstream >> colaVersionInput;
        if (colaVersionInput == 1)
        {
          colaVersion = ColaVersion::COLA_1;
        }
        else if (colaVersionInput == 2)
        {
          colaVersion = ColaVersion::COLA_2;
        }
        else
        {
          showHelpAndExit = true;
        }
        break;
      }
      case 'i':
        argstream >> interfaceIpAddr;
        break;
      case 'n':
        argstream >> ipAddr;
        break;
      case 'm':
        argstream >> ipMask;
        break;
      case 'd':
        dhcp = true;
        break;
      case 't':
        argstream >> timeoutMs;
        break;
      case 'g':
        argstream >> ipGateway;
        break;
      default:
        showHelpAndExit = true;
        exitCode        = ExitCode::eParamError;
        break;
    }
  }

  std::replace(interfaceIpAddr.begin(), interfaceIpAddr.end(), '/', ' ');
  std::istringstream ipStream(interfaceIpAddr);
  std::string        interfaceIp;
  std::uint16_t      prefix{0u};
  if (ipStream >> interfaceIp >> prefix)
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
    std::cout << "where options are" << std::endl;
    std::cout << "-h            show this help and exit" << std::endl;
    std::cout << "-o<MAC>       mac address of the device to assign" << std::endl;
    std::cout << "-i<IP>        ip address of the interface on which the scan is performed." << std::endl
              << "              It is expected to be in a CIDR manner, " << std::endl
              << "              i.e., using ip address and the length of network prefix seperated by /. " << std::endl
              << "              For example, -i192.168.1.100/24" << std::endl
              << "              Note the range of prefix is [0, 32]. " << std::endl;
    std::cout << "-c<version>   cola version either  -c1 (COLA1) or -c2 (COLA2)" << std::endl;
    std::cout << "-n<IP>        new ip address of the device" << std::endl;
    std::cout << "-m<mask>      network mask of the device" << std::endl;
    std::cout << "-g<IP>        gateway of the device" << std::endl;
    std::cout << "-d            enable dhcp" << std::endl;
    std::cout << "-t<timeout>   broadcast timeout in milliseconds; default is " << DEF_BROADCAST_TIMEOUT << std::endl;

    return static_cast<int>(exitCode);
  }

  exitCode = runAssignDemo(
    destinationMac, colaVersion, interfaceIp, static_cast<uint8_t>(prefix), ipAddr, ipMask, ipGateway, dhcp, timeoutMs);

  std::cout << "exit code " << static_cast<int>(exitCode) << std::endl;

  return static_cast<int>(exitCode);
}