//
// Copyright (c) 2026 SICK AG, Waldkirch
//
// SPDX-License-Identifier: MIT

#include <chrono>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <sick_visionary_cpp_base/VisionaryType.h>

#include "exitcodes.h"

namespace {

enum class ReconnectMode
{
  Recreate,
  Reuse
};

bool isDeviceIdentValid(const visionary::DeviceIdent& deviceIdent)
{
  return !deviceIdent.name.empty() && !deviceIdent.version.empty();
}

bool openControl(visionary::VisionaryControl& control, const std::string& ipAddress, bool autoReconnect)
{
  return control.open(ipAddress, visionary::VisionaryControl::kSessionTimeout, autoReconnect);
}

ExitCode runConnectionTest(visionary::VisionaryType visionaryType,
                           const std::string&      ipAddress,
                           int                     pollIntervalMs,
                           int                     reconnectIntervalMs,
                           ReconnectMode           reconnectMode,
                           bool                    autoReconnect)
{
  std::cout << "Starting connection monitor for " << ipAddress << " (mode="
            << ((reconnectMode == ReconnectMode::Recreate) ? "recreate" : "reuse")
            << ", poll=" << pollIntervalMs << "ms"
            << ", reconnect=" << reconnectIntervalMs << "ms"
            << ", autoReconnect=" << (autoReconnect ? "true" : "false") << ")\n";
  std::cout << "Unplug/replug the Ethernet cable and observe the output. Stop with Ctrl+C.\n";

  std::unique_ptr<visionary::VisionaryControl> pControl;

  while (true)
  {
    if (!pControl)
    {
      // tag::open_control[]
      pControl = std::unique_ptr<visionary::VisionaryControl>(new visionary::VisionaryControl(visionaryType));
      if (!openControl(*pControl, ipAddress, autoReconnect))
      {
        std::cout << "[connect-failed] open() failed\n";
        pControl.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(reconnectIntervalMs));
        continue;
      }

      const visionary::DeviceIdent deviceIdent = pControl->getDeviceIdent();
      if (isDeviceIdentValid(deviceIdent))
      {
        std::cout << "[connected] Device Name: '" << deviceIdent.name << "', Device Version: '" << deviceIdent.version
                  << "'\n";
      }
      else
      {
        std::cout << "[connected-but-no-ident] getDeviceIdent() returned empty values\n";
      }
      // end::open_control[]
    }

    // tag::poll_ident[]
    const visionary::DeviceIdent deviceIdent = pControl->getDeviceIdent();
    if (isDeviceIdentValid(deviceIdent))
    {
      std::cout << "[alive] Device Name: '" << deviceIdent.name << "', Device Version: '" << deviceIdent.version << "'\n";
      std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs));
      continue;
    }

    std::cout << "[connection-lost] getDeviceIdent() returned empty values\n";
    // end::poll_ident[]

    // tag::reconnect[]
    if (reconnectMode == ReconnectMode::Reuse)
    {
      pControl->close();
      std::this_thread::sleep_for(std::chrono::milliseconds(reconnectIntervalMs));

      if (openControl(*pControl, ipAddress, autoReconnect))
      {
        const visionary::DeviceIdent reconnectIdent = pControl->getDeviceIdent();
        if (isDeviceIdentValid(reconnectIdent))
        {
          std::cout << "[reconnected-reuse] Device Name: '" << reconnectIdent.name
                    << "', Device Version: '" << reconnectIdent.version << "'\n";
          continue;
        }
      }

      std::cout << "[reuse-open-failed] retry with fresh object\n";
    }

    pControl->close();
    pControl.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(reconnectIntervalMs));
    // end::reconnect[]
  }
}

} // namespace

int main(int argc, char* argv[])
{
  std::string              deviceIpAddr("192.168.1.10");
  visionary::VisionaryType visionaryType(visionary::VisionaryType::eVisionaryTMini);
  int                      pollIntervalMs      = 1000;
  int                      reconnectIntervalMs = 1000;
  ReconnectMode            reconnectMode       = ReconnectMode::Recreate;
  bool                     autoReconnect       = false;

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
        argstream >> deviceIpAddr;
        break;
      case 't':
      {
        std::string visionaryTypeName;
        argstream >> visionaryTypeName;
        try
        {
          visionaryType = visionary::VisionaryType::fromString(visionaryTypeName);
        }
        catch (const std::invalid_argument& e)
        {
          std::cerr << e.what() << ": '" << visionaryTypeName << "'\n";
          showHelpAndExit = true;
          exitCode        = ExitCode::eParamError;
        }
      }
      break;
      case 'p':
        argstream >> pollIntervalMs;
        break;
      case 'r':
        argstream >> reconnectIntervalMs;
        break;
      case 'm':
      {
        std::string mode;
        argstream >> mode;
        if (mode == "recreate")
        {
          reconnectMode = ReconnectMode::Recreate;
        }
        else if (mode == "reuse")
        {
          reconnectMode = ReconnectMode::Reuse;
        }
        else
        {
          std::cerr << "Invalid mode: '" << mode << "' (expected recreate or reuse)\n";
          showHelpAndExit = true;
          exitCode        = ExitCode::eParamError;
        }
      }
      break;
      case 'a':
      {
        int autoReconnectInt = 0;
        argstream >> autoReconnectInt;
        autoReconnect = (autoReconnectInt != 0);
      }
      break;
      default:
        showHelpAndExit = true;
        exitCode        = ExitCode::eParamError;
        break;
    }
  }

  if (pollIntervalMs < 1 || reconnectIntervalMs < 1)
  {
    std::cerr << "-p and -r must be >= 1 ms\n";
    return static_cast<int>(ExitCode::eParamError);
  }

  if (showHelpAndExit)
  {
    std::cout << argv[0] << " [option]*\n";
    std::cout << "where option is one of\n";
    std::cout << "-h              show this help and exit\n";
    std::cout << "-i<IP>          connect to device with IP <IP>; default is 192.168.1.10\n";
    std::cout << "-t<typename>    visionary product type; default is '" << visionaryType.toString() << "'\n";
    std::cout << "-p<ms>          poll interval in ms for getDeviceIdent(); default is 1000\n";
    std::cout << "-r<ms>          reconnect interval in ms after connection loss; default is 1000\n";
    std::cout << "-m<mode>        reconnect mode: recreate | reuse; default is recreate\n";
    std::cout << "-a<0|1>         enable VisionaryControl autoReconnect in open(); default is 0\n";
    std::cout << "Visionary product types:\n";
    for (const auto& name : visionary::VisionaryType::getNames())
    {
      std::cout << "  " << name << '\n';
    }

    return static_cast<int>(exitCode);
  }

  exitCode = runConnectionTest(
    visionaryType, deviceIpAddr, pollIntervalMs, reconnectIntervalMs, reconnectMode, autoReconnect);

  std::cout << "exit code " << static_cast<int>(exitCode) << "\n";
  return static_cast<int>(exitCode);
}
