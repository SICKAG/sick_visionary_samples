//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include "ioports.h"

#include <stdexcept>

#include <CoLaCommand.h>
#include <CoLaParameterReader.h>
#include <CoLaParameterWriter.h>

#include "checkcola.h"

// private definitions
namespace {

static const char* getOutputFunctionVarName(visionary::DioPort port)
{
  using namespace visionary;

  switch (port)
  {
    case DioPort::eINOUT1:
      return "DIO1Fnc";
      break;

    case DioPort::eINOUT2:
      return "DIO2Fnc";
      break;

    case DioPort::eINOUT3:
      return "DIO3Fnc";
      break;

    case DioPort::eINOUT4:
      return "DIO4Fnc";
      break;

    case DioPort::eINOUT5:
      return "DIO5Fnc";
      break;

    case DioPort::eINOUT6:
      return "DIO6Fnc";
      break;

    default:
      return "";
  }
}

static const char* getInputFunctionVarName(visionary::DInPort port)
{
  using namespace visionary;

  switch (port)
  {
    case DInPort::eSENS_IN1:
      return "SENS_IN1Func";
      break;

    case DInPort::eSENS_IN2:
      return "SENS_IN2Func";
      break;

    default:
      return "";
  }
}

static const char* getPortLevelVarName(visionary::DInPort port)
{
  using namespace visionary;

  switch (port)
  {
    case DInPort::eSENS_IN1:
      return "SENS_IN1_active";
      break;

    case DInPort::eSENS_IN2:
      return "SENS_IN2_active";
      break;

    default:
      throw std::invalid_argument("Invalid port: " + std::to_string(static_cast<int>(port)));
  }
}

static const char* getPortLevelVarName(visionary::DioPort port)
{
  using namespace visionary;

  switch (port)
  {
    case DioPort::eINOUT1:
      return "OUT1_active";
      break;

    case DioPort::eINOUT2:
      return "OUT2_active";
      break;

    case DioPort::eINOUT3:
      return "OUT3_active";
      break;

    case DioPort::eINOUT4:
      return "OUT4_active";
      break;

    case DioPort::eINOUT5:
      return "OUT5_active";
      break;

    case DioPort::eINOUT6:
      return "OUT6_active";
      break;

    default:
      throw std::invalid_argument("Invalid port: " + std::to_string(static_cast<int>(port)));
  }
}

} // namespace

// -----------------------------------------------------------------------------
// public definitions

namespace visionary {

std::string getInOutPortName(DioPort port)
{
  switch (port)
  {
    case DioPort::eINOUT1:
      return "INOUT1";
    case DioPort::eINOUT2:
      return "INOUT2";
    case DioPort::eINOUT3:
      return "INOUT3";
    case DioPort::eINOUT4:
      return "INOUT4";
    case DioPort::eINOUT5:
      return "INOUT5";
    case DioPort::eINOUT6:
      return "INOUT6";
    default:
      throw std::invalid_argument("Invalid port: " + std::to_string(static_cast<int>(port)));
  }
}

DioPort getInOutPortFromName(const std::string& name)
{
  if (name == "INOUT1")
  {
    return DioPort::eINOUT1;
  }
  else if (name == "INOUT2")
  {
    return DioPort::eINOUT2;
  }
  else if (name == "INOUT3")
  {
    return DioPort::eINOUT3;
  }
  else if (name == "INOUT4")
  {
    return DioPort::eINOUT4;
  }
  else if (name == "INOUT5")
  {
    return DioPort::eINOUT5;
  }
  else if (name == "INOUT6")
  {
    return DioPort::eINOUT6;
  }
  else
  {
    throw std::invalid_argument("Invalid port name: " + name);
  }
}

std::string getInPortName(DInPort port)
{
  switch (port)
  {
    case DInPort::eSENS_IN1:
      return "SENS_IN1";
    case DInPort::eSENS_IN2:
      return "SENS_IN2";
    default:
      throw std::invalid_argument("Invalid port: " + std::to_string(static_cast<int>(port)));
  }
}

DInPort getInPortFromName(const std::string& name)
{
  if (name == "SENS_IN1")
  {
    return DInPort::eSENS_IN1;
  }
  else if (name == "SENS_IN2")
  {
    return DInPort::eSENS_IN2;
  }
  else
  {
    throw std::invalid_argument("Invalid port name: " + name);
  }
}

IOFunctionType readDioFunction(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DioPort port)
{
  using namespace visionary;

  const auto pVarName = getOutputFunctionVarName(port);

  CoLaCommand cmd  = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, pVarName).build();
  CoLaCommand resp = rVisionaryControl->sendCommand(cmd);
  checkReadResponse(resp, pVarName);
  CoLaParameterReader reader(resp);
  return static_cast<IOFunctionType>(reader.readUSInt());
}

void writeDioFunction(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DioPort port, IOFunctionType type)
{
  using namespace visionary;

  const auto pVarName = getOutputFunctionVarName(port);

  CoLaCommand cmd =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, pVarName).parameterUSInt(static_cast<uint8_t>(type)).build();
  CoLaCommand resp = rVisionaryControl->sendCommand(cmd);
  checkWriteResponse(resp, pVarName);
}

InputFunctionType readDioFunction(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DInPort port)
{
  using namespace visionary;

  const auto pVarName = getInputFunctionVarName(port);

  CoLaCommand cmd  = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, pVarName).build();
  CoLaCommand resp = rVisionaryControl->sendCommand(cmd);
  checkReadResponse(resp, pVarName);
  CoLaParameterReader reader(resp);
  return static_cast<InputFunctionType>(reader.readUSInt());
}

void writeDioFunction(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DInPort port, InputFunctionType type)
{
  using namespace visionary;

  const auto pVarName = getInputFunctionVarName(port);

  CoLaCommand cmd =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, pVarName).parameterUSInt(static_cast<uint8_t>(type)).build();
  CoLaCommand resp = rVisionaryControl->sendCommand(cmd);
  checkWriteResponse(resp, pVarName);
}

bool readDioPortPolarity(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DInPort port)
{
  using namespace visionary;

  const auto pVarName = getPortLevelVarName(port);

  CoLaCommand cmd  = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, pVarName).build();
  CoLaCommand resp = rVisionaryControl->sendCommand(cmd);
  checkReadResponse(resp, pVarName);
  CoLaParameterReader reader(resp);
  return (reader.readUSInt() != 0);
}

void writeDioPortPolarity(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DInPort port, bool polarity)
{
  using namespace visionary;

  const auto pVarName = getPortLevelVarName(port);

  CoLaCommand cmd =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, pVarName).parameterUSInt(polarity ? 1u : 0u).build();
  CoLaCommand resp = rVisionaryControl->sendCommand(cmd);
  checkWriteResponse(resp, pVarName);
}

bool readDioPortPolarity(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DioPort port)
{
  using namespace visionary;

  const auto pVarName = getPortLevelVarName(port);

  CoLaCommand cmd  = CoLaParameterWriter(CoLaCommandType::READ_VARIABLE, pVarName).build();
  CoLaCommand resp = rVisionaryControl->sendCommand(cmd);
  checkReadResponse(resp, pVarName);
  CoLaParameterReader reader(resp);
  return (reader.readUSInt() != 0);
}

void writeDioPortPolarity(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DioPort port, bool polarity)
{
  using namespace visionary;

  const auto pVarName = getPortLevelVarName(port);

  CoLaCommand cmd =
    CoLaParameterWriter(CoLaCommandType::WRITE_VARIABLE, pVarName).parameterUSInt(polarity ? 1u : 0u).build();
  CoLaCommand resp = rVisionaryControl->sendCommand(cmd);
  checkWriteResponse(resp, pVarName);
}

} // namespace visionary