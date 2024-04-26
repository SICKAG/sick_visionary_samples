#ifndef SHARED_IOPORTS_H_INCLUDED
#define SHARED_IOPORTS_H_INCLUDED

#include <cstdint>
#include <string>

#include <VisionaryControl.h>

namespace visionary {

/// Possible input-only function types (Visionary-S and Visionary-T CX/AG/DT).
enum class InputFunctionType : std::uint8_t
{
  eNoFunction    = 0, ///< no function assigned (inactive)
  ePowerSaveMode = 1, ///< power-save mode input
  eTrigger       = 2, ///< external hardware trigger input (only allowed for SENS_IN1)
  eJobSwitching  = 4, ///< job switching input
  eJobCycling    = 5  ///< job cycling input
};

/// Possible IO function types.
enum class IOFunctionType : std::uint8_t
{
  eNoFunction          = 0,  ///< no function assigned (inactive).
  eSteadyLOW           = 1,  ///< steady LOW output.
  eSteadyHIGH          = 2,  ///< steady HIGH output.
  eDeviceStatus        = 3,  ///< device status output.
  eDataQualityCheck    = 4,  ///< data quality output (Visionary-S CX and Visionary-T CX only).
  eTemperatureWarning  = 5,  ///< temperature warning output.
  eTrigger             = 7,  ///< external trigger input (Visionary-T Mini CX, for Visionary-S CX only on SENS_IN1).
  eTriggerBusy         = 23, ///< external trigger process output (Visionary-T Mini CX only).
  ePowerSaveMode       = 24, ///< power-save mode input (Visionary-T Mini CX only).
  eJobSwitching        = 25, ///< job switching input (Visionary-S CX and Visionary-T CX only).
  eIlluminationTrigger = 28, ///< RGB flash-sync (only Visionary-S CX on INOUT4).
  eHeartbeatOut        = 29  ///< output a device-alive heartbeat signal(Visionary-T CX/AG/DT only).
};

/// Possible digital IO ports.
///
/// These are bi-directional ports. Their direction (input or output) is determined by the function type.
///
/// Which ports are available depends on the device model. The following table shows the available ports for each device
/// model:
///
/// | Device model | Available ports |
/// |--------------|-----------------|
/// | Visionary-S  | INOUT1, INOUT2, INOUT3, INOUT4 |
/// | Visionary-T  | INOUT1, INOUT2, INOUT3, INOUT4 |
/// | Visionary-T Mini | INOUT1, INOUT2, INOUT3, INOUT4, INOUT5, INOUT6 |
enum class DioPort
{
  eINOUT1 = 0,
  eINOUT2 = 1,
  eINOUT3 = 2,
  eINOUT4 = 3,
  eINOUT5 = 4,
  eINOUT6 = 5
};

/// Possible digital input-only ports.
///
/// These ports are input-only. They can be used for input function types only.
///
/// Which ports are available depends on the device model. The following table shows the available ports for each device
/// model:
///
/// | Device model | Available ports |
/// |--------------|-----------------|
/// | Visionary-S  | SENS_IN1, SENS_IN2 |
/// | Visionary-T  | SENS_IN1, SENS_IN2 |
/// | Visionary-T Mini | -- |
enum class DInPort
{
  eSENS_IN1 = 0u,
  eSENS_IN2 = 1u
};

/// Get the port name of a digital input port.
///
/// \param[in]  port The port to get the name from.
/// \returns the name of the port or an empty string if the port is invalid.
std::string getInPortName(DInPort port);

/// Get the port enum value from an input port name.
///
/// \param[in]  name The name of the port.
/// \returns the port enum value.
///
/// \throws std::invalid_argument if the port name is invalid.
DInPort getInPortFromName(const std::string& name);

/// Get the port name of a digital IO port.
///
/// \param[in]  port The port to get the name from.
/// \returns the name of the port or an empty string if the port is invalid.
///
std::string getInOutPortName(DioPort port);

/// Get the port enum value from an in/out port name.
///
/// \param[in]  name The name of the port.
/// \returns the port enum value.
///
/// \throws std::invalid_argument if the port name is invalid.
DioPort getInOutPortFromName(const std::string& name);

/// Read the currently active input function type of a digital input port.
///
/// \param[in]  rVisionaryControl the VisionaryControl instance to use for communication.
/// \param[in]  port The port to get the input function type from.
///
/// \returns the currently active input function type of the port (eNoFunction if the port is inactive).
///
/// \throws std::runtime_error if an communication/protocol error occurred.
InputFunctionType readDioFunction(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DInPort port);

/// Write the input function type of a digital input port.
///
/// \param[in]  rVisionaryControl the VisionaryControl instance to use for communication.
/// \param[in]  port The port to set the input function type for.
/// \param[in]  type The input function type to set.
///
/// \throws std::runtime_error if the input function type could not be set or a communication/protocol error occurred.
///
/// \note Not all sensor models support all input function types. If an unsupported input function type is set, a CoLa
/// error will occur.
void writeDioFunction(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DInPort port, InputFunctionType type);

/// Read the current polarity of a digital input port.
///
/// \param[in]  rVisionaryControl the VisionaryControl instance to use for communication.
/// \param[in]  port The port to get the polarity from.
///
/// \retval true  if the port polarity is high.
/// \retval false if the port polarity is low.
///
/// \throws std::runtime_error if an communication/protocol error occurred.
bool readDioPortPolarity(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DInPort port);

/// Write the polarity of a digital input port.
///
/// \param[in]  rVisionaryControl the VisionaryControl instance to use for communication.
/// \param[in]  port  The port to set the polarity for.
/// \param[in]  polarity The polarity to set (true for high, false for low).
///
/// \throws std::runtime_error if the port polarity could not be set or a communication/protocol error occurred.
void writeDioPortPolarity(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DInPort port, bool polarity);

/// Read the currently active IO function type of a digital IO port.
///
/// \param[in]  rVisionaryControl the VisionaryControl instance to use for communication.
/// \param[in]  port The port to get the IO function type from.
///
/// \returns the currently active IO function type of the port (eNoFunction if the port is inactive).
///
/// \throws std::runtime_error if an communication/protocol error occurred.
IOFunctionType readDioFunction(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DioPort port);

/// Write the IO function type of a digital IO port.
///
/// This functions sets both the function type and direction of the port. If the function type is an input function
/// type, the port will be set to input mode. If the function type is an output function type, the port will be set to
/// output.
///
/// \param[in]  rVisionaryControl the VisionaryControl instance to use for communication.
/// \param[in]  port The port to set the IO function type for.
/// \param[in]  type The IO function type to set.
///
/// \throws std::runtime_error if the IO function type could not be set or a communication/protocol error occurred.
void writeDioFunction(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, DioPort port, IOFunctionType type);

/// Read the current polarity of a digital IO port.
///
/// \param[in]  rVisionaryControl the VisionaryControl instance to use for communication.
/// \param[in]  port The port to get the polarity from.
///
/// \retval true  if the port polarity is high.
/// \retval false if the port polarity is low.
///
/// \throws std::runtime_error if an communication/protocol error occurred.
bool readDioPortPolarity(VisionaryControl& rVisionaryControl, DioPort port);

/// Write the polarity of a digital IO port.
///
/// \param[in]  rVisionaryControl the VisionaryControl instance to use for communication.
/// \param[in]  port  The port to set the polarity for.
/// \param[in]  polarity The polarity to set (true for high, false for low).
///
/// \throws std::runtime_error if the port polarity could not be set or a communication/protocol error occurred.
void writeDioPortPolarity(VisionaryControl& rVisionaryControl, DioPort port, bool polarity);

} // namespace visionary

#endif // SHARED_IOPORTS_H_INCLUDED