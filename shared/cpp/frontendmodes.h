//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#ifndef IMAGE_STREAMING_AND_STORING_FRONTENDMODES_H_INCLUDED
#define IMAGE_STREAMING_AND_STORING_FRONTENDMODES_H_INCLUDED

#include <cstdint>

#include <sick_visionary_cpp_base/VisionaryControl.h>

namespace visionary {

/// Possible front end modes
enum class FrontendMode : std::uint8_t
{
  eContinuous      = 0, ///< Continuous image acquisition.
  eStopped         = 1, ///< Frontend is stopped, snapshots can be triggered.
  eExternalTrigger = 2  ///< External trigger mode, an external trigger signal is required to acquire images.
};

/// Get the current frontend mode.
///
/// \param[in]  rVisionaryControl The VisionaryControl instance representing the device.
///
/// \returns the current frontend mode.
///
/// \throws std::runtime_error if the frontend mode could not be read.
FrontendMode readFrontendMode(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl);

/// Set the frontend mode (non-permanently).
///
/// \param[in] rVisionaryControl The VisionaryControl instance representing the device.
/// \param[in] mode              The new frontend mode.
///
/// \throws std::runtime_error if the frontend mode could not be set.
void writeFrontendMode(std::shared_ptr<visionary::VisionaryControl> rVisionaryControl, FrontendMode mode);

} // namespace visionary

#endif // IMAGE_STREAMING_AND_STORING_FRONTENDMODES_H_INCLUDED
