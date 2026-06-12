//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#ifndef TIMESTAMP_HELPER_H_INCLUDED
#define TIMESTAMP_HELPER_H_INCLUDED

#include "exitcodes.h"
#include <sick_visionary_cpp_base/VisionaryControl.h>
#include <chrono>

ExitCode printDeviceTime(visionary::VisionaryControl& visionaryControl);

#endif // TIMESTAMP_HELPER_H_INCLUDED