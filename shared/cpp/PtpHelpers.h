//
// Copyright (c) 2026 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#ifndef PTP_HELPERS_H_INCLUDED
#define PTP_HELPERS_H_INCLUDED

#include <cstdint>
#include <string>

#include <sick_visionary_cpp_base/VisionaryControl.h>

const char* ptpStateToString(std::uint8_t state);
std::string getPtpState(visionary::VisionaryControl& visionaryControl);

#endif // PTP_HELPERS_H_INCLUDED