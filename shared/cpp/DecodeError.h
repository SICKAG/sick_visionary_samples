//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#pragma once

#include <cstdint>
#include <unordered_map>
#include <string>


std::string decodeErrorCode(std::uint32_t error_code, std::string device_type);

// ERROR_DICT_T_MINI/ERROR_DICT_VISIONARY_S maps the subsystem-value and errorname-value to the error description
// as definded in V3SXX5_1_CX.cid.processed.xml
const std::unordered_map<uint8_t, std::unordered_map<uint8_t, std::string>> ERROR_DICT_VISIONARY_T_MINI ={
{0, {
    {1, "Debug Information"},
    {2, "Debug Warning"},
    {3, "Debug Error"},
    {4, "Debug Fatal Error"},
    {5, "Unknown Error"},
    {10, "Error from SPEED"},
    {11, "Warning from SPEED"},
    {12, "Info from SPEED"},
    {30, "Reset by Power On"},
    {31, "Reset by Assertion"},
    {32, "Reset by Unhandled Interrupt"},
    {33, "Reset on boot abandoned"},
    {34, "Reset by clearing Application Magic"},
    {35, "Reset by Sopas method Softreset"},
    {36, "Reset by Sopas method Reset Device"},
    {37, "Reset needed because of Ethernet Parameter change"},
    {38, "Performing firmware update"}
}},
{15, {
    {1, "Connection established"},
    {2, "Connection lost"},
    {3, "Transmit failed"},
    {4, "No ethernet cable"},
    {5, "Connection aborted"},
    {6, "Connection closed by peer"},
    {7, "Connection closing"},
    {8, "Connection released"},
    {9, "Connection timed out"},
    {10, "Connection open failed"},
    {11, "Tx failed with error code"},
    {12, "Rx failed with error code"},
    {13, "Open failed with error code"},
    {14, "Close failed with error code"},
    {15, "Listen failed"},
    {16, "Bind failed"},
    {17, "Accept failed"},
    {18, "Reached maximum client connections"},
    {19, "Server not reachable"},
    {27, "Successfully assigned IP-Address via DHCP"},
    {28, "DHCP server reply timed out"},
    {29, "IP-Address conflict detected"}
}},
{129, {
    {0, "System entered a power-saving state"},
    {1, "A critical hardware component is missing or malfunctioning"},
    {2, "A hardware component is missing or malfunctioning"},
    {3, "A non-vital hardware component is missing or malfunctioning"},
    {4, "The Total Acquisition time is too low or the Integration Time(s) are too high"}
}},
{130, {
    {0, "Temperature reaches warning levels"},
    {1, "Temperature reaches critical levels"},
    {2, "An output port was overloaded, possibly due to a short circuit"},
    {3, "A port can't be connected."},
    {4, "A port was overheated."},
    {5, "A port has undervoltage."},
    {6, "The operating voltage is outside range"},
    {7, "The illumination not working properly"},
    {8, "The illumination is not working"},
    {9, "The illumination has a fatal error"},
    {10, "Eye safety error"}
}},
{131, {
    {0, "Unreliable measurement warning"},
    {1, "Invalid or no measurement"}
}},
{132, {
    {0, "Data upgrade was performed"},
    {1, "Some non-critical user data could not be upgraded"},
    {2, "Data upgrade failed, production data could not be read"},
    {3, "Data upgrade failed, production data were corrupted"}
}},
{151, {
    {0, "Frames were lost due to slow receiver"}
}}};

const std::unordered_map<int, std::unordered_map<int, std::string>> ERROR_DICT_VISIONARY_S ={
{0, {
    {1, "Debug Information"},
    {2, "Debug Warning"},
    {3, "Debug Error"},
    {4, "Debug Fatal Error"},
    {5, "Unknown Error"},
    {10, "Error from SPEED"},
    {11, "Warning from SPEED"},
    {12, "Info from SPEED"},
    {20, "Error from RAPID"},
    {21, "Warning from RAPID"},
    {22, "Info from RAPID"},
    {30, "Reset by Power On"},
    {31, "Reset by Assertion"},
    {32, "Reset by Unhandled Interrupt"},
    {33, "Reset on boot abandoned"},
    {34, "Reset by clearing Application Magic"},
    {35, "Reset by Sopas method Softreset"},
    {36, "Reset by Sopas method Reset Device"},
    {37, "Reset needed because of Ethernet Parameter change"}
}},
{5, {
    {0, "File I/O failed"},
    {1, "Storage device not found"},
    {10, "Memory card detected"},
    {11, "Problem occured accessing memory card"},
    {12, "File system on sd card is damaged"}
}},
{14, {
    {1, "Test error for level INFO"},
    {2, "Test error for level WARNING"},
    {3, "Test error for level ERROR"},
    {4, "Test error for level FATALERROR"}
}},
{15, {
    {1, "Connection established"},
    {2, "Connection lost"},
    {3, "Transmit failed"},
    {4, "No ethernet cable"},
    {5, "Connection aborted"},
    {6, "Connection closed by peer"},
    {7, "Connection closing"},
    {8, "Connection released"},
    {9, "Connection timed out"},
    {10, "Connection open failed"},
    {11, "Tx failed with error code"},
    {12, "Rx failed with error code"},
    {13, "Open failed with error code"},
    {14, "Close failed with error code"},
    {15, "Listen failed"},
    {16, "Bind failed"},
    {17, "Accept failed"},
    {18, "Reached maximum client connections"},
    {19, "Server not reachable"},
    {20, "FTP open failed"},
    {21, "FTP password failed"},
    {22, "FTP unknown user"},
    {23, "FTP command CWD failed"},
    {24, "FTP command STOR failed"},
    {25, "FTP command TYPE failed"},
    {26, "FTP failed to open local file"},
    {27, "Successfully assigned IP-Address via DHCP"},
    {28, "DHCP server reply timed out"}
}},
{19, {
    {1, "Error at loading CSAD"},
    {2, "Successfully loaded CSAD"},
    {3, "Error at loading CSFD"},
    {4, "Successfully loaded CSFD"}
}},
{129, {
    {0, "System entered a power-saving state"},
    {1, "A critical hardware component is missing or malfunctioning"},
    {2, "A hardware component is missing or malfunctioning"},
    {3, "A non-vital hardware component is missing or malfunctioning"},
    {4, "The Total Acquisition time is too low or the Integration Time(s) are too high"}
}},
{130, {
    {0, "Temperature reaches warning levels"},
    {1, "Temperature reaches critical levels"},
    {2, "An output port was overloaded, possibly due to a short circuit"},
    {3, "The operating voltage is outside range"},
    {4, "The illumination not working properly"},
    {5, "The illumination is not working"},
    {6, "The illumination has a fatal error"},
    {7, "An output port was overheated, possibly due to a short circuit"},
    {8, "An output port has an undervoltage error"}
}},
{131, {
    {0, "Unreliable measurement warning"},
    {1, "Invalid or no measurement"}
}},
{132, {
    {0, "Data upgrade was performed"},
    {1, "Some non-critical user data could not be upgraded"},
    {2, "Data upgrade failed, production data could not be read"},
    {3, "Data upgrade failed, production data were corrupted"},
    {4, "System update failed"}
}},
{149, {
    {0, "Unspecific application warning"},
    {1, "Unspecific application error"},
    {2, "Unspecific application initialization warning"},
    {3, "Unspecific application initialization error"},
    {4, "Frames are acquired faster than the internal processing takes"}
}},
{150, {
   {0, "A sopas Parameter was referenced in Blocks.xml but not found in Sopas Repository"},
   {1, "The configuration file for function blocks was not found"}
}},
{151, {
    {0, "Frames were lost due to slow receiver"}
}}};