#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.24)

message(STATUS "Project: Time synchronization")
project(time_synchronization
        VERSION 1.0.0
        DESCRIPTION "NTP/PTP time synchronization example"
        LANGUAGES CXX)

### Configuration
if(WIN32)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON) # If building as shared lib on Windows
endif()

### COMPILER FLAGS ###
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# root folder and name of the visionary_cpp_base module
set(VISIONARY_BASE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../base/cpp)
set(VISIONARY_BASE_NAME sick_visionary_cpp_base::sick_visionary_cpp_base)

# sample code shared folder
set(SHARED_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/cpp)
set(SHARED_CPP_UTILS shared_cpp_utils)

# device base interface, if not already added
if (NOT TARGET ${VISIONARY_BASE_NAME})
  add_subdirectory(${VISIONARY_BASE_PATH} ${CMAKE_CURRENT_BINARY_DIR}/base)
endif()

# device shared interface, if not already added
if (NOT TARGET ${SHARED_CPP_UTILS})
  add_subdirectory(${SHARED_PATH} ${CMAKE_CURRENT_BINARY_DIR}/shared)
endif()

# device base interface, if not already added
if (NOT TARGET ${VISIONARY_BASE_NAME})
  add_subdirectory(${VISIONARY_BASE_PATH} ${CMAKE_CURRENT_BINARY_DIR}/base)
endif()

# NTP Sample
add_executable(ntp_sync ntp_sync.cpp)
target_include_directories(ntp_sync
    PRIVATE
    ${SHARED_PATH})
target_link_libraries(ntp_sync
    ${VISIONARY_BASE_NAME}
    ${SHARED_CPP_UTILS})

# PTP Sample
add_executable(ptp_sync ptp_sync.cpp)
target_include_directories(ptp_sync
    PRIVATE
    ${SHARED_PATH})
target_link_libraries(ptp_sync
    ${VISIONARY_BASE_NAME}
    ${SHARED_CPP_UTILS})