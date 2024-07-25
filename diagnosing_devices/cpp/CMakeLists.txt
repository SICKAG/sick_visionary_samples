#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.16)

message(STATUS "project: diagnosing_devices")
project(diagnosing_devices
        VERSION 1.0.0
        DESCRIPTION "Devicestate and system log sample"
        LANGUAGES CXX)

### COMPILER FLAGS ###
if(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# root folder and name of the visionary_cpp_base module
set(VISIONARY_BASE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../base/cpp)
set(VISIONARY_BASE_NAME sick_visionary_cpp_base)

# sample code shared folder
set(SHARED_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/cpp)
set(SHARED_CPP_UTILS shared_cpp_utils)

# device base interface, if not already added
if (NOT TARGET sick_visionary_cpp_base)
  add_subdirectory(${VISIONARY_BASE_PATH} ${CMAKE_CURRENT_BINARY_DIR}/base)
endif()

# device shared interface, if not already added
if (NOT TARGET shared_cpp_utils)
  add_subdirectory(${SHARED_PATH} ${CMAKE_CURRENT_BINARY_DIR}/shared)
endif()

# system log example
add_executable(system_log system_log.cpp)
target_link_libraries(system_log
  ${VISIONARY_BASE_NAME}
  ${SHARED_CPP_UTILS})

# device state example
add_executable(device_state device_state.cpp)
target_include_directories(device_state
  PRIVATE
    ${SHARED_PATH})
target_link_libraries(device_state
  ${VISIONARY_BASE_NAME}
  ${SHARED_CPP_UTILS})
