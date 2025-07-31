#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.24)

message(STATUS "project: finding_and_connecting_devices")
project(finding_and_connecting_devices
        VERSION 1.3.0
        DESCRIPTION "Finding, configuring and first interaction with visionary device"
        LANGUAGES CXX)

### COMPILER FLAGS ###
if(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE Release)
endif()

### Configuration
if(WIN32)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON) # If building as shared lib on Windows
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# root folder and name of the visionary_cpp_base module
set(VISIONARY_BASE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../base/cpp)
set(VISIONARY_BASE_NAME sick_visionary_cpp_base::sick_visionary_cpp_base)

# sample code shared folder
set(SHARED_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/cpp)

# device base interface, if not already added
if (NOT TARGET ${VISIONARY_BASE_NAME})
  add_subdirectory(${VISIONARY_BASE_PATH} ${CMAKE_CURRENT_BINARY_DIR}/base)
endif()

# hello sensor example
add_executable(hello_sensor hello_sensor.cpp)
target_include_directories(hello_sensor
  PRIVATE
    ${SHARED_PATH})
target_link_libraries(hello_sensor
  ${VISIONARY_BASE_NAME})

# Find sensor sample
add_executable(find_sensor find_sensor.cpp)
target_include_directories(find_sensor
  PRIVATE
    ${SHARED_PATH})
target_link_libraries(find_sensor
  ${VISIONARY_BASE_NAME})

# Configure sensor sample
add_executable(configure_sensor configure_sensor.cpp)
target_include_directories(configure_sensor
  PRIVATE
    ${SHARED_PATH})
target_link_libraries(configure_sensor
  ${VISIONARY_BASE_NAME})
