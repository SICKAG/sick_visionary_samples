#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.16)

message(STATUS "project: continuous_streaming")
project(continuous_streaming
        VERSION 1.0.0
        DESCRIPTION "Continuous streaming example"
        LANGUAGES CXX C)

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

# device base interface, if not already added
if (NOT TARGET sick_visionary_cpp_base)
  add_subdirectory(${VISIONARY_BASE_PATH} ${CMAKE_CURRENT_BINARY_DIR}/base)
endif()

if (NOT TARGET spng_miniz)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../3pp/spng_miniz ${CMAKE_CURRENT_BINARY_DIR}/spng_miniz)
endif()

add_executable(continuous_streaming
  ${SHARED_PATH}/pamwrite.cpp
  ${SHARED_PATH}/pngwrite.cpp
  ${SHARED_PATH}/framewrite.cpp
  continuous_streaming.cpp
  )
target_include_directories(continuous_streaming
  PRIVATE
    ${SHARED_PATH})
target_link_libraries(continuous_streaming
  ${VISIONARY_BASE_NAME}
  spng_miniz)

add_executable(snapshots
  ${SHARED_PATH}/pamwrite.cpp
  ${SHARED_PATH}/pngwrite.cpp
  ${SHARED_PATH}/framewrite.cpp
  snapshots.cpp
  )
target_include_directories(snapshots
  PRIVATE
    ${SHARED_PATH})
target_link_libraries(snapshots
  ${VISIONARY_BASE_NAME}
  spng_miniz)

add_executable(external_trigger
  ${SHARED_PATH}/checkcola.cpp
  ${SHARED_PATH}/ioports.cpp
  ${SHARED_PATH}/frontendmodes.cpp
  ${SHARED_PATH}/pamwrite.cpp
  ${SHARED_PATH}/pngwrite.cpp
  ${SHARED_PATH}/framewrite.cpp
  external_trigger.cpp
  )
target_include_directories(external_trigger
  PRIVATE
    ${SHARED_PATH})
target_link_libraries(external_trigger
  ${VISIONARY_BASE_NAME}
  spng_miniz)
