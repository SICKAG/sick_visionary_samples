#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.24)

message(STATUS "project: welcome_demo")
project(welcome_demo
        VERSION 1.3.0
        DESCRIPTION "Welcome demo of the visionary programming API"
        LANGUAGES CXX C)

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
set(SHARED_CPP_UTILS shared_cpp_utils)

# device base interface, if not already added
if (NOT TARGET ${VISIONARY_BASE_NAME})
  add_subdirectory(${VISIONARY_BASE_PATH} ${CMAKE_CURRENT_BINARY_DIR}/base)
endif()

# device shared interface, if not already added
if (NOT TARGET ${SHARED_CPP_UTILS})
  add_subdirectory(${SHARED_PATH} ${CMAKE_CURRENT_BINARY_DIR}/shared)
endif()

if (NOT TARGET spng_miniz)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../3pp/spng_miniz ${CMAKE_CURRENT_BINARY_DIR}/spng_miniz)
endif()

add_executable(welcome
# ${SHARED_PATH}/framewrite.cpp
# ${SHARED_PATH}/pngwrite.cpp
welcome.cpp)
# target_include_directories(welcome
#   PRIVATE
#     ${SHARED_PATH})
target_link_libraries(welcome
  ${VISIONARY_BASE_NAME}
  ${SHARED_CPP_UTILS}
  spng_miniz)
