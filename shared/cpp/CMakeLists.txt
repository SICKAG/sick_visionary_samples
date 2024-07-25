#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.16)

# Set the project name
project(shared_cpp_utils)

set(SOURCES
    BlobServerConfig.cpp
    DecodeError.cpp
    checkcola.cpp
    framewrite.cpp
    frontendmodes.cpp
    ioports.cpp
    pamwrite.cpp
    pngwrite.cpp
    usertypes.cpp
)

# Create a static library with the above sources
add_library(${PROJECT_NAME} STATIC ${SOURCES})

# Specify the C++ standard
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 11)

# root folder and name of the visionary_cpp_base module
set(VISIONARY_BASE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../base/cpp)
set(VISIONARY_BASE_NAME sick_visionary_cpp_base)

# device base interface, if not already added
if (NOT TARGET sick_visionary_cpp_base)
  add_subdirectory(${VISIONARY_BASE_PATH} ${CMAKE_CURRENT_BINARY_DIR}/base)
endif()

if (NOT TARGET spng_miniz)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../3pp/spng_miniz ${CMAKE_CURRENT_BINARY_DIR}/spng_miniz)
endif()

# Add your header files' path to the include directories
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME}
  ${VISIONARY_BASE_NAME}
  spng_miniz)

