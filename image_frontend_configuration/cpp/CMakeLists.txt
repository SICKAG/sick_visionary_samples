#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.16)

message(STATUS "project: image_frontend_configuration")
project(image_frontend_configuration
        VERSION 1.0.0
        DESCRIPTION "Shows how to configure the frontend settings of Visionary devices"
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

# device base interface, if not already added
if (NOT TARGET sick_visionary_cpp_base)
  add_subdirectory(${VISIONARY_BASE_PATH} ${CMAKE_CURRENT_BINARY_DIR}/base)
endif()

# Visionary-S example
add_executable(visionary_s_frontend_config visionary_s_frontend_config.cpp)
target_include_directories(visionary_s_frontend_config
  PRIVATE
    ${SHARED_PATH})
target_link_libraries(visionary_s_frontend_config
  ${VISIONARY_BASE_NAME})

# Visionary-T Mini example
add_executable(visionary_t_mini_frontend_config visionary_t_mini_frontend_config.cpp)
target_include_directories(visionary_t_mini_frontend_config
  PRIVATE
    ${SHARED_PATH})
target_link_libraries(visionary_t_mini_frontend_config
  ${VISIONARY_BASE_NAME})

# Save parameters permanently example
add_executable(save_permanently save_permanently.cpp)
target_include_directories(save_permanently
  PRIVATE
    ${SHARED_PATH})
target_link_libraries(save_permanently
  ${VISIONARY_BASE_NAME})
