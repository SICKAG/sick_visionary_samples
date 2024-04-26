#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.16)

message(STATUS "project: userlevels_and_passwords")
project(userlevels_and_passwords
        VERSION 1.0.0
        DESCRIPTION "Userlevels and passwords example"
        LANGUAGES CXX)

if (DEFINED ENV{CI_JOB_TOKEN})
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../3pp/botan ${CMAKE_CURRENT_BINARY_DIR}/3pp/botan)
else()
  include(cmake/botan.cmake)
  UseBotan(2 "aes,cbc,hmac,md5,sha2_32,sha2_64,auto_rng,system_rng")
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
set(VISIONARY_BASE_NAME sick_visionary_cpp_base)

# sample code shared folder
set(SHARED_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/cpp)

# device base interface, if not already added
if (NOT TARGET ${VISIONARY_BASE_NAME})
  add_subdirectory(${VISIONARY_BASE_PATH} ${CMAKE_CURRENT_BINARY_DIR}/base)
endif()

add_executable(login_logout login_logout.cpp)
target_include_directories(login_logout
    PRIVATE
    ${SHARED_PATH})
target_link_libraries(login_logout
    ${VISIONARY_BASE_NAME})

# ------------------------------------------------------------------------------------------------

add_executable(password_change
    password_change.cpp)
target_link_libraries(password_change
    ${VISIONARY_BASE_NAME} botan)
target_include_directories(password_change
    PRIVATE
    ${SHARED_PATH})
