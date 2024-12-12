#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.24)

project(botan)

### Configuration
if(WIN32)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON) # If building as shared lib on Windows
endif()

add_library(botan STATIC src/botan_all.cpp src/botan_all.h)
target_include_directories(botan PUBLIC src)
set_target_properties(botan PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
