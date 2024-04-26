#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.16)

project(botan)

add_library(botan STATIC src/botan_all.cpp src/botan_all.h)
target_include_directories(botan PUBLIC src)
set_target_properties(botan PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
