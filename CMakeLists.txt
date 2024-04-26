#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.16)

project(sick_visionary_samples
        VERSION 1.0.0
        DESCRIPTION "samples for Visionary devices"
        HOMEPAGE_URL "https://github.com/SICKAG/sick_visionary_samples"
        LANGUAGES CXX)

# add sample projects
add_subdirectory(base/cpp)
add_subdirectory(diagnosing_devices/cpp)
add_subdirectory(finding_and_connecting_devices/cpp)
add_subdirectory(image_frontend_configuration/cpp)
add_subdirectory(image_streaming_and_storing/cpp)
add_subdirectory(userlevels_and_passwords/cpp)
add_subdirectory(visionary_welcome/cpp)
