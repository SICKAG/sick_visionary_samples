#
# Copyright (c) 2024 SICK AG, Waldkirch
#
# SPDX-License-Identifier: Unlicense

cmake_minimum_required(VERSION 3.16)

project(spng_miniz
        VERSION 1.0.0
        DESCRIPTION "static spng compiled against miniz"
        LANGUAGES C)

add_library(spng_miniz spng/spng.c miniz/miniz.c)
target_include_directories(spng_miniz PUBLIC spng miniz)
target_compile_definitions(spng_miniz PRIVATE SPNG_USE_MINIZ PUBLIC SPNG_STATIC=ON)
