//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#ifndef IMAGE_STREAMING_AND_STORING_PNGWRITE_H_INCLUDED
#define IMAGE_STREAMING_AND_STORING_PNGWRITE_H_INCLUDED

#include <spng.h>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <cstdio>

int write_png_u16(const std::string& file_name, std::vector<uint16_t>& image_data, const std::uint32_t width, const std::uint32_t height);

int write_png_rgba(const std::string& file_name, std::vector<std::uint32_t>& image_data, const std::uint32_t width, const std::uint32_t height);


#endif // IMAGE_STREAMING_AND_STORING_PNGWRITE_H_INCLUDED