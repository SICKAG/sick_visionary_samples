//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include "pngwrite.h"

int write_png_u16(const std::string& file_name, std::vector<uint16_t>& image_data, const std::uint32_t width, const std::uint32_t height)
{
    // Convert std::vector<uint16_t> to unsigned char*
    unsigned char *image = reinterpret_cast<unsigned char*>(image_data.data());

    FILE *fp = fopen(file_name.c_str(), "wb");
    if(!fp) throw std::runtime_error("Failed to open file for writing");

    int fmt;
    int ret = 0;
    spng_ctx *ctx = NULL;
    struct spng_ihdr ihdr = {0}; // zero-initialize to set valid defaults

    // Creating an encoder context requires a flag
    ctx = spng_ctx_new(SPNG_CTX_ENCODER);

    // Set an output FILE
    spng_set_png_file(ctx, fp);

    // Set image properties, this determines the destination image format
    ihdr.width = width;
    ihdr.height = height;
    ihdr.color_type = SPNG_COLOR_TYPE_GRAYSCALE;
    ihdr.bit_depth = 16;

    spng_set_ihdr(ctx, &ihdr);

    // When encoding fmt is the source format
    // SPNG_FMT_PNG is a special value that matches the format in ihdr
    fmt = SPNG_FMT_PNG;

    size_t image_size, image_width;

    ret = spng_decoded_image_size(ctx, fmt, &image_size);
    
    if(ret)
    {
        printf("spng_decoded_image_size() error: %s\n", spng_strerror(ret));
        goto encode_error;
    }

    // SPNG_ENCODE_FINALIZE will finalize the PNG with the end-of-file marker
    ret = spng_encode_image(ctx, image, image_size, fmt, SPNG_ENCODE_FINALIZE);

    if(ret)
    {
        printf("spng_encode_image() error: %s\n", spng_strerror(ret));
        goto encode_error;
    }

    encode_error:
        spng_ctx_free(ctx);

    return ret;
}

int write_png_rgba(const std::string& file_name, std::vector<std::uint32_t>& image_data, const std::uint32_t width, const std::uint32_t height)
{
    // Convert std::vector<uint32_t> to unsigned char*
    unsigned char *image = reinterpret_cast<unsigned char*>(image_data.data());

    FILE *fp = fopen(file_name.c_str(), "wb");
    if(!fp) throw std::runtime_error("Failed to open file for writing");

    int fmt;
    int ret = 0;
    spng_ctx *ctx = NULL;
    struct spng_ihdr ihdr = {0}; // zero-initialize to set valid defaults

    // Creating an encoder context requires a flag
    ctx = spng_ctx_new(SPNG_CTX_ENCODER);

    // Set an output FILE
    spng_set_png_file(ctx, fp);

    // Set image properties, this determines the destination image format
    ihdr.width = width;
    ihdr.height = height;
    ihdr.color_type = SPNG_COLOR_TYPE_TRUECOLOR_ALPHA;
    ihdr.bit_depth = 8;

    spng_set_ihdr(ctx, &ihdr);

    // When encoding fmt is the source format
    // SPNG_FMT_PNG is a special value that matches the format in ihdr
    fmt = SPNG_FMT_PNG;

    size_t image_size, image_width;

    ret = spng_decoded_image_size(ctx, fmt, &image_size);
    
    if(ret)
    {
        printf("spng_decoded_image_size() error: %s\n", spng_strerror(ret));
        goto encode_error;
    }

    // SPNG_ENCODE_FINALIZE will finalize the PNG with the end-of-file marker
    ret = spng_encode_image(ctx, image, image_size, fmt, SPNG_ENCODE_FINALIZE);

    if(ret)
    {
        printf("spng_encode_image() error: %s\n", spng_strerror(ret));
        goto encode_error;
    }

    encode_error:
        spng_ctx_free(ctx);

    return ret;
}


