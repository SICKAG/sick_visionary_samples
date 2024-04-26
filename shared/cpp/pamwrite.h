#ifndef IMAGE_STREAMING_AND_STORING_PGMWRITE_H_INCLUDED
#define IMAGE_STREAMING_AND_STORING_PGMWRITE_H_INCLUDED

#include <cstdint>
#include <string>
#include <vector>

/// Write a 16-bit PAM file.
///
/// \param[in] filepath the path to the file to write.
/// \param[in] data     the image data to write.
/// \param[in] width    the width of the image.
/// \param[in] height   the height of the image.
///
/// \throws std::runtime_error if the file could not be opened for writing or
///                            if an error occurred while writing to the file.
void pamwriteu16(const std::string& filepath, const std::vector<std::uint16_t>& data, int width, int height);

/// Write a 32bit RGBA PAM file.
///
/// \param[in] filepath the path to the file to write.
/// \param[in] data     the image data to write.
/// \param[in] width    the width of the image.
/// \param[in] height   the height of the image.
///
/// \throws std::runtime_error if the file could not be opened for writing or
///                            if an error occurred while writing to the file.
void pamwritergba(const std::string& filepath, const std::vector<std::uint32_t>& data, int width, int height);

#endif // IMAGE_STREAMING_AND_STORING_PGMWRITE_H_INCLUDED