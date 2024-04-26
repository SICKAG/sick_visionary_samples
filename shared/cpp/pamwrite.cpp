#include "pamwrite.h"

#include <fstream>

void pamwriteu16(const std::string& filepath, const std::vector<std::uint16_t>& data, int width, int height)
{
  std::ofstream pamfile(filepath, std::ios::binary);

  if (!pamfile.is_open())
  {
    throw std::runtime_error("Could not open file for writing: " + filepath);
  }

  pamfile << "P7\n"
          << "WIDTH " << width << "\n"
          << "HEIGHT " << height << "\n"
          << "DEPTH 1\n"
          << "MAXVAL 65535\n"
          << "TUPLTYPE GRAYSCALE\n"
          << "ENDHDR\n";

  for (std::uint16_t value : data)
  {
    // Write the 16-bit value in big-endian order.
    const char bytes[2] = {static_cast<char>(value >> 8), static_cast<char>(value & 0xFFu)};
    pamfile.write(bytes, sizeof(bytes));
  }

  if (!pamfile)
  {
    throw std::runtime_error("Error writing to file: " + filepath);
  }

  pamfile.close();
}

void pamwritergba(const std::string& filepath, const std::vector<std::uint32_t>& data, int width, int height)
{
  std::ofstream pamfile(filepath, std::ios::binary);

  if (!pamfile.is_open())
  {
    throw std::runtime_error("Could not open file for writing: " + filepath);
  }

  pamfile << "P7\n"
          << "WIDTH " << width << "\n"
          << "HEIGHT " << height << "\n"
          << "DEPTH 4\n"
          << "MAXVAL 255\n"
          << "TUPLTYPE RGB_ALPHA\n"
          << "ENDHDR\n";

  // 32bit format as read from visionary
  //  byte 0: red
  //  byte 1: green
  //  byte 2: blue
  //  byte 3: alpha
  for (std::uint32_t value : data)
  {
    const char bytes[4] = {static_cast<char>(value & 0xFFu),
                           static_cast<char>((value >> 8) & 0xFFu),
                           static_cast<char>((value >> 16) & 0xFFu),
                           static_cast<char>((value >> 24) & 0xFFu)};
    pamfile.write(bytes, sizeof(bytes));
  }

  if (!pamfile)
  {
    throw std::runtime_error("Error writing to file: " + filepath);
  }

  pamfile.close();
}
