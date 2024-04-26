#ifndef IMAGE_STREAMING_AND_STORING_FRAMEWRITE_H_INCLUDED
#define IMAGE_STREAMING_AND_STORING_FRAMEWRITE_H_INCLUDED

#include <string>

#include <VisionaryData.h>
#include <VisionaryType.h>

/// Write a complete frame including meta data to file.
///
/// This function writes the maps as PAM/PNM files and the meta data as a simple .ini file
/// (that also references the PAM/PNM files).
/// The files will be named according to the frame number and the type of data they contain,
/// taking the given file prefix as a base and appending frame number, the type of data and a file extension.
/// - the meta data will be written to a file named "<filePrefix>.ini",
/// - the intensity map will be written to a file named "<filePrefix><frame number>_int.pam",
/// - the distance map will be written to a file named "<filePrefix><frame number>_dist.pgm",
/// - the confidence map will be written to a file named "<filePrefix><frame number>_conf.pgm",
/// - the color map will be written to a file named "<filePrefix><frame number>_rgba.pam",
/// - the z map will be written to a file named "<filePrefix><frame number>_z.pgm", and
/// - the statemap will be written to a file named "<filePrefix><frame number>_states.pgm".
///
/// \param[in] visionaryType the type of the Visionary device.
/// \param[in] rDataHandler the data handler containing the frame to write.
/// \param[in] filePrefix the path prefix for the files to write. The files will be named
///                       according to the frame number and the type of data they contain.
///
/// \throws std::runtime_error if the file could not be opened for writing or
///                           if an error occurred while writing to the file.
void writeFrame(visionary::VisionaryType        visionaryType,
                const visionary::VisionaryData& rDataHandler,
                const std::string&              filePrefix);

#endif // IMAGE_STREAMING_AND_STORING_FRAMEWRITE_H_INCLUDED