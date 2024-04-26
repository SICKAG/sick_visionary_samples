#include <fstream>
#include <memory>
#include <vector>

#include <VisionaryData.h>
#include <VisionarySData.h>
#include <VisionaryTMiniData.h>

#include "framewrite.h"
#include "pamwrite.h"
#include "pngwrite.h"

// stores a map tag and the associated file name
struct TagAndName
{
  std::string tag;
  std::string filename;
};

// Write both the meta data and the images (using the fileWriters).
// The meta data will be extracted from rDataHandler and are:
//   - the sensor type,
//   - the frame number,
//   - the timestamp,
//   - the width and height of the images, and
//   - the camera parameters
//      - the intrinsic camera matrix,
//      - the lens distortion parameters, and
//      - the transformation matrix from the sensor focus to the origin of the configured user coordinate system.
static void writeMeta(visionary::VisionaryType        visionaryType,
                      const visionary::VisionaryData& rDataHandler,
                      const std::string&              inifilename,
                      const std::vector<TagAndName>&  mapdescs)
{
  // Write the meta data to a .ini file.
  std::ofstream metafile(inifilename);
  if (!metafile.is_open())
  {
    throw std::runtime_error("Could not open file for writing: " + inifilename);
  }

  // Write the meta data to the .ini file.
  metafile << "[ident]\n";
  metafile << "visionarytype=" << visionaryType.toString() << '\n';

  metafile << "\n[frame]\n";
  // tag::frame_meta_data[]
  const std::uint32_t frameNumber = rDataHandler.getFrameNum();
  const std::uint64_t timestamp   = rDataHandler.getTimestamp();
  // end::frame_meta_data[]
  metafile << "framenumber=" << frameNumber << '\n';
  metafile << "timestamp=" << timestamp << '\n';

  // tag::camera_data[]
  const visionary::CameraParameters& rCameraParameters = rDataHandler.getCameraParameters();
  // end::camera_data[]

  // tag::frame_geometry[]
  const int width  = rDataHandler.getWidth();
  const int height = rDataHandler.getHeight();
  // end::frame_geometry[]
  metafile << "width=" << width << '\n';
  metafile << "height=" << height << '\n';

  // tag::intrinsics[]
  const double cx = rCameraParameters.cx;
  const double cy = rCameraParameters.cy;
  const double fx = rCameraParameters.fx;
  const double fy = rCameraParameters.fy;
  // end::intrinsics[]
  metafile << "\n[intrinsics]\n";
  metafile << "cx=" << cx << '\n';
  metafile << "cy=" << cy << '\n';
  metafile << "fx=" << fx << '\n';
  metafile << "fy=" << fy << '\n';

  // tag::lens_distortion[]
  const double k1 = rCameraParameters.k1;
  const double k2 = rCameraParameters.k2;
  const double p1 = rCameraParameters.p1;
  const double p2 = rCameraParameters.p2;
  const double k3 = rCameraParameters.k3;
  // end::lens_distortion[]
  metafile << "\n[lensdistortion]\n";
  metafile << "k1=" << k1 << '\n';
  metafile << "k2=" << k2 << '\n';
  metafile << "p1=" << p1 << '\n';
  metafile << "p2=" << p2 << '\n';
  metafile << "k3=" << k3 << '\n';

  metafile << "\n[cam2world]\n";
  // tag::f2rc[]
  const double f2rc = rCameraParameters.f2rc;
  // end::f2rc[]
  metafile << "f2rc=" << f2rc << '\n';

  // tag::cam2world[]
  const double* const pCam2worldMatrix = rCameraParameters.cam2worldMatrix;
  // end::cam2world[]
  metafile << "cam2world=" << pCam2worldMatrix[0];
  for (int i = 1; i < 4 * 4; ++i)
  {
    metafile << ' ' << pCam2worldMatrix[i];
  }
  metafile << '\n';

  // write the map names and file names
  metafile << "\n[maps]\n";
  for (const TagAndName& mapDesc : mapdescs)
  {
    metafile << mapDesc.tag << '=' << mapDesc.filename << '\n';
  }

  if (!metafile)
  {
    throw std::runtime_error("Error writing to file: " + inifilename);
  }

  metafile.close();
}

void writeFrame(visionary::VisionaryType        visionaryType,
                const visionary::VisionaryData& rDataHandler,
                const std::string&              filePrefix)
{
  using namespace visionary;

  // Get the frame number
  const std::uint32_t frameNumber = rDataHandler.getFrameNum();

  // Get the width and height of the images
  const  std::uint32_t width  = rDataHandler.getWidth();
  const  std::uint32_t height = rDataHandler.getHeight();

  const std::string framePrefix = std::to_string(frameNumber);

  std::vector<TagAndName> mapdescs;

  // access visionary type specific data
  switch (visionaryType)
  {
    // end::extract_frame_data[]
    case VisionaryType::eVisionaryS:
    {
      // tag::visionary_s_maps[]
      // cast to specific visionary data type
      const VisionarySData& rVisionarySData = dynamic_cast<const VisionarySData&>(rDataHandler);
      // end::visionary_s_maps[]

      // get color data and write it as file
      {
        const TagAndName tagAndName{"rgba", framePrefix + "-rgba.png"};

        // tag::visionary_s_maps[]
        std::vector<std::uint32_t> colorData = rVisionarySData.getRGBAMap();
        // end::visionary_s_maps[]

        write_png_rgba(filePrefix + tagAndName.filename, colorData, width, height);
        mapdescs.push_back(tagAndName);
      }

      // get Z data and write it as file
      {
        const TagAndName tagAndName{"z", framePrefix + "-z.png"};

        // tag::visionary_s_maps[]
        std::vector<std::uint16_t> zData = rVisionarySData.getZMap();
        // end::visionary_s_maps[]

        write_png_u16(filePrefix + tagAndName.filename, zData, width, height);
        mapdescs.push_back(tagAndName);
      }

      // get statemap data and write it as file
      {
        const TagAndName tagAndName{"state", framePrefix + "-state.png"};

        // tag::visionary_s_maps[]
        std::vector<std::uint16_t> stateMapData = rVisionarySData.getStateMap();
        // end::visionary_s_maps[]

        write_png_u16(filePrefix + tagAndName.filename, stateMapData, width, height);
        mapdescs.push_back(tagAndName);
      }
    }
    break;

    case VisionaryType::eVisionaryTMini:
    {
      // tag::visionary_t_mini_maps[]
      // cast to specific visionary data type
      const VisionaryTMiniData& rVisionaryTMiniData = dynamic_cast<const VisionaryTMiniData&>(rDataHandler);
      // end::visionary_t_mini_maps[]

      // get intensity data and write it as file
      {
        const TagAndName tagAndName{"int", framePrefix + "-int.png"};

        // tag::visionary_t_mini_maps[]
        std::vector<std::uint16_t> intensityData = rVisionaryTMiniData.getIntensityMap();
        // end::visionary_t_mini_maps[]

        write_png_u16(filePrefix + tagAndName.filename, intensityData, width, height);
        mapdescs.push_back(tagAndName);
      }

      // get distance data and write it as file
      {
        const TagAndName tagAndName{"dist", framePrefix + "-dist.png"};

        // tag::visionary_t_mini_maps[]
        std::vector<std::uint16_t> distanceData = rVisionaryTMiniData.getDistanceMap();
        // end::visionary_t_mini_maps[]

        write_png_u16(filePrefix + tagAndName.filename, distanceData, width, height);
        mapdescs.push_back(tagAndName);
      }

      // get statemap data and write it as file
      {
        const TagAndName tagAndName{"state", framePrefix + "-state.png"};

        // tag::visionary_t_mini_maps[]
        std::vector<std::uint16_t> stateMapData = rVisionaryTMiniData.getStateMap();
        // end::visionary_t_mini_maps[]

        write_png_u16(filePrefix + tagAndName.filename, stateMapData, width, height);
        mapdescs.push_back(tagAndName);
      }
    }
    break;

    default:
      std::fprintf(stderr, "Unknown visionary type\n");
      break;
  }

  // write the meta data
  writeMeta(visionaryType, rDataHandler, filePrefix + framePrefix + ".ini", mapdescs);
}
