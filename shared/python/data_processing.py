import os
import time

from base.python.PointCloud.PointCloud import (convertToPointCloud,
                                               convertToPointCloudOptimized,
                                               writePointCloudToPCD,
                                               writePointCloudToPLY)
from shared.python.framewrite import writeFrame


def processSensorData(sensor_data, device_type, img_dir, output_prefix, pcl_dir, write_files=True):
    """
    Processes sensor data to extract and convert depth map information, and optionally writes the data to files.

    This function performs the following steps:
    1. Prints the timestamp of the sensor data.
    2. Checks if the sensor data contains a depth map.
    3. If depth map data is present and `write_files` is True:
       - Writes the depth map as a PNG file.
       - Converts the depth map to a point cloud using both non-optimized and optimized methods.
       - Writes the resulting point clouds to PLY and PCD files respectively.

    Args:
        sensor_data (Data.Data): The sensor data object containing depth map and other information.
        device_type (str): The type of device (e.g., "Visionary-S").
        img_dir (str): Directory to save image files.
        output_prefix (str): Prefix for output file names.
        pcl_dir (str): Directory to save point cloud files.
        write_files (bool, optional): Flag to indicate whether to write files. Defaults to True.

    Returns:
        None
    """
    print("Data Timestamp [YYYY-MM-DD HH:MM:SS.mm] = %04u-%02u-%02u %02u:%02u:%02u.%03u" % (
        sensor_data.getDecodedTimestamp()))

    if sensor_data.hasDepthMap:
        frame_number = sensor_data.depthmap.frameNumber
        print("Data contains depth map data")

        if write_files:
            print("=== Write PNG file: Frame number: {}".format(frame_number))
            writeFrame(device_type, sensor_data,
                       os.path.join(img_dir, output_prefix))
            print("=== Converting image to pointcloud")

            # Non optimized
            start_time = time.time()
            world_coordinates, dist_data = convertToPointCloud(
                sensor_data.depthmap.distance,
                sensor_data.depthmap.intensity,
                sensor_data.depthmap.confidence,
                sensor_data.cameraParams,
                sensor_data.xmlParser.stereo
            )
            end_time = time.time()
            execution_time = end_time - start_time
            print(f"convertToPointCloud took: {execution_time:.3}s")

            # Optimized
            is_stereo = True if device_type == "Visionary-S" else False
            start_time = time.time()
            point_cloud = convertToPointCloudOptimized(
                sensor_data.depthmap.distance,
                sensor_data.depthmap.confidence,
                sensor_data.cameraParams,
                is_stereo
            )
            end_time = time.time()
            execution_time = end_time - start_time
            print(f"convertToPointCloudOptimized took: {execution_time:.3}s")

            # Write output of the non optimized function to PLY
            writePointCloudToPLY(os.path.join(
                pcl_dir, "world_coordinates{}.ply".format(frame_number)), world_coordinates)

            # Write output of the optimized function to PCD
            writePointCloudToPCD(os.path.join(
                pcl_dir, "world_coordinates{}.pcd".format(frame_number)), point_cloud.reshape(-1, point_cloud.shape[-1]))
