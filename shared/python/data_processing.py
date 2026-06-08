import os
import time

from python_base.PointCloud.PointCloud import (convertToPointCloudOptimized,
                                               writePointCloudToPCD,
                                               writePointCloudToPLY)
from shared.python.framewrite import writeFrame


def processSensorData(sensor_data, device_type, img_dir, output_prefix, pcl_dir,
                      write_files=True, pointcloud_binary=False,
                      pointcloud_output="pcd"):
    """
    Processes sensor data to extract and convert depth map information, and optionally writes the data to files.

    This function performs the following steps:
    1. Prints the timestamp of the sensor data.
    2. Checks if the sensor data contains a depth map.
    3. If depth map data is present and `write_files` is True:
       - Writes the depth map as a PNG file.
    - Converts the depth map to an optimized point cloud.
         - Writes the resulting point cloud to PCD, PLY, or both.

    Args:
        sensor_data (Data.Data): The sensor data object containing depth map and other information.
        device_type (str): The type of device (e.g., "Visionary-S").
        img_dir (str): Directory to save image files.
        output_prefix (str): Prefix for output file names.
        pcl_dir (str): Directory to save point cloud files.
        write_files (bool, optional): Flag to indicate whether to write files. Defaults to True.
        pointcloud_binary (bool, optional): Write point cloud files in binary mode if True, ASCII mode if False.
            Applies to PCD and PLY. Defaults to False.
        pointcloud_output (str, optional): Which point cloud files to write: "pcd", "ply", or "both".
            Defaults to "pcd".

    Returns:
        None
    """
    print("Data Timestamp [YYYY-MM-DD HH:MM:SS.mm] = %04u-%02u-%02u %02u:%02u:%02u.%03u" % (
        sensor_data.getDecodedTimestamp()))

    if sensor_data.hasDepthMap:
        frame_number = sensor_data.depthmap.frameNumber
        print("Data contains depth map data")

        if write_files:
            print("Write PNG file: Frame number: {}".format(frame_number))
            writeFrame(device_type, sensor_data,
                       os.path.join(img_dir, output_prefix))
            print("Converting image to pointcloud")

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

            point_cloud_flat = point_cloud.reshape(-1, point_cloud.shape[-1])

            if pointcloud_output in ("pcd", "both"):
                start_time = time.time()
                writePointCloudToPCD(
                    os.path.join(pcl_dir, "world_coordinates{}.pcd".format(frame_number)),
                    point_cloud_flat,
                    binary=pointcloud_binary)
                print_mode = "binary" if pointcloud_binary else "ascii"
                print(f"writePointCloudToPCD ({print_mode}) took: {time.time() - start_time:.3}s")

            if pointcloud_output in ("ply", "both"):
                start_time = time.time()
                writePointCloudToPLY(
                    os.path.join(pcl_dir, "world_coordinates{}.ply".format(frame_number)),
                    point_cloud_flat,
                    binary=pointcloud_binary)
                print_mode = "binary" if pointcloud_binary else "ascii"
                print(f"writePointCloudToPLY ({print_mode}) took: {time.time() - start_time:.3}s")
