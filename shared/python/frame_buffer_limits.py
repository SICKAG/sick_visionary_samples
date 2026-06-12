import math

import psutil


def estimate_frame_size(frame) -> int:
    """Return frame size in bytes for numpy-like or bytes-like frame objects."""
    if hasattr(frame, "nbytes"):
        return int(frame.nbytes)

    return len(frame)


def get_available_memory_bytes() -> int:
    """Return currently available system memory in bytes."""
    return int(psutil.virtual_memory().available)


def get_safe_buffer_limit(requested_count: int, frame_size: int) -> int:
    """Return a memory-safe frame count capped at 90% of currently available RAM."""
    if requested_count <= 0:
        return 0

    if frame_size <= 0:
        return 1

    usable_mem = int(get_available_memory_bytes() * 0.9)
    max_count = math.floor(usable_mem / frame_size)
    return max(1, min(requested_count, max_count))