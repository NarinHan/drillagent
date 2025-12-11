import os

def get_file_size(file_path: str) -> int:
    # Get the size of a file in bytes.
    return os.path.getsize(file_path)

class BaseUtils:
    # General utility functions for the project
    pass