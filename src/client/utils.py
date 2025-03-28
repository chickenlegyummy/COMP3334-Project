import os

def validate_filename(filename):
    return bool(filename and all(c.isalnum() or c in "._-" for c in filename))

def get_file_size(filepath):
    return os.path.getsize(filepath)