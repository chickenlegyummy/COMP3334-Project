import os

class FileController:
    def __init__(self, storage_path):
        self.storage_path = storage_path
    
    def store_file(self, filename, data):
        filepath = os.path.join(self.storage_path, filename)
        with open(filepath, "wb") as f:
            f.write(data)
    
    def get_file(self, filename):
        filepath = os.path.join(self.storage_path, filename)
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                return f.read()
        return None
    
    def store_key(self, filename, key):
        key_filepath = os.path.join(self.storage_path, f"{filename}.key")
        print(f"Storing key for {filename} at {key_filepath}")
        try:
            with open(key_filepath, "w") as f:
                f.write(key)
            print(f"Key stored successfully: {key}")
        except Exception as e:
            print(f"Failed to store key for {filename}: {e}")

    def get_key(self, filename):
        key_filepath = os.path.join(self.storage_path, f"{filename}.key")
        if os.path.exists(key_filepath):
            with open(key_filepath, "r") as f:
                key = f.read()
                print(f"Retrieved key for {filename}: {key}")
                return key
        print(f"No key file found at {key_filepath}")
        return None
    
    def list_files(self):
        return [f for f in os.listdir(self.storage_path) if os.path.isfile(os.path.join(self.storage_path, f)) and not f.endswith(".key")]