import os
import json

class FileController:
    def __init__(self, storage_path):
        self.storage_path = storage_path
        self.metadata_file = os.path.join(self.storage_path, "metadata.json")
        if not os.path.exists(self.metadata_file):
            with open(self.metadata_file, "w") as f:
                json.dump({}, f)
    
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
        try:
            with open(key_filepath, "w") as f:
                f.write(key)
        except Exception as e:
            print(f"Failed to store key for {filename}: {e}")
    
    def get_key(self, filename):
        key_filepath = os.path.join(self.storage_path, f"{filename}.key")
        if os.path.exists(key_filepath):
            with open(key_filepath, "r") as f:
                return f.read()
        return None
    
    def store_metadata(self, filename, owner, visibility, allowed_users=None):
        with open(self.metadata_file, "r") as f:
            metadata = json.load(f)
        metadata[filename] = {
            "owner": owner,
            "visibility": visibility,
            "allowed_users": allowed_users or []
        }
        with open(self.metadata_file, "w") as f:
            json.dump(metadata, f)
    
    def get_metadata(self, filename):
        with open(self.metadata_file, "r") as f:
            metadata = json.load(f)
        return metadata.get(filename)
    
    def list_files(self, username, role):
        with open(self.metadata_file, "r") as f:
            metadata = json.load(f)
        visible_files = []
        for filename, data in metadata.items():
            privilege = self.get_privilege(username, role, data)
            if privilege != "none":
                visible_files.append({
                    "filename": filename,
                    "owner": data["owner"],
                    "visibility": data["visibility"],
                    "allowed_users": data["allowed_users"],
                    "privilege": privilege
                })
        return visible_files
    
    def delete_file(self, filename):
        filepath = os.path.join(self.storage_path, filename)
        key_filepath = os.path.join(self.storage_path, f"{filename}.key")
        file_exists = os.path.exists(filepath)
        
        if file_exists:
            os.remove(filepath)
            if os.path.exists(key_filepath):
                os.remove(key_filepath)
            with open(self.metadata_file, "r") as f:
                metadata = json.load(f)
            if filename in metadata:
                del metadata[filename]
                with open(self.metadata_file, "w") as f:
                    json.dump(metadata, f)
            return True
        return False
    
    def edit_privilege(self, filename, visibility=None, allowed_users=None, add_users=None, remove_users=None):
        with open(self.metadata_file, "r") as f:
            metadata = json.load(f)
        if filename not in metadata:
            return False
        
        file_data = metadata[filename]
        if visibility:
            file_data["visibility"] = visibility
            if visibility in ["private", "public"]:
                file_data["allowed_users"] = []
        
        if file_data["visibility"] == "unlisted":
            current_users = set(file_data["allowed_users"])
            if add_users:
                current_users.update(add_users)
            if remove_users:
                current_users.difference_update(remove_users)
            file_data["allowed_users"] = list(current_users)
        elif (add_users or remove_users) and visibility != "unlisted":
            return False
        
        metadata[filename] = file_data
        with open(self.metadata_file, "w") as f:
            json.dump(metadata, f)
        return True
    
    def get_privilege(self, username, role, metadata):
        if role == "admin":
            return "edit"  # Admin can view/edit/delete all files
        if metadata["owner"] == username:
            return "edit"  # Owner can view/edit/delete their files
        if metadata["visibility"] == "public" and role == "normal":
            return "view"  # Normal users can view public files
        if metadata["visibility"] == "unlisted" and username in metadata["allowed_users"] and role == "normal":
            return "view"  # Normal users can view unlisted files if allowed
        return "none"  # No access