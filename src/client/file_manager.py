import os

class FileManager:
    def __init__(self, socket):
        self.socket = socket
    
    def upload_file(self, filepath, crypto):
        if not os.path.exists(filepath):
            print("File does not exist!")
            return
        
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            data = f.read()
        
        encrypted_data, key = crypto.encrypt(data)
        size = len(encrypted_data)
        self.socket.send(f"UPLOAD:{filename}:{size}:{key.decode()}".encode())
        self.socket.send(encrypted_data)
        response = self.socket.recv(1024).decode()
        if response == "UPLOAD_SUCCESS":
            print("File uploaded successfully!")
        else:
            print("Upload failed!")
    
    def download_file(self, filename, crypto):
        self.socket.send(f"DOWNLOAD:{filename}".encode())
        response = self.socket.recv(1024).decode()
        
        if response.startswith("ERROR"):
            print(response.split(":", 1)[1])
            return
        
        size = int(response.split(":", 1)[1])
        print(f"Expected file size: {size}")  # Debug
        file_data = b""
        while len(file_data) < size:
            chunk = self.socket.recv(size - len(file_data))
            if not chunk:
                print("Connection closed before receiving full file!")
                return
            file_data += chunk
        print(f"Received file data size: {len(file_data)}")  # Debug
        
        key_data = self.socket.recv(1024).decode()
        print(f"Received key data: {key_data}")  # Debug
        if not key_data.startswith("KEY:"):
            print(f"Invalid key response from server: {key_data}")
            return
        key = key_data.split(":", 1)[1].encode()
        
        decrypted_data = crypto.decrypt(file_data, key)
        with open(filename, "wb") as f:
            f.write(decrypted_data)
        print(f"File downloaded and saved as {filename}")