import socket
from .auth import authenticate
from .file_manager import FileManager
from .crypto import Crypto

class Client:
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        self.file_manager = FileManager(self.socket)
        self.crypto = Crypto()
    
    def run(self):
        if authenticate(self.socket):
            print("Authentication successful!")
            self.main_loop()
        else:
            print("Authentication failed!")
            self.socket.close()
    
    def main_loop(self):
        while True:
            command = input("Enter command (upload/download/list/exit): ").lower()
            if command == "exit":
                self.socket.close()
                break
            elif command == "upload":
                filepath = input("Enter file path: ")
                self.file_manager.upload_file(filepath, self.crypto)
            elif command == "download":
                filename = input("Enter filename to download: ")
                self.file_manager.download_file(filename, self.crypto)
            elif command == "list":
                self.socket.send("LIST".encode())
                response = self.socket.recv(1024).decode()
                if response.startswith("FILES:"):
                    files = response.split(":", 1)[1]
                    print("Files in storage:\n" + files)
                else:
                    print("Error listing files")
            else:
                print("Invalid command!")

if __name__ == "__main__":
    client = Client("localhost", 5000)
    client.run()