import socket
from .auth import authenticate
from .file_manager import FileManager
from .crypto import Crypto

class Client:
    def __init__(self, host, port):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.file_manager = FileManager(self.socket)
            self.crypto = Crypto()
        except socket.error as e:
            print(f"Failed to connect to server {host}:{port}: {e}")
            raise
    
    def run(self):
        try:
            if authenticate(self.socket):
                print("Authentication successful!")
                self.main_loop()
            else:
                print("Authentication failed!")
        except socket.error as e:
            print(f"Network error during authentication: {e}")
        except Exception as e:
            print(f"Unexpected error during authentication: {e}")
        finally:
            self.socket.close()
            print("Client connection closed.")
    
    def main_loop(self):
        while True:
            try:
                command = input("Enter command (upload/download/list/delete/exit): ").lower().strip()
                if not command:
                    print("Please enter a valid command.")
                    continue

                if command == "exit":
                    break
                elif command == "upload":
                    filepath = input("Enter file path: ").strip()
                    if not filepath:
                        print("File path cannot be empty.")
                        continue
                    self.file_manager.upload_file(filepath, self.crypto)
                elif command == "download":
                    filename = input("Enter filename to download: ").strip()
                    if not filename:
                        print("Filename cannot be empty.")
                        continue
                    self.file_manager.download_file(filename, self.crypto)
                elif command == "list":
                    self.socket.send("LIST".encode())
                    response = self.socket.recv(1024).decode()
                    if response.startswith("FILES:"):
                        files = response.split(":", 1)[1]
                        print("Files in storage:\n" + files)
                    else:
                        print("Error listing files: " + response)
                elif command == "delete":
                    filename = input("Enter filename to delete: ").strip()
                    if not filename:
                        print("Filename cannot be empty.")
                        continue
                    self.socket.send(f"DELETE:{filename}".encode())
                    response = self.socket.recv(1024).decode()
                    if response == "DELETE_SUCCESS":
                        print(f"File '{filename}' deleted successfully!")
                    else:
                        print(f"Error deleting file: {response.split(':', 1)[1] if ':' in response else response}")
                else:
                    print(f"Invalid command '{command}'. Use: upload, download, list, delete, or exit.")
            
            except socket.error as e:
                print(f"Network error: {e}. Check your connection or server status.")
                break
            except ValueError as e:
                print(f"Input error: {e}. Please try again.")
            except FileNotFoundError as e:
                print(f"File error: {e}. Check the file path or filename.")
            except Exception as e:
                print(f"Unexpected error: {e}. Please try again or contact support.")

if __name__ == "__main__":
    SERVER_HOST = "localhost"  # Replace with your server's public IP or domain
    SERVER_PORT = 5000
    try:
        client = Client(SERVER_HOST, SERVER_PORT)
        client.run()
    except Exception as e:
        print(f"Failed to start client: {e}")