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
                command = input("Enter command (upload/download/list/delete/edit/exit): ").lower().strip()
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
                    visibility = input("Set visibility (private/public/unlisted): ").lower().strip()
                    if visibility not in ["private", "public", "unlisted"]:
                        print("Invalid visibility. Use: private, public, or unlisted.")
                        continue
                    self.file_manager.upload_file(filepath, self.crypto, visibility)
                elif command == "download":
                    filename = input("Enter filename to download: ").strip()
                    if not filename:
                        print("Filename cannot be empty.")
                        continue
                    self.file_manager.download_file(filename, self.crypto)
                elif command == "list":
                    self.socket.send("LIST".encode())
                    response = self.socket.recv(2048).decode()
                    if response.startswith("FILES:"):
                        files = response.split(":", 1)[1]
                        print("Files in storage:\n" + files)
                    else:
                        print("Error listing files: " + response.split(":", 1)[1] if ":" in response else response)
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
                elif command == "edit":
                    filename = input("Enter filename to edit: ").strip()
                    if not filename:
                        print("Filename cannot be empty.")
                        continue
                    visibility = input("New visibility (private/public/unlisted, or leave blank): ").lower().strip()
                    if visibility and visibility not in ["private", "public", "unlisted"]:
                        print("Invalid visibility. Use: private, public, unlisted, or leave blank.")
                        continue
                    
                    cmd = f"EDIT:{filename}"
                    if visibility in ["private", "public"]:
                        cmd += f":{visibility}::"
                    else:
                        # Fetch and display current allowed users
                        self.socket.send(f"GET_ALLOWED:{filename}".encode())
                        response = self.socket.recv(1024).decode()
                        if response.startswith("ALLOWED:"):
                            allowed_users = response.split(":", 1)[1]
                            print(f"Users allowed: {allowed_users if allowed_users != 'None' else 'None'}")
                        else:
                            print(f"Error fetching allowed users: {response.split(':', 1)[1] if ':' in response else response}")
                            continue
                        add_users_input = input("Users to add (comma-separated, or leave blank): ").strip()
                        remove_users_input = input("Users to remove (comma-separated, or leave blank): ").strip()
                        # Clean up add_users and remove_users by removing extra spaces
                        add_users = ",".join([u.strip() for u in add_users_input.split(",") if u.strip()]) if add_users_input else ""
                        remove_users = ",".join([u.strip() for u in remove_users_input.split(",") if u.strip()]) if remove_users_input else ""
                        cmd += f":{visibility}" if visibility else ":"
                        cmd += f":{add_users}" if add_users else ":"
                        cmd += f":{remove_users}" if remove_users else ":"
                    
                    self.socket.send(cmd.encode())
                    response = self.socket.recv(1024).decode()
                    if response == "EDIT_SUCCESS":
                        print(f"Privileges for '{filename}' updated successfully!")
                    else:
                        print(f"Error editing file: {response.split(':', 1)[1] if ':' in response else response}")
                else:
                    print(f"Invalid command '{command}'. Use: upload, download, list, delete, edit, or exit.")
            
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