import socket
from threading import Thread
from .user_manager import UserManager
from .file_controller import FileController
from .audit_logger import AuditLogger
from src.common.protocol import Protocol
from src.client.crypto import Crypto  # Import from client directory  # Changed from Fernet import to our custom Crypto class

class Server:
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.user_manager = UserManager()
        self.file_controller = FileController("storage")
        self.logger = AuditLogger("audit.log")
        self.running = True
        self.crypto = Crypto()  # Added Crypto instance
    
    def run(self):
        self.socket.listen()
        print("Server running on port 5000...")
        try:
            while self.running:
                client, addr = self.socket.accept()
                print(f"New connection from {addr}")
                Thread(target=self.handle_client, args=(client, addr)).start()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            self.shutdown()
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.socket.close()
    
    def shutdown(self):
        self.running = False
        self.socket.close()
    
    def handle_client(self, client, addr):
        print(f"Starting client handler for {addr}")
        current_user = None
        current_role = None
        
        while self.running:
            try:
                message = client.recv(1024).decode()
                if not message:
                    print(f"Client {addr} disconnected")
                    break
                
                print(f"Received from {addr}: {message}")
                command, args = Protocol.parse_message(message)
                print(f"Parsed command: {command}, args: {args}")
                
                if command == "AUTH":
                    username, password = args
                    print(f"Authenticating {username}")
                    is_valid, role = self.user_manager.verify_user(username, password)
                    if is_valid:
                        current_user = username
                        current_role = role
                        client.send("AUTH_SUCCESS".encode())
                        self.logger.log_action(username, "login")
                        print(f"Auth success for {username} ({role})")
                    else:
                        client.send("AUTH_FAILED".encode())
                        print(f"Auth failed for {username}")
                elif not current_user:
                    client.send("ERROR:Not authenticated".encode())
                elif command == "UPLOAD":
                    self.handle_upload(client, args, addr, current_user, current_role)
                elif command == "DOWNLOAD":
                    self.handle_download(client, args, addr, current_user, current_role)
                elif command == "LIST":
                    self.handle_list(client, addr, current_user, current_role)
                elif command == "DELETE":
                    self.handle_delete(client, args, addr, current_user, current_role)
                elif command == "EDIT":
                    self.handle_edit(client, args, addr, current_user, current_role)
                elif command == "GET_ALLOWED":
                    self.handle_get_allowed(client, args, addr, current_user, current_role)
                else:
                    print(f"Unknown command from {addr}: {command}")
                    client.send("ERROR:Unknown command".encode())
            except Exception as e:
                print(f"Error handling client {addr}: {e}")
                client.send(f"ERROR:Server error: {e}".encode())
        client.close()
        print(f"Closed connection with {addr}")
    
    def handle_upload(self, client, args, addr, current_user, current_role):
        if current_role == "guest":
            client.send("ERROR:Guests cannot upload".encode())
            return
        try:
            filename, size, key, visibility = args
            size = int(size)
            if visibility not in ["private", "public", "unlisted"]:
                client.send("ERROR:Invalid visibility (private/public/unlisted)".encode())
                return
            data = client.recv(size)
            self.file_controller.store_file(filename, data)
            self.file_controller.store_key(filename, key)
            self.file_controller.store_metadata(filename, current_user, visibility)
            self.logger.log_action(addr[0], f"uploaded {filename} ({visibility})")
            client.send("UPLOAD_SUCCESS".encode())
        except ValueError as e:
            client.send(f"ERROR:Invalid size: {e}".encode())
    
    def handle_download(self, client, args, addr, current_user, current_role):
        filename = args[0]
        metadata = self.file_controller.get_metadata(filename)
        if not metadata:
            client.send("ERROR:File not found".encode())
            return
        if not self.can_access_file(metadata, current_user, current_role):
            client.send("ERROR:Permission denied".encode())
            return
        data = self.file_controller.get_file(filename)
        if data:
            client.send(f"FILE:{len(data)}".encode())
            client.send(data)
            key = self.file_controller.get_key(filename)
            if key:
                client.send(f"KEY:{key}".encode())
            else:
                client.send("ERROR:Key not found".encode())
            self.logger.log_action(addr[0], f"downloaded {filename}")
        else:
            client.send("ERROR:File not found".encode())
    
    def handle_list(self, client, addr, current_user, current_role):
        if current_role == "guest":
            client.send("ERROR:Guests cannot list files".encode())
            return
        files = self.file_controller.list_files(current_user, current_role)
        if files:
            file_list = "\n".join([f"{f['filename']} (Owner: {f['owner']}, Your Privilege: {f['privilege']})" for f in files])
            client.send(f"FILES:{file_list}".encode())
        else:
            client.send("FILES:No files visible".encode())
        self.logger.log_action(addr[0], "listed files")
    
    def handle_delete(self, client, args, addr, current_user, current_role):
        if current_role == "guest":
            client.send("ERROR:Guests cannot delete".encode())
            return
        filename = args[0]
        metadata = self.file_controller.get_metadata(filename)
        if not metadata:
            client.send("ERROR:File not found".encode())
            return
        if current_role != "admin" and metadata["owner"] != current_user:
            client.send("ERROR:Permission denied".encode())
            return
        if self.file_controller.delete_file(filename):
            self.logger.log_action(addr[0], f"deleted {filename}")
            client.send("DELETE_SUCCESS".encode())
        else:
            client.send("ERROR:File not found".encode())
    
    def handle_edit(self, client, args, addr, current_user, current_role):
        if current_role == "guest":
            client.send("ERROR:Guests cannot edit".encode())
            return
        filename = args[0]
        metadata = self.file_controller.get_metadata(filename)
        if not metadata:
            client.send("ERROR:File not found".encode())
            return
        if current_role != "admin" and metadata["owner"] != current_user:
            client.send("ERROR:Permission denied".encode())
            return
        try:
            visibility = args[1] if len(args) > 1 and args[1] else None
            add_users_raw = args[2] if len(args) > 2 and args[2] else None
            remove_users_raw = args[3] if len(args) > 3 and args[3] else None
            
            # Strip whitespace from add_users and remove_users
            add_users = [u.strip() for u in add_users_raw.split(",") if u.strip()] if add_users_raw else None
            remove_users = [u.strip() for u in remove_users_raw.split(",") if u.strip()] if remove_users_raw else None
            
            if visibility and visibility not in ["private", "public", "unlisted"]:
                client.send("ERROR:Invalid visibility (private/public/unlisted)".encode())
                return
            if not visibility and not add_users and not remove_users:
                client.send("ERROR:No changes specified".encode())
                return
            
            if self.file_controller.edit_privilege(filename, visibility, None, add_users, remove_users):
                self.logger.log_action(addr[0], f"edited {filename} privileges")
                client.send("EDIT_SUCCESS".encode())
            else:
                client.send("ERROR:Edit failed (add/remove only valid for unlisted)".encode())
        except Exception as e:
            client.send(f"ERROR:Invalid edit arguments: {e}".encode())
    
    def handle_get_allowed(self, client, args, addr, current_user, current_role):
        if current_role == "guest":
            client.send("ERROR:Guests cannot edit".encode())
            return
        filename = args[0]
        metadata = self.file_controller.get_metadata(filename)
        if not metadata:
            client.send("ERROR:File not found".encode())
            return
        if current_role != "admin" and metadata["owner"] != current_user:
            client.send("ERROR:Permission denied".encode())
            return
        allowed_users = metadata["allowed_users"]
        client.send(f"ALLOWED:{','.join(allowed_users) if allowed_users else 'None'}".encode())
    
    def can_access_file(self, metadata, current_user, current_role):
        if current_role == "admin":
            return True
        if metadata["owner"] == current_user:
            return True
        if metadata["visibility"] == "public":
            return current_role == "normal"
        if metadata["visibility"] == "unlisted" and current_user in metadata["allowed_users"]:
            return current_role == "normal"
        return False

if __name__ == "__main__":
    import os
    if not os.path.exists("storage"):
        os.makedirs("storage")
    server = Server("0.0.0.0", 5000)
    server.run()