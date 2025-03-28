import socket
from threading import Thread
from .user_manager import UserManager
from .file_controller import FileController
from .audit_logger import AuditLogger
from src.common.protocol import Protocol
from cryptography.fernet import Fernet

class Server:
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.user_manager = UserManager()
        self.file_controller = FileController("storage")
        self.logger = AuditLogger("audit.log")
        self.running = True
    
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
                    if self.user_manager.verify_user(username, password):
                        client.send("AUTH_SUCCESS".encode())
                        self.logger.log_action(username, "login")
                        print(f"Auth success for {username}")
                    else:
                        client.send("AUTH_FAILED".encode())
                        print(f"Auth failed for {username}")
                elif command == "UPLOAD":
                    self.handle_upload(client, args, addr)
                elif command == "DOWNLOAD":
                    self.handle_download(client, args, addr)
                elif command == "LIST":
                    self.handle_list(client, addr)
                else:
                    print(f"Unknown command from {addr}: {command}")
            except Exception as e:
                print(f"Error handling client {addr}: {e}")
                break
        client.close()
        print(f"Closed connection with {addr}")
    
    def handle_upload(self, client, args, addr):
        filename, size, key = args[0], int(args[1]), args[2]
        data = client.recv(size)
        self.file_controller.store_file(filename, data)  # Store encrypted data
        self.file_controller.store_key(filename, key)    # Store the key
        self.logger.log_action(addr[0], f"uploaded {filename}")
        client.send("UPLOAD_SUCCESS".encode())
    
    def handle_download(self, client, args, addr):
        filename = args[0]
        data = self.file_controller.get_file(filename)
        if data:
            print(f"Sending file data for {filename}, size: {len(data)}")
            client.send(f"FILE:{len(data)}".encode())
            client.send(data)
            key = self.file_controller.get_key(filename)
            if key:
                print(f"Sending key for {filename}: {key}")
                client.send(f"KEY:{key}".encode())
            else:
                print(f"Key not found for {filename}")
                client.send("ERROR:Key not found".encode())
            self.logger.log_action(addr[0], f"downloaded {filename}")
        else:
            print(f"File {filename} not found")
            client.send("ERROR:File not found".encode())
    
    def handle_list(self, client, addr):
        files = self.file_controller.list_files()
        if files:
            file_list = "\n".join(files)
            client.send(f"FILES:{file_list}".encode())
        else:
            client.send("FILES:No files in storage".encode())
        self.logger.log_action(addr[0], "listed files")

if __name__ == "__main__":
    import os
    if not os.path.exists("storage"):
        os.makedirs("storage")
    server = Server("0.0.0.0", 5000)
    server.run()