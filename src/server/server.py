import socket
import os
import json
import random
import string
from threading import Thread
from .user_manager import UserManager
from .file_controller import FileController
from .audit_logger import AuditLogger
from src.common.protocol import Protocol
from src.common.totp import TOTP  # If needed directly in server.py
from src.client.crypto import Crypto

class Server:
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.user_manager = UserManager()
        self.file_controller = FileController("storage")
        self.logger = AuditLogger("audit.log")
        self.running = True
        self.crypto = Crypto()
        self.mfa_sessions = {}  # To track MFA verification status
    
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
                    is_valid, role, has_mfa, mfa_secret = self.user_manager.verify_user(username, password)
                    
                    if is_valid:
                        if has_mfa:
                            # Save info for the second MFA stage
                            session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                            self.mfa_sessions[session_id] = {
                                'username': username,
                                'role': role,
                                'mfa_secret': mfa_secret
                            }
                            client.send(f"MFA_REQUIRED:{session_id}".encode())
                            print(f"MFA required for {username}")
                        else:
                            current_user = username
                            current_role = role
                            client.send("AUTH_SUCCESS".encode())
                            self.logger.log_action(username, "login")
                            self.user_manager.log_audit(username, "login", addr[0])
                            print(f"Auth success for {username} ({role})")
                    else:
                        client.send("AUTH_FAILED".encode())
                        print(f"Auth failed for {username}")
                
                elif command == "MFA_VERIFY":
                    session_id, code = args
                    if session_id in self.mfa_sessions:
                        session = self.mfa_sessions[session_id]
                        username = session['username']
                        if self.user_manager.verify_mfa(username, code):
                            current_user = username
                            current_role = session['role']
                            client.send("AUTH_SUCCESS".encode())
                            self.logger.log_action(username, "login with MFA")
                            self.user_manager.log_audit(username, "login with MFA", addr[0])
                            print(f"MFA verification success for {username}")
                            # Clean up session
                            del self.mfa_sessions[session_id]
                        else:
                            client.send("MFA_FAILED".encode())
                            print(f"MFA verification failed for {username}")
                    else:
                        client.send("MFA_FAILED:Invalid session".encode())
                
                elif command == "REGISTER":
                    if len(args) < 3:
                        client.send("ERROR:Missing required fields".encode())
                        continue
                        
                    username, password, email = args[:3]
                    mfa_secret = args[3] if len(args) > 3 else None
                    
                    success, message = self.user_manager.register_user(
                        username, password, email, "normal", mfa_secret
                    )
                    
                    if success:
                        client.send("REGISTER_SUCCESS".encode())
                        print(f"User {username} registered successfully")
                    else:
                        client.send(f"REGISTER_FAILED:{message}".encode())
                        print(f"User registration failed: {message}")
                
                elif command == "RESET_REQUEST":
                    if len(args) != 2:
                        client.send("ERROR:Invalid arguments".encode())
                        continue
                        
                    username, email = args
                    success, token_or_message = self.user_manager.create_reset_token(username, email)
                    
                    if success:
                        # In a real system, you would send this token via email
                        # For demo purposes, we're sending it back directly
                        verification_code = ''.join(random.choices(string.digits, k=6))
                        print(f"Reset code for {username}: {verification_code}")
                        client.send(f"RESET_CODE:{verification_code}".encode())
                    else:
                        client.send(f"RESET_FAILED:{token_or_message}".encode())
                
                elif command == "RESET_PASSWORD":
                    if len(args) != 2:
                        client.send("ERROR:Invalid arguments".encode())
                        continue
                        
                    username, new_password = args
                    success, message = self.user_manager.update_password(username, new_password)
                    
                    if success:
                        client.send("PASSWORD_UPDATED".encode())
                        self.user_manager.log_audit(username, "password reset", addr[0])
                    else:
                        client.send(f"RESET_FAILED:{message}".encode())
                
                elif command == "CHANGE_PASSWORD":
                    if not current_user:
                        client.send("ERROR:Not authenticated".encode())
                        continue
                        
                    if len(args) != 3:
                        client.send("ERROR:Invalid arguments".encode())
                        continue
                        
                    username, current_password, new_password = args
                    
                    # Verify this is the logged-in user
                    if username != current_user:
                        client.send("ERROR:Permission denied".encode())
                        continue
                    
                    # Verify current password
                    password_valid, _ = self.user_manager.verify_current_password(username, current_password)
                    
                    if not password_valid:
                        client.send("ERROR:Current password is incorrect".encode())
                        continue
                    
                    # Update password
                    success, message = self.user_manager.update_password(username, new_password)
                    
                    if success:
                        client.send("PASSWORD_UPDATED".encode())
                        self.user_manager.log_audit(username, "password changed", addr[0])
                    else:
                        client.send(f"ERROR:{message}".encode())
                
                elif command == "LOGOUT":
                    if current_user:
                        self.user_manager.log_audit(current_user, "logout", addr[0])
                        self.logger.log_action(current_user, "logout")
                        client.send("LOGOUT_SUCCESS".encode())
                        current_user = None
                        current_role = None
                    else:
                        client.send("ERROR:Not logged in".encode())
                
                elif command == "ENABLE_MFA":
                    if not current_user:
                        client.send("ERROR:Not authenticated".encode())
                        continue
                    
                    success, mfa_secret = self.user_manager.enable_mfa(current_user)
                    
                    if success:
                        client.send(f"MFA_ENABLED:{mfa_secret}".encode())
                        self.user_manager.log_audit(current_user, "enabled MFA", addr[0])
                    else:
                        client.send(f"ERROR:{mfa_secret}".encode())
                
                elif command == "DISABLE_MFA":
                    if not current_user:
                        client.send("ERROR:Not authenticated".encode())
                        continue
                    
                    success, message = self.user_manager.disable_mfa(current_user)
                    
                    if success:
                        client.send("MFA_DISABLED".encode())
                        self.user_manager.log_audit(current_user, "disabled MFA", addr[0])
                    else:
                        client.send(f"ERROR:{message}".encode())
                
                elif not current_user:
                    client.send("ERROR:Not authenticated".encode())
                
                # File operations
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
                elif command == "GET_METADATA":
                    self.handle_get_metadata(client, args, addr, current_user, current_role)
                elif command == "UPDATE":
                    self.handle_update(client, args, addr, current_user, current_role)
                else:
                    print(f"Unknown command from {addr}: {command}")
                    client.send("ERROR:Unknown command".encode())
            except UnicodeDecodeError as e:
                print(f"Decode error from {addr}: {e}")
                client.send(f"ERROR:Server error: {e}".encode())
                # Reset buffer to avoid sending garbage
                client.send(b"")
            except Exception as e:
                print(f"Error handling client {addr}: {e}")
                client.send(f"ERROR:Server error: {e}".encode())
                client.send(b"")
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
            self.user_manager.log_audit(current_user, f"uploaded file {filename}", addr[0])
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
            self.user_manager.log_audit(current_user, f"downloaded file {filename}", addr[0])
        else:
            client.send("ERROR:File not found".encode())
    
    def handle_update(self, client, args, addr, current_user, current_role):
        if current_role == "guest":
            client.send("ERROR:Guests cannot update files".encode())
            return
        
        try:
            filename, size, key, visibility = args
            size = int(size)
            
            # Check permissions
            metadata = self.file_controller.get_metadata(filename)
            if not metadata:
                client.send("ERROR:File not found".encode())
                return
                
            if current_role != "admin" and metadata["owner"] != current_user:
                client.send("ERROR:Permission denied".encode())
                return
            
            # Receive updated file data
            data = b""
            while len(data) < size:
                chunk = client.recv(min(size - len(data), 4096))
                if not chunk:
                    raise Exception("Client disconnected during upload")
                data += chunk
            
            # Store the updated file
            self.file_controller.store_file(filename, data)
            self.file_controller.store_key(filename, key)
            
            if visibility and visibility != metadata["visibility"]:
                self.file_controller.edit_privilege(filename, visibility)
                
            self.logger.log_action(addr[0], f"updated {filename}")
            self.user_manager.log_audit(current_user, f"updated file {filename}", addr[0])
            client.send("UPDATE_SUCCESS".encode())
            
        except ValueError as e:
            client.send(f"ERROR:Invalid size: {e}".encode())
        except Exception as e:
            client.send(f"ERROR:Update failed: {str(e)}".encode())
            # Ensure no leftover data corrupts the stream
            client.send(b"")  # Reset buffer
    
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
        self.user_manager.log_audit(current_user, "listed files", addr[0])
    
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
            self.user_manager.log_audit(current_user, f"deleted file {filename}", addr[0])
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
                self.user_manager.log_audit(current_user, f"edited file {filename} privileges", addr[0])
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
    
    def handle_get_metadata(self, client, args, addr, current_user, current_role):
        filename = args[0]
        metadata = self.file_controller.get_metadata(filename)
        
        if not metadata:
            client.send("ERROR:File not found".encode())
            return
            
        if not self.can_access_file(metadata, current_user, current_role):
            client.send("ERROR:Permission denied".encode())
            return
            
        # Send just the visibility parameter for now
        client.send(f"METADATA:{metadata['visibility']}".encode())
    
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