import socket
import os
import json
import random
import string
import time
from threading import Thread
from .user_manager import UserManager
from .file_controller import FileController
from .audit_logger import AuditLogger
from src.common.protocol import Protocol
from src.common.totp import TOTP
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
        self.mfa_sessions = {}
        self.auth_codes = {}
    
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
                raw_message = client.recv(1024)
                if not raw_message:
                    print(f"Client {addr} disconnected")
                    break
                
                try:
                    message = raw_message.decode('utf-8')
                    print(f"Received from {addr}: {message}")
                    command, args = Protocol.parse_message(message)
                    print(f"Parsed command: {command}, args: {args}")
                except UnicodeDecodeError:
                    print(f"Received non-text data from {addr}, skipping")
                    continue
                
                if command == "AUTH":
                    username, password = args
                    print(f"Authenticating {username} with password {password}")
                    is_valid, role, has_mfa, mfa_secret = self.user_manager.verify_user(username, password)
                    print(f"Verification result: valid={is_valid}, role={role}, has_mfa={has_mfa}")
                    
                    if is_valid:
                        if has_mfa:
                            session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                            self.mfa_sessions[session_id] = {
                                'username': username,
                                'role': role,
                                'mfa_secret': mfa_secret
                            }
                            client.send(f"MFA_REQUIRED:{session_id}".encode())
                            print(f"MFA required for {username}, session_id={session_id}")
                        else:
                            auth_code = ''.join(random.choices(string.digits, k=6))
                            self.auth_codes[username] = {
                                'code': auth_code,
                                'role': role,
                                'expires': time.time() + 300
                            }
                            client.send(f"AUTH_CODE:{auth_code}".encode())
                            print(f"Sent AUTH_CODE:{auth_code} for {username}")
                    else:
                        client.send("AUTH_FAILED".encode())
                        print(f"Auth failed for {username} - invalid credentials")
                
                elif command == "VERIFY_AUTH_CODE":
                    username, code = args
                    print(f"Verifying auth code for {username}: {code}")
                    if username in self.auth_codes:
                        session = self.auth_codes[username]
                        print(f"Stored session: {session}")
                        if time.time() > session['expires']:
                            del self.auth_codes[username]
                            client.send("AUTH_FAILED:Code expired".encode())
                            print(f"Auth code expired for {username}")
                        elif session['code'] == code:
                            current_user = username
                            current_role = session['role']
                            del self.auth_codes[username]
                            client.send("AUTH_SUCCESS".encode())
                            self.logger.log_action(username, "login")
                            self.user_manager.log_audit(username, "login", addr[0])
                            print(f"Auth code verified for {username}")
                        else:
                            client.send("AUTH_FAILED:Invalid code".encode())
                            print(f"Invalid auth code for {username}: expected {session['code']}, got {code}")
                    else:
                        client.send("AUTH_FAILED:Invalid session".encode())
                        print(f"No auth code session for {username}")
                
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
                    success, message = self.user_manager.register_user(username, password, email, "normal", mfa_secret)
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
                    password_valid, _ = self.user_manager.verify_current_password(username, new_password)
                    if password_valid:
                        client.send("ERROR:New password cannot be the same as the old password".encode())
                        continue
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
                    if username != current_user:
                        client.send("ERROR:Permission denied".encode())
                        continue
                    password_valid, _ = self.user_manager.verify_current_password(username, current_password)
                    if not password_valid:
                        client.send("ERROR:Current password is incorrect".encode())
                        continue
                    new_password_same, _ = self.user_manager.verify_current_password(username, new_password)
                    if new_password_same:
                        client.send("ERROR:New password cannot be the same as the current password".encode())
                        continue
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
                
                elif command == "UPLOAD":
                    self.handle_upload(client, args, addr, current_user, current_role)
                elif command == "CONFIRM":
                    if len(args) != 1 or args[0] not in ["yes", "no"]:
                        client.send("ERROR:Invalid confirmation response".encode())
                        continue
                    # Handled within handle_upload
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
            
            # Check if file already exists
            existing_metadata = self.file_controller.get_metadata(filename)
            if existing_metadata:
                if current_role == "admin" or existing_metadata["owner"] == current_user:
                    client.send(f"CONFIRM_OVERWRITE:File '{filename}' already exists. Overwrite? (yes/no)".encode())
                    print(f"Prompting {current_user} to confirm overwrite of '{filename}'")
                    
                    response = client.recv(1024).decode()
                    response_command, response_args = Protocol.parse_message(response)
                    if response_command == "CONFIRM" and response_args[0] == "yes":
                        print(f"User {current_user} confirmed overwrite of '{filename}'")
                    elif response_command == "CONFIRM" and response_args[0] == "no":
                        client.send("UPLOAD_CANCELLED:Upload cancelled by user".encode())
                        print(f"User {current_user} declined to overwrite '{filename}'")
                        # Clear any residual data with timeout
                        client.settimeout(0.1)
                        while True:
                            try:
                                client.recv(1024)
                            except socket.timeout:
                                break
                        client.settimeout(None)
                        return
                    else:
                        client.send("ERROR:Invalid confirmation response".encode())
                        print(f"Invalid confirmation response from {current_user}")
                        return
                else:
                    client.send("ERROR:File already exists with this name. Please use a different filename.".encode())
                    print(f"Upload rejected: {current_user} tried to overwrite '{filename}' owned by {existing_metadata['owner']}")
                    return
            
            # Proceed with upload (new file or confirmed overwrite)
            data = client.recv(size)
            self.file_controller.store_file(filename, data)
            self.file_controller.store_key(filename, key)
            self.file_controller.store_metadata(filename, current_user, visibility)
            self.logger.log_action(addr[0], f"uploaded {filename} ({visibility})")
            self.user_manager.log_audit(current_user, f"uploaded file {filename}", addr[0])
            client.send("UPLOAD_SUCCESS".encode())
            print(f"File '{filename}' uploaded successfully by {current_user}")
        except ValueError as e:
            client.send(f"ERROR:Invalid size: {e}".encode())
            print(f"ValueError in handle_upload: {e}")
    
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
            metadata = self.file_controller.get_metadata(filename)
            if not metadata:
                client.send("ERROR:File not found".encode())
                return
            if current_role != "admin" and metadata["owner"] != current_user:
                client.send("ERROR:Permission denied".encode())
                return
            data = b""
            while len(data) < size:
                chunk = client.recv(min(size - len(data), 4096))
                if not chunk:
                    raise Exception("Client disconnected during upload")
                data += chunk
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
    
    def handle_list(self, client, addr, current_user, current_role):
        if current_role == "guest":
            client.send("ERROR:Guests cannot list files".encode())
            return
        try:
            files = self.file_controller.list_files(current_user, current_role)
            if files:
                file_list = "\n".join([f"{f['filename']} (Owner: {f['owner']}, Your Privilege: {f['privilege']})" for f in files])
                client.send(f"FILES:{file_list}".encode())
            else:
                client.send("FILES:No files visible".encode())
            self.logger.log_action(addr[0], "listed files")
            self.user_manager.log_audit(current_user, "listed files", addr[0])
        except Exception as e:
            print(f"Error in handle_list: {e}")
            client.send(f"ERROR:Failed to list files: {str(e)}".encode())
    
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