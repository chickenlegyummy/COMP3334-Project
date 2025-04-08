import socket
import os
import getpass
import re
import time
import platform
import subprocess
import signal
from src.common.totp import TOTP
from src.common.security import SecurityUtils
from .auth import authenticate, verify_mfa, request_password_reset
from .file_manager import FileManager
from .crypto import Crypto

class Client:
    def __init__(self, host, port):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.file_manager = FileManager(self.socket)
            self.crypto = Crypto()
            self.current_user = None
            # Track launched processes for cleanup
            self.opened_processes = []
        except socket.error as e:
            print(f"Failed to connect to server {host}:{port}: {e}")
            raise
    
    def run(self):
        try:
            print("\n=== Secure File Sharing System ===")
            while True:
                if not self.current_user:
                    self.show_auth_menu()
                else:
                    self.main_loop()
        except socket.error as e:
            print(f"Network error: {e}")
        except KeyboardInterrupt:
            print("\nApplication terminated by user.")
        except Exception as e:
            print(f"Unexpected error: {e}")
        finally:
            if self.current_user:
                self.logout()
            self.socket.close()
            print("Client connection closed.")
    
    def show_auth_menu(self):
        print("\n=== Authentication Menu ===")
        print("1. Login")
        print("2. Register")
        print("3. Reset Password")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            self.login()
        elif choice == "2":
            self.register()
        elif choice == "3":
            self.reset_password()
        elif choice == "4":
            print("Exiting application...")
            raise SystemExit(0)
        else:
            print("Invalid choice. Please try again.")
    
    def login(self):
        try:
            if authenticate(self.socket):
                print("Authentication successful!")
                self.current_user = input("Enter your username again to confirm: ")
                # Validate username to prevent injection
                if not re.match(r'^[\w@\.\+\-]{3,30}$', self.current_user):
                    print("Invalid username format.")
                    self.current_user = None
                    return False
                return True
            else:
                print("Authentication failed!")
                return False
        except Exception as e:
            print(f"Login error: {e}")
            return False
    
    def register(self):
        # Get username with validation
        while True:
            username = input("Create username (3-30 characters, alphanumeric and @.+-_): ")
            if re.match(r'^[\w@\.\+\-]{3,30}$', username):
                break
            print("Invalid username format. Please use letters, numbers, and the characters @.+-_")
        
        # Get password with validation
        while True:
            password = getpass.getpass("Create password (at least 8 char long, must contain uppercase, lowercase, digit, and special characters): ")
            is_strong, message = SecurityUtils.is_password_strong(password)
            if not is_strong:
                print(message)
                continue
                
            confirm_password = getpass.getpass("Confirm password: ")
            if password != confirm_password:
                print("Passwords do not match!")
                continue
            break
        
        # Get email with validation
        while True:
            email = input("Enter your email for account recovery: ")
            if re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                break
            print("Invalid email format. Please enter a valid email address.")
        
        # Ask if user wants to set up MFA
        setup_mfa = input("Do you want to set up Multi-Factor Authentication (y/n)? ").lower() == 'y'
        mfa_secret = None
        
        if setup_mfa:
            # Use our custom TOTP implementation
            totp = TOTP()
            mfa_secret = totp.secret
            print("\nMFA Setup")
            print(f"Your MFA secret: {mfa_secret}")
            print("Please save this secret or scan the QR code in your authenticator app (Google Authenticator, Authy, etc.)")
            print(f"QR Code URL: {totp.provisioning_uri(username)}")
            
            # Verify the user has set up MFA
            print("\nVerify your MFA setup:")
            verification_code = input("Enter the code from your authenticator app: ")
            
            if not totp.verify(verification_code):
                print("Invalid verification code. MFA setup failed. Please try again.")
                return
        
        # Send registration request
        if mfa_secret:
            self.socket.send(f"REGISTER:{username}:{password}:{email}:{mfa_secret}".encode())
        else:
            self.socket.send(f"REGISTER:{username}:{password}:{email}".encode())
        
        response = self.socket.recv(1024).decode()
        if response == "REGISTER_SUCCESS":
            print("Registration successful! You can now login.")
        else:
            print(f"Registration failed: {response.split(':', 1)[1] if ':' in response else response}")
    
    def reset_password(self):
        # Get username with validation
        while True:
            username = input("Enter your username: ")
            if re.match(r'^[\w@\.\+\-]{3,30}$', username):
                break
            print("Invalid username format.")
        
        # Get email with validation
        while True:
            email = input("Enter your registered email: ")
            if re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                break
            print("Invalid email format.")
        
        response = request_password_reset(self.socket, username, email)
        
        if response.startswith("RESET_CODE:"):
            verification_code = response.split(":")[1]
            print("A verification code has been sent to your email.")
            print(f"For demo purposes, the code is: {verification_code}")
            
            user_code = input("Enter the verification code: ")
            
            if user_code == verification_code:
                # Get and validate new password
                while True:
                    new_password = getpass.getpass("Enter new password (at least 8 char long, must contain uppercase, lowercase, digit, and special characters): ")
                    is_strong, message = SecurityUtils.is_password_strong(new_password)
                    if not is_strong:
                        print(message)
                        continue
                        
                    confirm_password = getpass.getpass("Confirm new password: ")
                    if new_password != confirm_password:
                        print("Passwords do not match!")
                        continue
                    break
                
                self.socket.send(f"RESET_PASSWORD:{username}:{new_password}".encode())
                response = self.socket.recv(1024).decode()
                
                if response == "PASSWORD_UPDATED":
                    print("Password reset successful! You can now login with your new password.")
                else:
                    print(f"Password reset failed: {response.split(':', 1)[1] if ':' in response else response}")
            else:
                print("Invalid verification code!")
        else:
            print(f"Password reset request failed: {response.split(':', 1)[1] if ':' in response else response}")
    
    def logout(self):
        if self.current_user:
            self.socket.send(f"LOGOUT:{self.current_user}".encode())
            response = self.socket.recv(1024).decode()
            
            if response == "LOGOUT_SUCCESS":
                print("Logged out successfully!")
            else:
                print(f"Logout error: {response.split(':', 1)[1] if ':' in response else response}")
            
            self.current_user = None
    
    def change_password(self):
        current_password = getpass.getpass("Enter current password: ")
        
        # Get and validate new password
        while True:
            new_password = getpass.getpass("Enter new password (at least 8 char long, must contain uppercase, lowercase, digit, and special characters): ")
            is_strong, message = SecurityUtils.is_password_strong(new_password)
            if not is_strong:
                print(message)
                continue
                
            confirm_password = getpass.getpass("Confirm new password: ")
            if new_password != confirm_password:
                print("Passwords do not match!")
                continue
            break
        
        self.socket.send(f"CHANGE_PASSWORD:{self.current_user}:{current_password}:{new_password}".encode())
        response = self.socket.recv(1024).decode()
        
        if response == "PASSWORD_UPDATED":
            print("Password changed successfully!")
        else:
            print(f"Password change failed: {response.split(':', 1)[1] if ':' in response else response}")
    
    def main_loop(self):
        while True:
            try:
                print("\n=== File Operations Menu ===")
                print("1. Upload a file")
                print("2. Download a file")
                print("3. List files")
                print("4. Delete a file")
                print("5. Edit file permissions")
                print("6. Edit file content")
                print("7. Change password")
                print("8. Manage MFA")
                print("9. Logout")
                print("0. Exit")
                
                choice = input("Enter your choice (0-9): ").strip()
                
                if choice == "0":
                    if self.current_user:
                        self.logout()
                    print("Exiting application...")
                    break
                elif choice == "1":
                    self.handle_upload()
                elif choice == "2":
                    self.handle_download()
                elif choice == "3":
                    self.handle_list()
                elif choice == "4":
                    self.handle_delete()
                elif choice == "5":
                    self.handle_edit_permissions()
                elif choice == "6":
                    self.handle_edit_content()
                elif choice == "7":
                    self.change_password()
                elif choice == "8":
                    self.manage_mfa()
                elif choice == "9":
                    self.logout()
                    return
                else:
                    print("Invalid choice. Please enter a number between 0-9.")
            
            except socket.error as e:
                print(f"Network error: {e}. Check your connection or server status.")
                break
            except ValueError as e:
                print(f"Input error: {e}. Please try again.")
            except FileNotFoundError as e:
                print(f"File error: {e}. Check the file path or filename.")
            except Exception as e:
                print(f"Unexpected error: {e}. Please try again or contact support.")
    
    def handle_upload(self):
        filepath = input("Enter file path: ").strip()
        if not filepath:
            print("File path cannot be empty.")
            return
            
        # Validate visibility
        while True:
            visibility = input("Set visibility (private/public/unlisted): ").lower().strip()
            if visibility in ["private", "public", "unlisted"]:
                break
            print("Invalid visibility. Use: private, public, or unlisted.")
            
        self.file_manager.upload_file(filepath, self.crypto, visibility)
    
    def handle_download(self):
        # Show available files first
        self.handle_list()
        
        filename = input("Enter filename to download: ").strip()
        if not filename:
            print("Filename cannot be empty.")
            return
        
        # Don't sanitize the filename - this might remove spaces
        # Just ensure basic validation without affecting the spaces
        if not re.match(r'^[a-zA-Z0-9\s\.\-_]+$', filename):
            print("Invalid filename. Please use only letters, numbers, spaces, and characters .-_")
            return
            
        self.file_manager.download_file(filename, self.crypto)
    
    def handle_list(self):
        self.socket.send("LIST".encode())
        response = self.socket.recv(2048).decode()
        if response.startswith("FILES:"):
            files = response.split(":", 1)[1]
            if files.strip():
                print("Files in storage:\n" + files)
            else:
                print("No files available.")
        else:
            print("Error listing files: " + response.split(":", 1)[1] if ":" in response else response)
    
    def handle_delete(self):
        # Show available files first
        self.handle_list()
        
        filename = input("Enter filename to delete: ").strip()
        if not filename:
            print("Filename cannot be empty.")
            return
        
        # Don't sanitize the filename - this might remove spaces
        # Just ensure basic validation without affecting the spaces
        if not re.match(r'^[a-zA-Z0-9\s\.\-_]+$', filename):
            print("Invalid filename. Please use only letters, numbers, spaces, and characters .-_")
            return
            
        self.socket.send(f"DELETE:{filename}".encode())
        response = self.socket.recv(1024).decode()
        if response == "DELETE_SUCCESS":
            print(f"File '{filename}' deleted successfully!")
        else:
            print(f"Error deleting file: {response.split(':', 1)[1] if ':' in response else response}")
    
    def handle_edit_permissions(self):
        # Show available files first
        self.handle_list()
        
        filename = input("Enter filename to edit permissions: ").strip()
        if not filename:
            print("Filename cannot be empty.")
            return
        
        # Don't sanitize the filename - this might remove spaces
        # Just ensure basic validation without affecting the spaces
        if not re.match(r'^[a-zA-Z0-9\s\.\-_]+$', filename):
            print("Invalid filename. Please use only letters, numbers, spaces, and characters .-_")
            return
        
        visibility = input("New visibility (private/public/unlisted, or leave blank): ").lower().strip()
        if visibility and visibility not in ["private", "public", "unlisted"]:
            print("Invalid visibility. Use: private, public, unlisted, or leave blank.")
            return
        
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
                return
                
            add_users_input = input("Users to add (comma-separated, or leave blank): ").strip()
            remove_users_input = input("Users to remove (comma-separated, or leave blank): ").strip()
            
            # Validate and sanitize usernames
            add_users = []
            for user in add_users_input.split(","):
                user = user.strip()
                if user and re.match(r'^[\w@\.\+\-]{3,30}$', user):
                    add_users.append(user)
                elif user:
                    print(f"Warning: Skipping invalid username '{user}'")
                    
            remove_users = []
            for user in remove_users_input.split(","):
                user = user.strip()
                if user and re.match(r'^[\w@\.\+\-]{3,30}$', user):
                    remove_users.append(user)
                elif user:
                    print(f"Warning: Skipping invalid username '{user}'")
            
            # Join validated usernames
            add_users_str = ",".join(add_users) if add_users else ""
            remove_users_str = ",".join(remove_users) if remove_users else ""
            
            cmd += f":{visibility}" if visibility else ":"
            cmd += f":{add_users_str}" if add_users_str else ":"
            cmd += f":{remove_users_str}" if remove_users_str else ":"
        
        self.socket.send(cmd.encode())
        response = self.socket.recv(1024).decode()
        if response == "EDIT_SUCCESS":
            print(f"Privileges for '{filename}' updated successfully!")
        else:
            print(f"Error editing file: {response.split(':', 1)[1] if ':' in response else response}")
    
    def handle_edit_content(self):
        # Show available files first
        self.handle_list()
        
        filename = input("Enter filename to edit content: ").strip()
        if not filename:
            print("Filename cannot be empty.")
            return
        
        # Basic validation without removing spaces
        if not re.match(r'^[a-zA-Z0-9\s\.\-_]+$', filename):
            print("Invalid filename. Use only letters, numbers, spaces, and .-_")
            return
        
        # Check user's privilege for this file before proceeding
        self.socket.send("LIST".encode())
        response = self.socket.recv(2048).decode()
        if not response.startswith("FILES:"):
            print(f"Error fetching file list: {response.split(':', 1)[1] if ':' in response else response}")
            return
        
        files = response.split(":", 1)[1].strip()
        privilege = None
        for line in files.split("\n"):
            if filename in line:
                privilege = line.split("Your Privilege: ")[1].rstrip(")")
                break
        
        if not privilege:
            print(f"File '{filename}' not found in your accessible files.")
            return
        if privilege != "edit":
            print(f"You don’t have permission to edit '{filename}'. (Your privilege: {privilege})")
            return
        
        # Proceed with download and edit only if user has edit privilege
        self.socket.send(f"DOWNLOAD:{filename}".encode())
        response = self.socket.recv(1024).decode()
        
        if not response.startswith("FILE:"):
            print(f"Error: {response.split(':', 1)[1] if ':' in response else response}")
            return
        
        size = int(response.split(":", 1)[1])
        if size > 10 * 1024 * 1024:  # 10MB limit
            print("File is too large for editing (max 10MB).")
            self.socket.send("CANCEL_DOWNLOAD".encode())
            return
        
        encrypted_data = b""
        while len(encrypted_data) < size:
            chunk = self.socket.recv(size - len(encrypted_data))
            if not chunk:
                print("Connection closed before receiving full file!")
                return
            encrypted_data += chunk
        
        key_response = self.socket.recv(1024).decode()
        if not key_response.startswith("KEY:"):
            print(f"Error: {key_response}")
            return
        
        key = key_response.split(":", 1)[1].encode()
        
        try:
            self.opened_processes = []
            decrypted_data = self.crypto.decrypt(encrypted_data, key)
            safe_filename = filename.replace(" ", "_")
            temp_dir = "temp_edits"
            os.makedirs(temp_dir, exist_ok=True)
            temp_filepath = os.path.abspath(f"{temp_dir}/temp_{safe_filename}")
            
            with open(temp_filepath, "wb") as f:
                f.write(decrypted_data)
            
            print(f"\nFile '{filename}' downloaded for editing.")
            print(f"Saved as '{temp_filepath}'.")
            
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext in ['.txt', '.md', '.csv', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf']:
                open_file = input(f"Open this {file_ext} file automatically? (y/n): ").lower() == 'y'
                if open_file:
                    try:
                        process = None
                        if platform.system() == 'Darwin':
                            process = subprocess.Popen(['open', temp_filepath])
                            self.opened_processes.append(process.pid)
                        elif platform.system() == 'Windows':
                            os.startfile(temp_filepath)
                        else:
                            process = subprocess.Popen(['xdg-open', temp_filepath])
                            self.opened_processes.append(process.pid)
                        print(f"File opened in default {file_ext} editor.")
                    except Exception as e:
                        print(f"Failed to open file: {e}")
                        print(f"Open '{temp_filepath}' manually.")
            else:
                print(f"Open '{temp_filepath}' with your preferred editor.")
            
            print("\nIMPORTANT: When done:")
            print("1. Save changes in the editor")
            print("2. Press Enter here to upload")
            input("\nPress Enter when finished editing...")
            
            self._attempt_close_applications(temp_filepath)
            
            if not os.path.exists(temp_filepath):
                print("Error: Temp file not found after editing!")
                return
            
            if os.path.getsize(temp_filepath) > 10 * 1024 * 1024:
                print("Error: Edited file too large (max 10MB).")
                return
            
            max_attempts = 3
            for attempt in range(max_attempts):
                try:
                    with open(temp_filepath, "rb") as f:
                        modified_data = f.read()
                    break
                except (IOError, PermissionError):
                    if attempt < max_attempts - 1:
                        print("File locked. Trying to close apps...")
                        self._attempt_close_applications(temp_filepath)
                        time.sleep(0.2)
                    else:
                        print("Could not read file after retries.")
                        return
            
            self.socket.send(f"GET_METADATA:{filename}".encode())
            metadata_response = self.socket.recv(1024).decode()
            if not metadata_response.startswith("METADATA:"):
                print(f"Error getting metadata: {metadata_response}")
                return
            visibility = metadata_response.split(":")[1]
            
            encrypted_modified_data, new_key = self.crypto.encrypt(modified_data)
            self.socket.send(f"UPDATE:{filename}:{len(encrypted_modified_data)}:{new_key.decode()}:{visibility}".encode())
            self.socket.send(encrypted_modified_data)
            
            update_response = self.socket.recv(1024).decode()
            if update_response == "UPDATE_SUCCESS":
                print(f"File '{filename}' updated successfully!")
                self._remove_temp_file(temp_filepath)
            else:
                print(f"Error updating file: {update_response.split(':', 1)[1] if ':' in update_response else update_response}")
                self._remove_temp_file(temp_filepath)
        
        except Exception as e:
            print(f"Error during editing: {e}")
    
    def _attempt_close_applications(self, filepath):
        """Attempt to close any applications that might be using the file"""
        # First, try to close apps we launched
        for pid in self.opened_processes:
            try:
                if platform.system() == 'Windows':
                    # On Windows, use taskkill
                    subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE)
                else:
                    # On Unix-like systems, use kill
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.1)  # Give a moment for process to terminate
                    # If still running, try harder
                    try:
                        os.kill(pid, 0)  # Check if process exists
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass  # Process already terminated
            except Exception:
                pass
                
        # On Windows, try to close processes using the file
        if platform.system() == 'Windows':
            try:
                # Try using taskkill to terminate processes that have the file open
                # This is a more aggressive approach
                file_dir, file_name = os.path.split(filepath)
                subprocess.run(['taskkill', '/F', '/FI', f'WINDOWTITLE eq {file_name}*'], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
                
                # Try also terminating common editor processes
                for editor in ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "WORDPAD.EXE", "notepad.exe"]:
                    subprocess.run(['taskkill', '/F', '/IM', editor], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE)
            except Exception:
                pass
                
        # On macOS, try to use osascript to quit applications
        elif platform.system() == 'Darwin':
            try:
                for app in ["Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint", "TextEdit"]:
                    subprocess.run(['osascript', '-e', f'tell application "{app}" to quit'], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE)
            except Exception:
                pass
                
        # On Linux, try using fuser to find and kill processes
        elif platform.system() == 'Linux':
            try:
                # Find processes using the file
                subprocess.run(['fuser', '-k', filepath], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
            except Exception:
                pass
            
    def _remove_temp_file(self, temp_filepath, max_retries=3, retry_delay=0.2):
        """Helper method to remove temporary files with fast retry logic"""
        for attempt in range(max_retries):
            try:
                os.remove(temp_filepath)
                print(f"Temporary file removed successfully.")
                return True
            except PermissionError:
                if attempt < max_retries - 1:
                    if attempt == 0:
                        print(f"File is still in use. Attempting to force close applications...")
                    self._attempt_close_applications(temp_filepath)
                    time.sleep(retry_delay)
                else:
                    print(f"\nStill cannot remove the temporary file after closing applications.")
                    
                    # Try more aggressive methods on Windows
                    if platform.system() == 'Windows':
                        try:
                            print("Attempting a forced delete...")
                            os.system(f'attrib -R -S -H "{temp_filepath}"')
                            os.remove(temp_filepath)
                            print("Temporary file removed successfully with force method.")
                            return True
                        except Exception:
                            print(f"Could not remove file. It will remain at: {temp_filepath}")
                            return False
                    else:
                        print(f"Temporary file will remain at: {temp_filepath}")
                        return False
            except Exception as e:
                print(f"Warning: Could not remove temporary file: {e}")
                return False
    
    def manage_mfa(self):
        print("\n=== Multi-Factor Authentication Management ===")
        print("1. Enable MFA")
        print("2. Disable MFA")
        print("3. Back to main menu")
        
        choice = input("Enter your choice (1-3): ").strip()
        
        if choice == "1":
            self.socket.send(f"ENABLE_MFA:{self.current_user}".encode())
            response = self.socket.recv(1024).decode()
            
            if response.startswith("MFA_ENABLED:"):
                mfa_secret = response.split(":", 1)[1]  # Use split with maxsplit=1 to handle colons in secret
                totp = TOTP(secret=mfa_secret)
                print("\nMFA has been enabled (or updated) for your account!")
                print("Use this new secret to set up your authenticator app:")
                print(f"New MFA Secret: {mfa_secret}")
                print(f"QR Code URL: {totp.provisioning_uri(self.current_user)}")
                print("Open this URL in a QR code scanner or enter the secret manually in your app (e.g., Google Authenticator).")
                
                # Verify setup
                while True:
                    verification_code = input("\nEnter the 6-digit code from your authenticator app to verify: ")
                    if not re.match(r'^\d{6}$', verification_code):
                        print("Invalid format. Enter a 6-digit code.")
                        continue
                    if totp.verify(verification_code):
                        print("MFA setup verified successfully! You’ll need this code for future logins.")
                        break
                    else:
                        print("Invalid code. Try again or ensure your app is set up with the new secret.")
            else:
                print(f"Failed to enable MFA: {response.split(':', 1)[1] if ':' in response else response}")
        
        elif choice == "2":
            confirm = input("Are you sure you want to disable MFA? This will reduce account security. (y/n): ").lower()
            if confirm == 'y':
                self.socket.send(f"DISABLE_MFA:{self.current_user}".encode())
                response = self.socket.recv(1024).decode()
                
                if response == "MFA_DISABLED":
                    print("MFA has been disabled. You won’t need a code to log in.")
                else:
                    print(f"Failed to disable MFA: {response.split(':', 1)[1] if ':' in response else response}")
            else:
                print("MFA disable cancelled.")
        
        elif choice == "3":
            return
        
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    SERVER_HOST = "localhost"  # Replace with your server's public IP or domain
    SERVER_PORT = 5000
    try:
        client = Client(SERVER_HOST, SERVER_PORT)
        client.run()
    except Exception as e:
        print(f"Failed to start client: {e}")