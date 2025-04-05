import socket
import os
import getpass
import pyotp
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
                return True
            else:
                print("Authentication failed!")
                return False
        except Exception as e:
            print(f"Login error: {e}")
            return False
    
    def register(self):
        username = input("Create username: ")
        password = getpass.getpass("Create password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("Passwords do not match!")
            return
        
        email = input("Enter your email for account recovery: ")
        
        # Ask if user wants to set up MFA
        setup_mfa = input("Do you want to set up Multi-Factor Authentication (y/n)? ").lower() == 'y'
        mfa_secret = None
        
        if setup_mfa:
            mfa_secret = pyotp.random_base32()
            totp = pyotp.TOTP(mfa_secret)
            print("\nMFA Setup")
            print(f"Your MFA secret: {mfa_secret}")
            print("Please save this secret or scan the QR code in your authenticator app (Google Authenticator, Authy, etc.)")
            print(f"QR Code URL: otpauth://totp/SecureFileSharing:{username}?secret={mfa_secret}&issuer=SecureFileSharing")
            
            # Verify the user has set up MFA
            print("\nVerify your MFA setup:")
            verification_code = input("Enter the code from your authenticator app: ")
            
            totp = pyotp.TOTP(mfa_secret)
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
        username = input("Enter your username: ")
        email = input("Enter your registered email: ")
        
        response = request_password_reset(self.socket, username, email)
        
        if response.startswith("RESET_CODE:"):
            verification_code = response.split(":")[1]
            print("A verification code has been sent to your email.")
            print(f"For demo purposes, the code is: {verification_code}")
            
            user_code = input("Enter the verification code: ")
            
            if user_code == verification_code:
                new_password = getpass.getpass("Enter new password: ")
                confirm_password = getpass.getpass("Confirm new password: ")
                
                if new_password != confirm_password:
                    print("Passwords do not match!")
                    return
                
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
        new_password = getpass.getpass("Enter new password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        
        if new_password != confirm_password:
            print("New passwords do not match!")
            return
        
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
        visibility = input("Set visibility (private/public/unlisted): ").lower().strip()
        if visibility not in ["private", "public", "unlisted"]:
            print("Invalid visibility. Use: private, public, or unlisted.")
            return
        self.file_manager.upload_file(filepath, self.crypto, visibility)
    
    def handle_download(self):
        filename = input("Enter filename to download: ").strip()
        if not filename:
            print("Filename cannot be empty.")
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
        filename = input("Enter filename to delete: ").strip()
        if not filename:
            print("Filename cannot be empty.")
            return
        self.socket.send(f"DELETE:{filename}".encode())
        response = self.socket.recv(1024).decode()
        if response == "DELETE_SUCCESS":
            print(f"File '{filename}' deleted successfully!")
        else:
            print(f"Error deleting file: {response.split(':', 1)[1] if ':' in response else response}")
    
    def handle_edit_permissions(self):
        filename = input("Enter filename to edit permissions: ").strip()
        if not filename:
            print("Filename cannot be empty.")
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
    
    def handle_edit_content(self):
        # This function allows users to edit their own files
        filename = input("Enter filename to edit content: ").strip()
        if not filename:
            print("Filename cannot be empty.")
            return
        
        # Download the file first
        self.socket.send(f"DOWNLOAD:{filename}".encode())
        response = self.socket.recv(1024).decode()
        
        if not response.startswith("FILE:"):
            print(f"Error: {response.split(':', 1)[1] if ':' in response else response}")
            return
        
        size = int(response.split(":", 1)[1])
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
        
        # Decrypt the file
        try:
            decrypted_data = self.crypto.decrypt(encrypted_data, key)
            
            # Save to a temporary file for editing
            temp_filename = f"temp_{filename}"
            with open(temp_filename, "wb") as f:
                f.write(decrypted_data)
            
            print(f"\nFile '{filename}' downloaded for editing.")
            print(f"It has been saved as '{temp_filename}'.")
            print("Please edit this file with your preferred text editor.")
            input("Press Enter when you have finished editing...")
            
            # Check if file exists and read it
            if not os.path.exists(temp_filename):
                print("Error: Temporary file not found after editing!")
                return
            
            with open(temp_filename, "rb") as f:
                modified_data = f.read()
            
            # Get the file's current visibility
            self.socket.send(f"GET_METADATA:{filename}".encode())
            metadata_response = self.socket.recv(1024).decode()
            
            if not metadata_response.startswith("METADATA:"):
                print(f"Error getting file metadata: {metadata_response}")
                return
            
            visibility = metadata_response.split(":")[1]
            
            # Encrypt and upload the modified file
            encrypted_modified_data, new_key = self.crypto.encrypt(modified_data)
            
            # Send the UPDATE command
            self.socket.send(f"UPDATE:{filename}:{len(encrypted_modified_data)}:{new_key.decode()}:{visibility}".encode())
            self.socket.send(encrypted_modified_data)
            
            update_response = self.socket.recv(1024).decode()
            
            if update_response == "UPDATE_SUCCESS":
                print(f"File '{filename}' updated successfully!")
                # Clean up temporary file
                try:
                    os.remove(temp_filename)
                except:
                    print(f"Note: Could not remove temporary file '{temp_filename}'")
            else:
                print(f"Error updating file: {update_response.split(':', 1)[1] if ':' in update_response else update_response}")
        
        except Exception as e:
            print(f"Error during file editing: {e}")
    
    def manage_mfa(self):
        print("\n=== Multi-Factor Authentication Management ===")
        print("1. Enable MFA")
        print("2. Disable MFA")
        print("3. Back to main menu")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == "1":
            self.socket.send(f"ENABLE_MFA:{self.current_user}".encode())
            response = self.socket.recv(1024).decode()
            
            if response.startswith("MFA_ENABLED:"):
                mfa_secret = response.split(":")[1]
                print("\nMFA has been enabled!")
                print(f"Your MFA secret: {mfa_secret}")
                print("Please save this secret or scan the QR code in your authenticator app")
                print(f"QR Code URL: otpauth://totp/SecureFileSharing:{self.current_user}?secret={mfa_secret}&issuer=SecureFileSharing")
                
                # Verify setup
                verification_code = input("\nEnter the code from your authenticator app to verify setup: ")
                totp = pyotp.TOTP(mfa_secret)
                
                if totp.verify(verification_code):
                    print("MFA setup verified successfully!")
                else:
                    print("Warning: MFA verification failed, but MFA is still enabled.")
                    print("If you have trouble logging in, contact an administrator.")
            else:
                print(f"Failed to enable MFA: {response.split(':', 1)[1] if ':' in response else response}")
        
        elif choice == "2":
            confirm = input("Are you sure you want to disable MFA? This will reduce account security. (y/n): ")
            if confirm.lower() == 'y':
                self.socket.send(f"DISABLE_MFA:{self.current_user}".encode())
                response = self.socket.recv(1024).decode()
                
                if response == "MFA_DISABLED":
                    print("MFA has been disabled.")
                else:
                    print(f"Failed to disable MFA: {response.split(':', 1)[1] if ':' in response else response}")
            else:
                print("MFA disable operation cancelled.")
        
        elif choice == "3":
            return
        
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    SERVER_HOST = "localhost"  # Replace with your server's public IP or domain
    SERVER_PORT = 5000
    try:
        client = Client(SERVER_HOST, SERVER_PORT)
        client.run()
    except Exception as e:
        print(f"Failed to start client: {e}")