import getpass


def authenticate(socket):
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    credentials = f"AUTH:{username}:{password}"
    socket.send(credentials.encode())
    response = socket.recv(1024).decode()
    
    if response.startswith("MFA_REQUIRED:"):
        session_id = response.split(":")[1]
        code = input("Enter the verification code from your authenticator app: ")
        socket.send(f"MFA_VERIFY:{session_id}:{code}".encode())
        mfa_response = socket.recv(1024).decode()
        return mfa_response == "AUTH_SUCCESS"
    
    return response == "AUTH_SUCCESS"

def verify_mfa(socket, code, session_id):
    socket.send(f"MFA_VERIFY:{session_id}:{code}".encode())
    response = socket.recv(1024).decode()
    return response == "AUTH_SUCCESS"

def request_password_reset(socket, username, email):
    socket.send(f"RESET_REQUEST:{username}:{email}".encode())
    response = socket.recv(1024).decode()
    return response