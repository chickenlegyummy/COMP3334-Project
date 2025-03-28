def authenticate(socket):
    username = input("Username: ")
    password = input("Password: ")
    credentials = f"AUTH:{username}:{password}"
    socket.send(credentials.encode())
    response = socket.recv(1024).decode()
    return response == "AUTH_SUCCESS"