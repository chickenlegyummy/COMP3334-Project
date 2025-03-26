# TeamName Project

This repository contains a client-server application for secure file management and sharing. The project is organized into separate modules for the client, server, and shared components, providing a clear and maintainable structure.

## Table of Contents

- [Project Structure](#project-structure)
- [Setup Instructions](#setup-instructions)
  - [Install Dependencies](#install-dependencies)
  - [Set Up the Database](#set-up-the-database)
  - [Run the Server](#run-the-server)
  - [Run the Client](#run-the-client)
- [Testing](#testing)
- [Packaging](#packaging)
- [Demo](#demo)

---

## Project Structure

TeamName/
├── code/
│ ├── client/ # Client-side functionality
│ │ ├── init.py
│ │ ├── client.py # Main client program
│ │ ├── crypto.py # Client-side encryption functions
│ │ ├── auth.py # Authentication functions
│ │ ├── file_manager.py # File handling & sharing
│ │ └── utils.py # Helper functions
│ ├── server/ # Server-side functionality
│ │ ├── init.py
│ │ ├── server.py # Main server program
│ │ ├── database.py # Database interface
│ │ ├── user_manager.py # User management
│ │ ├── file_controller.py # File storage management
│ │ ├── audit_logger.py # Logging system
│ │ └── utils.py # Helper functions
│ ├── common/ # Shared components
│ │ ├── init.py
│ │ ├── protocol.py # Communication protocol
│ │ └── constants.py # Shared constants
│ ├── setup.py # Installation setup
│ ├── requirements.txt # Dependencies
│ └── schema.sql # Database schema
├── report.pdf # Project documentation
└── video.mp4 # Project demo video

---

## Setup Instructions

Follow these steps to set up and run the project:

### 1. Install Dependencies

Ensure you have Python 3.x installed. Then, install the project's dependencies by running:

```bash
pip install -r requirements.txt
```

2. Set Up the Database
The database schema is defined in schema.sql. To initialize the database:

Use a database management system (e.g., SQLite, MySQL, or PostgreSQL).
For SQLite, run the following command in the root directory:
```bash
sqlite3 database_name.db < schema.sql
```

Update the database configuration in server/database.py if necessary.

3. Run the Server
Start the server by running:

```bash
python code/server/server.py
```
4. Run the Client
Start the client by running:

```bash
python code/client/client.py
```

5. Testing
Test the functionality of the project by verifying:

1.Client-server communication using the protocol defined in common/protocol.py.
2.Authentication and user management.
3.File sharing and encryption.
4.Logging and audit trails.

6. Packaging
To package the project for distribution, use setup.py:

```bash
python setup.py install
```
7. Demo
A demo video (video.mp4) is included in the repository to showcase the functionality of the project. You can also refer to report.pdf for detailed documentation.