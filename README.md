# Quick Start Guide – Secure File Storage System
## Team 06
## Authors:
LI Kwan To with Carrot 🥕

This guide helps you quickly set up and run the secure file sharing system.

---

## Requirements

- Python 3.8+
- `cryptography` (Python package)
- **`sqlite3` command-line tool**  
  If it's not already installed, please install SQLite3 manually: https://www.sqlite.org/download.html

---

## Installation

1. Open your terminal or command prompt  
2. Navigate to your project folder  
3. Install the required package:

```bash
pip install cryptography
```

---

## Running the System

### Run Server
```bash
python -m src.server.server
```

### Run Client
```bash
python -m src.client.client
```

Follow the interactive menu to:
- Register and log in
- Enable MFA
- Upload/download encrypted files
- Share files and set permissions
