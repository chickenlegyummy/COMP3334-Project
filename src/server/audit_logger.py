import logging
from datetime import datetime

class AuditLogger:
    def __init__(self, log_file):
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )
    
    def log_action(self, user, action):
        logging.info(f"User: {user}, Action: {action}")