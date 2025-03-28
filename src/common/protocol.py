class Protocol:
    @staticmethod
    def parse_message(message):
        parts = message.split(":", 3)  # Up to 4 parts for UPLOAD:filename:size:key
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        return command, args