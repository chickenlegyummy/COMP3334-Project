class Protocol:
    @staticmethod
    def parse_message(message):
        parts = message.split(":", 5)  # Up to 6 parts for EDIT:filename:visibility:add_users:remove_users
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        return command, args