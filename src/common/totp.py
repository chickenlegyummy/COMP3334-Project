import time
import hmac
import hashlib
import base64
import secrets
import struct

class TOTP:
    """
    Time-based One-Time Password implementation according to RFC 6238
    Custom implementation without external libraries
    """
    def __init__(self, secret=None, digits=6, period=30, algorithm='sha1'):
        """
        Initialize a new TOTP instance
        
        Parameters:
        - secret: Base32 encoded secret key (will generate one if not provided)
        - digits: Number of digits in the generated code (default: 6)
        - period: Time period in seconds for which a code is valid (default: 30)
        - algorithm: Hash algorithm to use (default: sha1)
        """
        self.secret = secret or self.generate_secret()
        self.digits = digits
        self.period = period
        self.algorithm = algorithm
    
    @staticmethod
    def generate_secret(length=16):
        """
        Generate a random secret key
        
        Parameters:
        - length: Length of the secret key in bytes (default: 16)
        
        Returns:
        - Base32 encoded secret key
        """
        # Generate random bytes
        random_bytes = secrets.token_bytes(length)
        
        # Encode in Base32
        base32_encoded = base64.b32encode(random_bytes).decode('utf-8')
        
        return base32_encoded
    
    def _get_hash_algorithm(self):
        """Get the hash algorithm function based on the selected algorithm name"""
        if self.algorithm.lower() == 'sha1':
            return hashlib.sha1
        elif self.algorithm.lower() == 'sha256':
            return hashlib.sha256
        elif self.algorithm.lower() == 'sha512':
            return hashlib.sha512
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
    
    def _decode_base32(self, encoded_str):
        """Decode a Base32 encoded string, ensuring proper padding"""
        # Add padding if needed
        padding = 8 - (len(encoded_str) % 8)
        if padding < 8:
            encoded_str += '=' * padding
        
        return base64.b32decode(encoded_str.upper())
    
    def _generate_hotp(self, counter):
        """
        Generate an HMAC-based One-Time Password
        
        Parameters:
        - counter: Counter value (usually a timestamp)
        
        Returns:
        - OTP code
        """
        # Decode the Base32 encoded secret
        key = self._decode_base32(self.secret)
        
        # Convert counter to a byte array (8 bytes, big-endian)
        counter_bytes = struct.pack('>Q', counter)
        
        # Calculate HMAC
        hash_algorithm = self._get_hash_algorithm()
        hmac_result = hmac.new(key, counter_bytes, hash_algorithm).digest()
        
        # Dynamic truncation
        offset = hmac_result[-1] & 0x0F
        truncated_hash = ((hmac_result[offset] & 0x7F) << 24 |
                          (hmac_result[offset + 1] & 0xFF) << 16 |
                          (hmac_result[offset + 2] & 0xFF) << 8 |
                          (hmac_result[offset + 3] & 0xFF))
        
        # Generate code modulo 10^digits
        code = truncated_hash % (10 ** self.digits)
        
        # Ensure the code has the correct number of digits
        return str(code).zfill(self.digits)
    
    def now(self):
        """
        Generate a TOTP code for the current time
        
        Returns:
        - Current TOTP code
        """
        # Get current timestamp and convert to time window
        counter = int(time.time() // self.period)
        return self._generate_hotp(counter)
    
    def at(self, timestamp):
        """
        Generate a TOTP code for a specific timestamp
        
        Parameters:
        - timestamp: UNIX timestamp
        
        Returns:
        - TOTP code for the given timestamp
        """
        counter = int(timestamp // self.period)
        return self._generate_hotp(counter)
    
    def verify(self, code, timestamp=None, window=1):
        """
        Verify a TOTP code
        
        Parameters:
        - code: The code to verify
        - timestamp: Timestamp to check against (default: current time)
        - window: Number of time periods before and after to check (default: 1)
        
        Returns:
        - True if the code is valid, False otherwise
        """
        if timestamp is None:
            timestamp = time.time()
        
        # Check for current time window and adjacent windows
        for i in range(-window, window + 1):
            check_time = timestamp + (i * self.period)
            counter = int(check_time // self.period)
            if self._generate_hotp(counter) == code:
                return True
        
        return False
    
    def provisioning_uri(self, account_name, issuer="Secure File Sharing"):
        """
        Generate a URI for provisioning the TOTP to an authenticator app
        
        Parameters:
        - account_name: Name of the account
        - issuer: Name of the issuer (default: "Secure File Sharing")
        
        Returns:
        - otpauth URI
        """
        import urllib.parse
        
        # Ensure the account name and issuer are properly encoded
        account_name = urllib.parse.quote(account_name)
        issuer = urllib.parse.quote(issuer)
        
        # Build the URI according to the Key Uri Format
        uri = (f"otpauth://totp/{issuer}:{account_name}?"
               f"secret={self.secret}&"
               f"issuer={issuer}&"
               f"algorithm={self.algorithm.upper()}&"
               f"digits={self.digits}&"
               f"period={self.period}")
        
        return uri

# Example usage:
if __name__ == "__main__":
    # Generate a new secret
    totp = TOTP()
    print(f"Secret: {totp.secret}")
    
    # Generate a code
    code = totp.now()
    print(f"Current code: {code}")
    
    # Verify the code
    is_valid = totp.verify(code)
    print(f"Code valid: {is_valid}")
    
    # Generate a URI for provisioning
    uri = totp.provisioning_uri("test@example.com")
    print(f"Provisioning URI: {uri}")