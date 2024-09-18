from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class CryptoHandler:
    def __init__(self, password):
        self.symmetric_key = self.generate_key(password)
        self.fernet = Fernet(self.symmetric_key)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def generate_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'static_salt',  # In production, use a random salt and store it
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_message(self, message):
        return self.fernet.encrypt(message.encode())

    def decrypt_message(self, encrypted_message):
        try:
            print(f"Attempting to decrypt message of length: {len(encrypted_message)}")
            decrypted = self.fernet.decrypt(encrypted_message)
            print("Decryption successful")
            return decrypted.decode()
        except Exception as e:
            print(f"Decryption failed: {e}")
            print(f"Encrypted message (first 100 chars): {encrypted_message[:100]}")
            raise

    def sign_message(self, message):
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, message, signature, public_key):
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    def get_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_public_key(self, pem_data):
        return serialization.load_pem_public_key(pem_data)

