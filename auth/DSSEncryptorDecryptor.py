from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


class DSSEncryptorDecryptor:
    def __init__(self, key_size=1024):
        # Generate DSA key pair
        self.private_key = dsa.generate_private_key(
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        # Serialize and return the public key
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, message):
        # Sign the message using the private key
        signature = self.private_key.sign(
            message,
            hashes.SHA256()
        )
        return signature

    def verify(self, message, signature, public_key):
        # Load the provided public key
        loaded_public_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )

        # Verify the signature using the loaded public key
        try:
            loaded_public_key.verify(
                signature,
                message,
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256()
            )
            return True
        except Exception:
            return False
