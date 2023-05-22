import time
import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from auth.DSSEncryptorDecryptor import DSSEncryptorDecryptor
from auth.RSAEncryptorDecryptor import RSAEncryptorDecryptor


class User:
    def __init__(self, user_id, name, email=None, algorithm=None, key_size=1024, password=None):
        self.password_hash = self.generate_password_hash(password)
        self.timestamp = time.time()
        self.user_id = user_id
        self.name=name
        self.email=email
        self.algorithm=algorithm
        self.authService  = self.generate_key_pair(algorithm,key_size)
        self.key_id = self.generate_key_id(self.public_key)

    def generate_password_hash(self, password):
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode(), salt)
        return password_hash

    def verify_password(self, entered_password):
        entered_password_hash = bcrypt.hashpw(entered_password.encode(), self.password_hash)
        return bcrypt.checkpw(entered_password.encode(), entered_password_hash)

    def generate_key_pair(self,algorithm, key_size):
        if algorithm=='rsa':
            return RSAEncryptorDecryptor(key_size)
        elif algorithm=='dsa':
            return DSSEncryptorDecryptor(key_size)



    @staticmethod
    def generate_key_id(public_key):
        # Generate a key ID using the hash of the public key
        key_id = hash(public_key) & 0xffffffffffffffff
        return key_id

