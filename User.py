import time

import bcrypt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from auth.utils import sha1_hash
from compression.utils import bin2hex, hex2bin


class User:
    def __init__(self, name=None, email=None, algorithm=None, key_size=1024, password=''):
        private_key = None
        public_key = None
        if algorithm == 'rsa':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
            )

            public_key = private_key.public_key()
        self.timestamp = time.time()
        self.name = name
        self.email = email
        self.key_id = User.generate_key_id(public_key)
        self.auth_key_size = key_size
        self.auth_alg = algorithm
        self.auth_pub = public_key
        self.auth_priv = private_key
        self.priv_pass = self.generate_password_hash(password)

    def get_public_key(self):
        return self.auth_pub

    def get_private_key(self, password):
        if self.verify_password(entered_password=password):
            return self.auth_priv
        return None

    def set_public_key(self, public_key):
        self.auth_pub = public_key
        self.key_id = User.generate_key_id(public_key)

    def set_private_key(self, private_key: RSAPrivateKey):
        self.auth_priv = private_key
        self.auth_key_size = private_key.key_size

    def __repr__(self):
        return f"{self.name},{self.email} : {self.auth_alg} {self.auth_pub} {self.auth_priv}"

    def generate_password_hash(self, password):
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode(), salt)
        return password_hash

    def verify_password(self, entered_password):
        return bcrypt.checkpw(entered_password.encode(), self.priv_pass)

    @staticmethod
    def generate_key_id(public_key):
        if public_key is not None:
            modulus = public_key.public_numbers().n

            # Mask to get the least significant 64 bits
            mask = (1 << 64) - 1

            # Extract the least significant 64 bits by performing bitwise AND with the mask
            least_significant_64_bits = modulus & mask
            print(least_significant_64_bits)
            return least_significant_64_bits

    def sign_message(self, message):
        signature = {}
        timestamp = time.time()
        key_id = self.key_id

        if self.auth_alg == 'rsa':
            # hash_value = hashes.Hash(hashes.SHA1())
            # hash_value.update(message.encode('utf-8'))
            enc_hash = self.auth_priv.sign(
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA1()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA1()
            )
            signature = {
                "timestamp": timestamp,
                "key_id": key_id,
                "encrypted_hash": bin2hex(enc_hash)
            }

        else:
            pass
        return signature

    def verify(self, message, enc_hash, alg):

        message_bytes = message.encode('utf-8')
        if alg == 'rsa':
            try:
                self.auth_pub.verify(hex2bin(enc_hash), message_bytes,
                                     padding.PSS(
                                     mgf=padding.MGF1(hashes.SHA1()),
                                     salt_length=padding.PSS.MAX_LENGTH
                                 ), hashes.SHA1())
                return True
            except InvalidSignature:
                print("Invalid Signature for user: "+self.name)
                return False
        else:
            #TODO: El Gamal
            return False


    def encrypt_public(self, message):
        return self.auth_pub.encrypt(message.encode("utf-8"),
                                     padding.OAEP(
                                         mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                         algorithm=hashes.SHA256(),
                                         label=None
                                     ))

    def decrypt_private(self, cypher):
        return self.auth_priv.decrypt(
            cypher,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode('utf-8')

if __name__ == '__main__':

    user = User('merisa', 'm@gmail.com', 'rsa')
    message = "Hello, World!"

    # Sign the message
    signature = user.sign_message(message)

    # Extract the necessary information from the signature
    timestamp = signature["timestamp"]
    key_id = signature["key_id"]
    enc_hash = signature["encrypted_hash"]

    # Verify the signature
    verification_result = user.verify(message, enc_hash, 'rsa')

    # Print the verification result
    if verification_result:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")
