import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


class User:
    def __init__(self, name, email=None, algorithm=None, key_size=1024, password=''):
        private_key= None
        public_key=None
        if(algorithm=='rsa'):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )

            public_key = private_key.public_key()


        self.name=name
        self.email=email
        self.key_id = User.generate_key_id(public_key)
        self.auth_key_size = key_size
        self.auth_alg = algorithm
        self.auth_pub = public_key
        self.auth_priv = private_key
        self.priv_pass = self.generate_password_hash(password)


    def get_public_key(self):
        return self.auth_pub

    def get_private_key(self,password):
        if self.verify_password(entered_password=password):
            return self.auth_priv
        return None

    def set_public_key(self,public_key):
        self.auth_pub = public_key
        self.key_id = User.generate_key_id(public_key)

    def set_private_key(self,private_key: RSAPrivateKey):
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
            public_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
            print(public_bytes)
            pem_lines = public_bytes.splitlines()
            key_data = b"".join(pem_lines[1:-1])

            # Extract the smallest 64 bits from the key data
            smallest_64_bits = key_data[-8:]
            print(smallest_64_bits)
            return int.from_bytes(smallest_64_bits, byteorder='big')