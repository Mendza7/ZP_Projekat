import pickle
import time

import bcrypt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from auth.ElGamal import ElGamalDSA
from auth.utils import sha1_hash, custom_private_key_header_footer, custom_public_key_header_footer, \
    format_password_for_encryption
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
            self.key_id = User.generate_key_id(public_key,'rsa')
        elif algorithm =='elgamal':
            self.elGamal:ElGamalDSA = ElGamalDSA(key_size)
            self.key_id = User.generate_key_id(int(self.elGamal.elGamalPublic.y),'elgamal')

        self.timestamp = time.time()
        self.name = name
        self.email = email
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

    def set_public_rsa_key(self, public_key):
        self.auth_pub = public_key
        self.key_id = User.generate_key_id(public_key,'rsa')

    def set_private_rsa_key(self, private_key: RSAPrivateKey):
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



    def export_rsa_private_key_to_pem(self):
        decode = self.auth_priv.private_bytes(encoding=serialization.Encoding.PEM,
                                              format=serialization.PrivateFormat.PKCS8,
                                              encryption_algorithm=serialization.BestAvailableEncryption(password=format_password_for_encryption(self.priv_pass.decode()))).decode()
        return custom_private_key_header_footer(decode,'RSA')

    def export_rsa_public_key_to_pem(self):
        decode = self.auth_pub.public_bytes(encoding=serialization.Encoding.PEM,
                                              format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return custom_public_key_header_footer(decode, 'RSA')

    def export_multiple_keys_to_pem(self, filepath='combined_keys.pem'):
        combined_pem = self.export_rsa_private_key_to_pem()+self.export_rsa_public_key_to_pem()
        with open('%s' % filepath, 'w') as f:
            f.write(combined_pem)

    def import_rsa_key_from_pem(self,pem_file_path):
        with open(pem_file_path, 'r') as f:
            pem_data = f.read()
        rsa_private_key_pem = pem_data.split('-----BEGIN RSA PRIVATE KEY-----')[1].split('-----END RSA PRIVATE KEY-----')[
            0].strip()
        rsa_public_key_pem = pem_data.split('-----BEGIN RSA PUBLIC KEY-----')[1].split('-----END RSA PUBLIC KEY-----')[
            0].strip()
        rsa_private_key,rsa_public_key = None,None
        if len(rsa_private_key_pem):
            rsa_private_key = self.load_rsa_private_key(rsa_private_key_pem)
        if len(rsa_public_key_pem):
            rsa_public_key = self.load_rsa_public_key(rsa_public_key_pem)

        return [rsa_private_key,rsa_public_key]
    @staticmethod
    def generate_key_id(public_key, alg=None):
        mask = (1 << 64) - 1
        if alg == 'rsa':
            if public_key is not None:
                modulus = public_key.public_numbers().n


                least_significant_64_bits = modulus & mask
                print(least_significant_64_bits)
                return least_significant_64_bits
        else:
            least_significant_64_bits = public_key & mask
            print(least_significant_64_bits)
            return least_significant_64_bits

    def sign_message(self, message):
        signature = {}
        timestamp = time.time()
        key_id = self.key_id

        if self.auth_alg == 'rsa':
            enc_hash = self.auth_priv.sign(
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA1()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA1()
            )


        else:
            enc_hash = pickle.dumps(self.elGamal.sign(message.encode('utf-8')))

        signature = {
            "timestamp": timestamp,
            "key_id": key_id,
            "encrypted_hash": bin2hex(enc_hash)
        }
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
            return self.elGamal.verify(pickle.loads(hex2bin(enc_hash)),message_bytes)

    def encrypt_public(self, message):
        if self.auth_alg == 'rsa':
            return self.auth_pub.encrypt(message.encode("utf-8"),
                                         padding.OAEP(
                                             mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                             algorithm=hashes.SHA256(),
                                             label=None
                                         ))
        else:
            return pickle.dumps(self.elGamal.encrypt_public(message.encode('utf-8')))

    def decrypt_private(self, cypher):
        if self.auth_alg=='rsa':
            return self.auth_priv.decrypt(
                cypher,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode('utf-8')
        else:
            return self.elGamal.decrypt_private(pickle.loads(cypher))

    def load_rsa_public_key(self, rsa_public_key_pem):
        rsa_public_key = serialization.load_pem_public_key(
            ("-----BEGIN PUBLIC KEY-----\n" + rsa_public_key_pem + "\n-----END PUBLIC KEY-----").encode(),
            backend=default_backend()
        )
        return rsa_public_key

    def load_rsa_private_key(self, rsa_private_key_pem):
        rsa_private_key = serialization.load_pem_private_key(
            ("-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + rsa_private_key_pem + "\n-----END ENCRYPTED PRIVATE KEY-----").encode(),
            password=format_password_for_encryption(self.priv_pass.decode()),
            backend=default_backend()
        )
        return rsa_private_key


if __name__ == '__main__':
    user = User('merisa', 'm@gmail.com', 'rsa')
    message = "Hello, World!"
    sign_message = user.sign_message(message)
    user.export_multiple_keys_to_pem('test.pem')
    pem = user.import_rsa_key_from_pem('test.pem')
    user.set_public_rsa_key(pem[1])
    user.set_private_rsa_key(pem[0])
    print(user.verify(message=message,enc_hash=sign_message['encrypted_hash'],alg='rsa'))
    print(user)