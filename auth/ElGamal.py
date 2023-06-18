import base64
import pickle
import random
import secrets

import bcrypt
from Crypto.PublicKey import ElGamal
from Crypto.PublicKey.ElGamal import generate
from Crypto.Util.number import inverse
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.dsa import *

from auth.utils import int_to_bytes, bytes_to_int, custom_private_key_header_footer, custom_public_key_header_footer, \
    format_password_for_encryption
from compression.utils import bin2hex, hex2bin


class ElGamalDSA():

    @property
    def DSAPrivate(self):
        return self._DSAPrivate

    @DSAPrivate.setter
    def DSAPrivate(self, value):
        self._DSAPrivate = value

    @property
    def elGamalPrivate(self):
        return self._elGamalPrivate

    @elGamalPrivate.setter
    def elGamalPrivate(self, value):
        self._elGamalPrivate = value

    @property
    def DSAPublic(self):
        return self._DSAPublic

    @DSAPublic.setter
    def DSAPublic(self, value):
        self._DSAPublic = value

    @property
    def elGamalPublic(self):
        return self._elGamalPublic

    @elGamalPublic.setter
    def elGamalPublic(self, value):
        self._elGamalPublic = value

    def __init__(self, keySize=None, DSAPrivate: DSAPrivateKey = None, elGamalPrivate: ElGamal = None,
                 DSAPublic: DSAPublicKey = None, elGamalPublic: ElGamal = None):
        if keySize is not None:
            self.keySize = keySize
            self._DSAPrivate = generate_private_key(keySize)
            self._elGamalPrivate = generate(162, secrets.token_bytes)
            self._DSAPublic = self._DSAPrivate.public_key()
            self._elGamalPublic = self._elGamalPrivate.publickey()
            self._h = pow(self._elGamalPrivate.g, self._elGamalPrivate.x, self._elGamalPrivate.p)
        elif keySize is None:
            self.keySize = DSAPrivate.key_size
            self._DSAPrivate = DSAPrivate
            self._elGamalPrivate = elGamalPrivate
            self._DSAPublic = DSAPublic
            self._elGamalPublic = elGamalPublic
            self._h = pow(self._elGamalPrivate.g, self._elGamalPrivate.x, self._elGamalPrivate.p)
        else:
            raise ValueError("Invalid arguments")

    def sign(self, message):
        message1 = self.DSAPrivate.sign(message, hashes.SHA1())
        p = int(self._elGamalPrivate.p)
        g = int(self._elGamalPrivate.g)
        y = int(self._elGamalPrivate.y)
        return [self._encrypt(ord(i), p, g, y) for i in bin2hex(message1)]

    def verify(self, signature: list, message: bytes):
        try:
            p = int(self._elGamalPrivate.p)
            g = int(self._elGamalPrivate.g)
            x = int(self._elGamalPrivate.x)
            y = int(self._elGamalPrivate.y)
            decrypted_signature = hex2bin("".join([chr(self._decrypt(i, p, g, x, y)) for i in signature]))
            self.DSAPrivate.public_key().verify(decrypted_signature, message, hashes.SHA1())
            return True
        except InvalidSignature:
            return False

    def encrypt_public(self, message: bytes):
        p = int(self._elGamalPrivate.p)
        g = int(self._elGamalPrivate.g)
        y = int(self._elGamalPrivate.y)
        return [self._encrypt(ord(i), p, g, y) for i in bin2hex(message)]

    def _encrypt(self, message: int, p, g, y, key=None) -> tuple:
        if key is None:
            key = random.randint(1, p - 2)

        a = pow(g, key, p)
        b = (message * pow(y, key, p)) % p
        return (a, b)

    def _decrypt(self, tup: tuple, p, g, x, y):
        r = random.randrange(2, p - 1)
        a_blind = (tup[0] * pow(g, r, p)) % p
        ax = pow(a_blind, x, p)

        plaintext_blind = (tup[1] * inverse(ax, p)) % p

        # y = int(self._elGamalPrivate.y)
        plaintext = (plaintext_blind * pow(y, r, p)) % p
        return plaintext

    def decrypt_private(self, cypher):
        p = int(self._elGamalPrivate.p)
        g = int(self._elGamalPrivate.g)
        x = int(self._elGamalPrivate.x)
        y = int(self._elGamalPrivate.y)
        return hex2bin("".join([chr(self._decrypt(i, p, g, x, y)) for i in cypher]))

    def export_elgamal_private_key_to_pem(self):
        key_data = [int_to_bytes(int(self._elGamalPrivate.p)),
                    int_to_bytes(int(self._elGamalPrivate.g)),
                    int_to_bytes(int(self._elGamalPrivate.y)),
                    int_to_bytes(int(self._elGamalPrivate.x))]
        header = "-----BEGIN ELGAMAL PRIVATE KEY-----\n"
        footer = "\n-----END ELGAMAL PRIVATE KEY-----\n"

        key_data_b64 = base64.b64encode(pickle.dumps(key_data)).decode()

        # wrap base64 data to 64 characters per line as per PEM format
        key_data_b64_wrapped = "\n".join(key_data_b64[i:i + 64] for i in range(0, len(key_data_b64), 64))

        pem = header + key_data_b64_wrapped + footer

        return pem

    def export_elgamal_public_key_to_pem(self):

        key_data = [int_to_bytes(int(self._elGamalPublic.p)),
                    int_to_bytes(int(self._elGamalPublic.g)),
                    int_to_bytes(int(self._elGamalPublic.y))]
        header = "-----BEGIN ELGAMAL PUBLIC KEY-----\n"
        footer = "\n-----END ELGAMAL PUBLIC KEY-----\n"

        key_data_b64 = base64.b64encode(pickle.dumps(key_data)).decode()

        # wrap base64 data to 64 characters per line as per PEM format
        key_data_b64_wrapped = "\n".join(key_data_b64[i:i + 64] for i in range(0, len(key_data_b64), 64))

        pem = header + key_data_b64_wrapped + footer

        return pem

    def __repr__(self):
        if (self._elGamalPrivate.x is not None):
            return (
                f"p:{int(self._elGamalPublic.p)}\n g:{int(self._elGamalPublic.g)}\ny:{int(self._elGamalPublic.y)}\n x:{int(self._elGamalPrivate.x)}")
        return (f"p:{int(self._elGamalPublic.p)}\n g:{int(self._elGamalPublic.g)}\ny:{int(self._elGamalPublic.y)}")

    def export_multiple_keys_to_pem(self, filepath='combined_keys.pem', password=b'123'):

        dsa_private_key_pem = self.export_dsa_private_to_pem(password=password)

        dsa_public_key_pem = self.export_dsa_public_to_pem()

        elgamal_private_key_pem = self.export_elgamal_private_key_to_pem()
        elgamal_public_key_pem = self.export_elgamal_public_key_to_pem()

        combined_pem = dsa_private_key_pem + dsa_public_key_pem + elgamal_private_key_pem + elgamal_public_key_pem

        with open('%s' % filepath, 'w') as f:
            f.write(combined_pem)

    def export_dsa_public_to_pem(self):
        dsa_public_key_pem = self._DSAPublic.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        dsa_public_key_pem = custom_public_key_header_footer(dsa_public_key_pem, 'DSA')
        return dsa_public_key_pem

    def export_dsa_private_to_pem(self,password):
        dsa_private_key_pem = self.DSAPrivate.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(format_password_for_encryption(password))
        ).decode()
        dsa_private_key_pem = custom_private_key_header_footer(dsa_private_key_pem, 'DSA')
        return dsa_private_key_pem

    @staticmethod
    def import_elgamal_key(pem_data):
        key_data = pickle.loads(base64.b64decode(pem_data))

        key_data = [bytes_to_int(data) for data in key_data]

        if len(key_data) == 4:  # private key
            key = ElGamal.construct(tuple(key_data))
        elif len(key_data) == 3:  # public key
            key = ElGamal.construct(tuple(key_data))

        return key

    def import_keys_from_pem(pem_file_path:str,password):
        with open(pem_file_path, 'r') as f:
            pem_data = f.read()
        dsa_private_key, elgamal_private_key, dsa_public_key, elgamal_public_key = None,None,None,None
        dsa_private_key_pem,dsa_public_key_pem,elgamal_private_key_pem,elgamal_public_key_pem = None,None,None,None
        try:
            dsa_private_key_pem = pem_data.split('-----BEGIN DSA PRIVATE KEY-----')[1].split('-----END DSA PRIVATE KEY-----')[
                0].strip()
        except:
            pass
        try:
            dsa_public_key_pem = pem_data.split('-----BEGIN DSA PUBLIC KEY-----')[1].split('-----END DSA PUBLIC KEY-----')[
                0].strip()
        except:
            pass
        try:
            elgamal_private_key_pem = \
                pem_data.split('-----BEGIN ELGAMAL PRIVATE KEY-----')[1].split('-----END ELGAMAL PRIVATE KEY-----')[
                    0].strip()
        except:
            pass
        try:
            elgamal_public_key_pem = \
                pem_data.split('-----BEGIN ELGAMAL PUBLIC KEY-----')[1].split('-----END ELGAMAL PUBLIC KEY-----')[0].strip()
        except:
            pass
        if dsa_private_key_pem is not None:
            dsa_private_key = ElGamalDSA.load_dsa_private_key(dsa_private_key_pem,password)
        if dsa_public_key_pem is not None:
            dsa_public_key = ElGamalDSA.load_dsa_public_key(dsa_public_key_pem)

        if elgamal_private_key_pem is not None:
            elgamal_private_key = ElGamalDSA.import_elgamal_key(elgamal_private_key_pem)
        if elgamal_public_key_pem is not None:
            elgamal_public_key = ElGamalDSA.import_elgamal_key(elgamal_public_key_pem)

        return [None,dsa_private_key,elgamal_private_key, dsa_public_key , elgamal_public_key]
    @staticmethod
    def load_dsa_public_key(dsa_public_key_pem):
        dsa_public_key = serialization.load_pem_public_key(
            ("-----BEGIN PUBLIC KEY-----\n" + dsa_public_key_pem + "\n-----END PUBLIC KEY-----").encode(),
            backend=default_backend()
        )
        return dsa_public_key
    @staticmethod
    def load_dsa_private_key(dsa_private_key_pem,password):
        dsa_private_key = serialization.load_pem_private_key(
            ("-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + dsa_private_key_pem + "\n-----END ENCRYPTED PRIVATE KEY-----").encode(),
            password=format_password_for_encryption(password),
            backend=default_backend()
        )
        return dsa_private_key


if __name__ == '__main__':
    password = '123'
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode(), salt)

    lgma = ElGamalDSA(1024)
    message = 'Proba proba proba proba'
    sign = lgma.sign(message.encode('utf-8'))
    lgma.export_multiple_keys_to_pem(filepath='test.pem',password=password_hash.decode())
    pem = ElGamalDSA.import_keys_from_pem(pem_file_path='test.pem',password=password_hash.decode())
    el_gamal_dsa = ElGamalDSA(*(pem))
    verified = el_gamal_dsa.verify(sign, message.encode('utf-8'))
    print(verified)
