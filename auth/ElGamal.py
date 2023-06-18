import base64
import pickle
import random
import secrets

from Crypto.PublicKey import ElGamal
from Crypto.PublicKey.ElGamal import generate
from Crypto.Util.number import inverse
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.dsa import *

from compression.utils import bin2hex, hex2bin


# Compute the GCD
def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)


def gen_key(q):
    key = random.randint(pow(10, 20), q)
    while gcd(q, key) != 1:
        key = random.randint(pow(10, 20), q)
    return key


def power(a, b, c):
    x = 1
    y = a
    while b > 0:
        if b % 2 == 0:
            x = (x * y) % c
        y = (y * y) % c
        b = int(b / 2)
    return x % c


class ElGamalDSA():
    def __init__(self, keySize=None, DSAPrivate: DSAPrivateKey = None, elGamalPrivate: ElGamal = None,
                 DSAPublic: DSAPublicKey = None, elGamalPublic: ElGamal = None):
        if keySize is not None:
            self.keySize = keySize
            self.DSAPrivate = generate_private_key(keySize)
            self.elGamalPrivate = generate(162, secrets.token_bytes)
            self.DSAPublic = self.DSAPrivate.public_key()
            self.elGamalPublic = self.elGamalPrivate.publickey()
            self.h = pow(self.elGamalPrivate.g, self.elGamalPrivate.x, self.elGamalPrivate.p)
        elif DSAPrivate is not None and elGamalPrivate is not None and DSAPublic is not None and elGamalPublic is not None:
            self.keySize = DSAPrivate.key_size
            self.DSAPrivate = DSAPrivate
            self.elGamalPrivate = elGamalPrivate
            self.DSAPublic = DSAPublic
            self.elGamalPublic = elGamalPublic
            self.h = pow(self.elGamalPrivate.g, self.elGamalPrivate.x, self.elGamalPrivate.p)
        else:
            raise ValueError("Invalid arguments")

    def sign(self, message):
        message1 = self.DSAPrivate.sign(message, hashes.SHA1())
        p = int(self.elGamalPrivate.p)
        g = int(self.elGamalPrivate.g)
        y = int(self.elGamalPrivate.y)
        return [self._encrypt(ord(i), p, g, y) for i in bin2hex(message1)]

    def verify(self, signature: list, message: bytes):
        try:
            p = int(self.elGamalPrivate.p)
            g = int(self.elGamalPrivate.g)
            x = int(self.elGamalPrivate.x)
            y = int(self.elGamalPrivate.y)
            decrypted_signature = hex2bin("".join([chr(self._decrypt(i, p, g, x, y)) for i in signature]))
            self.DSAPrivate.public_key().verify(decrypted_signature, message, hashes.SHA1())
            return True
        except InvalidSignature:
            return False

    def encrypt_public(self, message: bytes):
        p = int(self.elGamalPrivate.p)
        g = int(self.elGamalPrivate.g)
        y = int(self.elGamalPrivate.y)
        return [self._encrypt(ord(i), p, g, y) for i in bin2hex(message)]

    def _encrypt(self, message: int, p, g, y, key=None) -> tuple:
        # p = int(self.elGamalPrivate.p)
        if key is None:
            key = random.randint(1, p - 2)

        # g = int(self.elGamalPrivate.g)
        a = pow(g, key, p)
        # y = int(self.elGamalPrivate.y)
        b = (message * pow(y, key, p)) % p
        return (a, b)

    def _decrypt(self, tup: tuple, p, g, x, y):
        # p = int(self.elGamalPrivate.p)
        r = random.randrange(2, p - 1)
        # g = int(self.elGamalPrivate.g)
        a_blind = (tup[0] * pow(g, r, p)) % p
        # x = int(self.elGamalPrivate.x)
        ax = pow(a_blind, x, p)

        plaintext_blind = (tup[1] * inverse(ax, p)) % p

        # y = int(self.elGamalPrivate.y)
        plaintext = (plaintext_blind * pow(y, r, p)) % p
        return plaintext

    def decrypt_private(self, cypher):
        p = int(self.elGamalPrivate.p)
        g = int(self.elGamalPrivate.g)
        x = int(self.elGamalPrivate.x)
        y = int(self.elGamalPrivate.y)
        return hex2bin("".join([chr(self._decrypt(i, p, g, x, y)) for i in cypher]))

    def export_elgamal_private_key_to_pem(self):
        key_data = [int_to_bytes(int(self.elGamalPrivate.p)),
                    int_to_bytes(int(self.elGamalPrivate.g)),
                    int_to_bytes(int(self.elGamalPrivate.y)),
                    int_to_bytes(int(self.elGamalPrivate.x))]
        header = "-----BEGIN ELGAMAL PRIVATE KEY-----\n"
        footer = "\n-----END ELGAMAL PRIVATE KEY-----\n"

        key_data_b64 = base64.b64encode(pickle.dumps(key_data)).decode()

        # wrap base64 data to 64 characters per line as per PEM format
        key_data_b64_wrapped = "\n".join(key_data_b64[i:i + 64] for i in range(0, len(key_data_b64), 64))

        pem = header + key_data_b64_wrapped + footer

        return pem

    def export_elgamal_public_key_to_pem(self):

        key_data = [int_to_bytes(int(self.elGamalPublic.p)),
                    int_to_bytes(int(self.elGamalPublic.g)),
                    int_to_bytes(int(self.elGamalPublic.y))]
        header = "-----BEGIN ELGAMAL PUBLIC KEY-----\n"
        footer = "\n-----END ELGAMAL PUBLIC KEY-----\n"

        key_data_b64 = base64.b64encode(pickle.dumps(key_data)).decode()

        # wrap base64 data to 64 characters per line as per PEM format
        key_data_b64_wrapped = "\n".join(key_data_b64[i:i + 64] for i in range(0, len(key_data_b64), 64))

        pem = header + key_data_b64_wrapped + footer

        return pem

    def __repr__(self):
        if (self.elGamalPrivate.x is not None):
            return (
                f"p:{int(self.elGamalPublic.p)}\n g:{int(self.elGamalPublic.g)}\ny:{int(self.elGamalPublic.y)}\n x:{int(self.elGamalPrivate.x)}")
        return (f"p:{int(self.elGamalPublic.p)}\n g:{int(self.elGamalPublic.g)}\ny:{int(self.elGamalPublic.y)}")

    def export_multiple_keys_to_pem(self, filepath='combined_keys.pem'):
        dsa_private_key_pem = self.DSAPrivate.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        dsa_public_key_pem = self.DSAPublic.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        elgamal_private_key_pem = self.export_elgamal_private_key_to_pem()
        elgamal_public_key_pem = self.export_elgamal_public_key_to_pem()

        combined_pem = dsa_private_key_pem + dsa_public_key_pem + elgamal_private_key_pem + elgamal_public_key_pem

        with open('%s' % filepath, 'w') as f:
            f.write(combined_pem)

    @staticmethod
    def import_elgamal_key(pem_data):
        # # Strip the header and footer
        # pem_data = pem_data.replace("-----BEGIN ELGAMAL PRIVATE KEY-----\n", "")
        # pem_data = pem_data.replace("\n-----END ELGAMAL PRIVATE KEY-----\n", "")
        # pem_data = pem_data.replace("-----BEGIN ELGAMAL PUBLIC KEY-----\n", "")
        # pem_data = pem_data.replace("\n-----END ELGAMAL PUBLIC KEY-----\n", "")

        # Concatenate the base64 strings and decode
        key_data = pickle.loads(base64.b64decode(pem_data))

        # Convert bytes back to ints
        key_data = [bytes_to_int(data) for data in key_data]

        # Construct key object based on the number of parts
        if len(key_data) == 4:  # private key
            key = ElGamal.construct(tuple(key_data))
        elif len(key_data) == 3:  # public key
            # key_data.append(None)  # append None for x (private component)
            key = ElGamal.construct(tuple(key_data))

        return key

    def import_keys_from_pem(pem_file_path):
        # Load PEM file
        with open(pem_file_path, 'r') as f:
            pem_data = f.read()

        # Separate keys
        dsa_private_key_pem = pem_data.split('-----BEGIN PRIVATE KEY-----')[1].split('-----END PRIVATE KEY-----')[
            0].strip()
        dsa_public_key_pem = pem_data.split('-----BEGIN PUBLIC KEY-----')[1].split('-----END PUBLIC KEY-----')[
            0].strip()
        elgamal_private_key_pem = \
            pem_data.split('-----BEGIN ELGAMAL PRIVATE KEY-----')[1].split('-----END ELGAMAL PRIVATE KEY-----')[
                0].strip()
        elgamal_public_key_pem = \
            pem_data.split('-----BEGIN ELGAMAL PUBLIC KEY-----')[1].split('-----END ELGAMAL PUBLIC KEY-----')[0].strip()

        # Load DSA keys
        dsa_private_key = ElGamalDSA.load_dsa_private_key(dsa_private_key_pem)
        dsa_public_key = ElGamalDSA.load_dsa_public_key(dsa_public_key_pem)

        # Decode ElGamal keys
        elgamal_private_key = ElGamalDSA.import_elgamal_key(elgamal_private_key_pem)
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
    def load_dsa_private_key(dsa_private_key_pem):
        dsa_private_key = serialization.load_pem_private_key(
            ("-----BEGIN PRIVATE KEY-----\n" + dsa_private_key_pem + "\n-----END PRIVATE KEY-----").encode(),
            password=None,
            backend=default_backend()
        )
        return dsa_private_key


def int_to_bytes(num, chunk_size_bits=31):
    chunk_size_bytes = (chunk_size_bits + 7) // 8

    chunks = []
    while num:
        chunks.append(num & ((1 << chunk_size_bits) - 1))
        num = num >> chunk_size_bits

    # Convert each chunk into bytes
    bytes_arr = bytearray()
    for chunk in reversed(chunks):
        bytes_arr += chunk.to_bytes(chunk_size_bytes, 'big')

    return bytes(bytes_arr)

def bytes_to_int(bytes_arr, chunk_size_bits=31):
    # Convert chunk size to bytes
    chunk_size_bytes = (chunk_size_bits + 7) // 8

    # Split the bytes array into chunks
    chunks = [bytes_arr[i:i+chunk_size_bytes] for i in range(0, len(bytes_arr), chunk_size_bytes)]

    # Convert each chunk into an integer
    num = 0
    for chunk in chunks:
        num = (num << chunk_size_bits) | int.from_bytes(chunk, 'big')

    return num

if __name__ == '__main__':
    lgma = ElGamalDSA(1024)
    message = 'Proba proba proba proba'
    sign = lgma.sign(message.encode('utf-8'))
    lgma.export_multiple_keys_to_pem(filepath='test.pem')
    pem = ElGamalDSA.import_keys_from_pem(pem_file_path='test.pem')
    el_gamal_dsa = ElGamalDSA(*(pem))
    verified = el_gamal_dsa.verify(sign, message.encode('utf-8'))
    print(verified)
