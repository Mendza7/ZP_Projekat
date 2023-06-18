import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def sha1_hash(message):
    sha1_hasher = hashes.Hash(hashes.SHA1())

    if isinstance(message, str):
        message = message.encode()

    sha1_hasher.update(message)

    hash_code = sha1_hasher.finalize()

    return hash_code


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



def int_to_bytes(num, chunk_size_bits=31):
    chunk_size_bytes = (chunk_size_bits + 7) // 8

    chunks = []
    while num:
        chunks.append(num & ((1 << chunk_size_bits) - 1))
        num = num >> chunk_size_bits

    bytes_arr = bytearray()
    for chunk in reversed(chunks):
        bytes_arr += chunk.to_bytes(chunk_size_bytes, 'big')

    return bytes(bytes_arr)


def bytes_to_int(bytes_arr, chunk_size_bits=31):
    chunk_size_bytes = (chunk_size_bits + 7) // 8

    chunks = [bytes_arr[i:i+chunk_size_bytes] for i in range(0, len(bytes_arr), chunk_size_bytes)]

    num = 0
    for chunk in chunks:
        num = (num << chunk_size_bits) | int.from_bytes(chunk, 'big')

    return num


def custom_private_key_header_footer(pem_key: str, key_type: str) -> str:
    key_type = key_type.upper()

    pem_key = pem_key.replace('-----BEGIN ENCRYPTED PRIVATE KEY-----', f'-----BEGIN {key_type} PRIVATE KEY-----')
    pem_key = pem_key.replace('-----END ENCRYPTED PRIVATE KEY-----', f'-----END {key_type} PRIVATE KEY-----')

    return pem_key

def custom_public_key_header_footer(pem_key: str, key_type: str) -> str:
    key_type = key_type.upper()

    pem_key = pem_key.replace('-----BEGIN PUBLIC KEY-----', f'-----BEGIN {key_type} PUBLIC KEY-----')
    pem_key = pem_key.replace('-----END PUBLIC KEY-----', f'-----END {key_type} PUBLIC KEY-----')

    return pem_key

def format_password_for_encryption(password:bytes):
    salt = b'SomeRandomSalt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    encrypt_key = kdf.derive(password)
    return encrypt_key



