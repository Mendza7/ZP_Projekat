import binascii
import random
from binascii import hexlify, unhexlify

from Crypto.Util.number import inverse
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.dsa import *
from Crypto.PublicKey.ElGamal import generate
import secrets

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
    def __init__(self,keySize):
        self.keySize = keySize

        self.DSAPrivate = generate_private_key(keySize)
        self.elGamalPrivate =generate(162, secrets.token_bytes)

        self.DSAPublic = self.DSAPrivate.public_key()
        self.elGamalPublic = self.elGamalPrivate.publickey()

        self.h = pow(self.elGamalPrivate.g,self.elGamalPrivate.x,self.elGamalPrivate.p)

    def sign(self,message):
        return self.encrypt(self.DSAPrivate.sign(message,hashes.SHA1()),int(self.elGamalPrivate.p),int(self.elGamalPrivate.g),int(self.elGamalPrivate.y))

    def verify(self,signature:list,message:bytes):
        try:
            decrypted_signature = self.decrypt(signature,int(self.elGamalPrivate.p),int(self.elGamalPrivate.g),int(self.elGamalPrivate.x),int(self.elGamalPrivate.y))
            self.DSAPrivate.public_key().verify(decrypted_signature,message,hashes.SHA1())
            return True
        except InvalidSignature:
            return False




    def encrypt(self,message:bytes,p,g,y):
       return [self._encrypt(ord(i),p,g,y) for i in bin2hex(message)]

    def encrypt_public(self,message:bytes):
        return self.encrypt(message, int(self.elGamalPrivate.p),
                            int(self.elGamalPrivate.g), int(self.elGamalPrivate.y))

    def decrypt(self, cypher,p,g,x,y):
        return hex2bin("".join([chr(self._decrypt(i,p,g,x,y)) for i in cypher]))

    def _encrypt(self,message:int, p,g,y,key=None)->tuple:
        # p = int(self.elGamalPrivate.p)
        if key is None:
            key = random.randint(1, p - 2)

        # g = int(self.elGamalPrivate.g)
        a = pow(g, key, p)
        # y = int(self.elGamalPrivate.y)
        b = (message * pow(y, key, p)) % p
        return (a,b)

    def _decrypt(self, tup:tuple,p,g,x,y):
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
        return self.decrypt(cypher, int(self.elGamalPrivate.p), int(self.elGamalPrivate.g),
                                           int(self.elGamalPrivate.x), int(self.elGamalPrivate.y))


def int_to_bytes(num, chunk_size_bits=31):
    # Convert chunk size to bytes
    chunk_size_bytes = (chunk_size_bits+7) // 8

    # Convert number into chunks
    chunks = []
    while num:
        chunks.append(num & ((1 << chunk_size_bits) - 1))
        num = num >> chunk_size_bits

    # Convert each chunk into bytes
    bytes_arr = bytearray()
    for chunk in reversed(chunks):
        bytes_arr += chunk.to_bytes(chunk_size_bytes, 'big')

    return bytes(bytes_arr)

if __name__ == '__main__':
    lgma=ElGamalDSA(1024)
    message = 'Proba proba proba proba'
    sign = lgma.sign(message.encode('utf-8'))

    verified = lgma.verify(sign,message.encode('utf-8'))
    print(verified)