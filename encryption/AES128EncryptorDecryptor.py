import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

class AES128EncryptorDecryptor:
    @staticmethod
    def encrypt(plaintext,iv,key):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        plaintext = plaintext.encode('utf-8')
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return ciphertext

    @staticmethod
    def generate_iv_and_key():
        iv = secrets.token_bytes(128 // 8)
        key = secrets.token_bytes(128 // 8)
        return key, iv

    @staticmethod
    def decrypt(ciphertext, iv, key):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return unpadded_plaintext


if __name__=='__main__':
    iv,key = AES128EncryptorDecryptor.generate_iv_and_key()


    plaintext = 'This is the message to be encrypted.asdasdasdasd'
    ciphertext = AES128EncryptorDecryptor.encrypt(plaintext,iv,key)

    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext)

    decrypted_plaintext = AES128EncryptorDecryptor.decrypt(ciphertext,iv,key)

    print("Decrypted plaintext:", decrypted_plaintext)