import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

class AES128EncryptorDecryptor:
    @staticmethod
    def encrypt(plaintext,iv,key):
        # Create an AES cipher object with CBC mode and the provided key
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        plaintext = plaintext.encode('utf-8')
        # Create an encryptor object
        encryptor = cipher.encryptor()

        # Apply PKCS7 padding to the plaintext
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Return the IV and ciphertext
        return ciphertext

    @staticmethod
    def generate_iv_and_key():
        iv = secrets.token_bytes(128 // 8)
        key = secrets.token_bytes(128 // 8)
        return iv, key

    @staticmethod
    def decrypt(ciphertext, iv, key):
        # Create an AES cipher object with CBC mode and the provided key
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        # Create a decryptor object
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding from the decrypted plaintext
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Return the plaintext
        return plaintext


if __name__=='__main__':
    # Example usage
    iv,key = AES128EncryptorDecryptor.generate_iv_and_key()

    # Create an instance of AES128EncryptorDecryptor

    # Encrypt a plaintext
    plaintext = 'This is the message to be encrypted.asdasdasdasd'
    ciphertext = AES128EncryptorDecryptor.encrypt(plaintext,key,iv)

    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext)

    # Decrypt the ciphertext
    decrypted_plaintext = AES128EncryptorDecryptor.decrypt(ciphertext,key,iv)

    print("Decrypted plaintext:", decrypted_plaintext)