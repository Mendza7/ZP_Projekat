import os
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class CAST5EncryptorDecryptor:
    @staticmethod
    def encrypt(plaintext, iv, key):

        # Create a CAST5 cipher object with CBC mode and the provided key
        cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv), backend=default_backend())

        # Create an encryptor object
        encryptor = cipher.encryptor()

        # Apply PKCS7 padding to the plaintext
        padder = padding.PKCS7(algorithms.CAST5.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Return the IV and ciphertext
        return ciphertext

    @staticmethod
    def generate_iv_and_key():
        # Generate a random IV (Initialization Vector)
        iv = secrets.token_bytes(64 // 8)
        key = secrets.token_bytes(128 // 8)
        return iv, key

    @staticmethod
    def decrypt(ciphertext, iv, key):
        # Create a CAST5 cipher object with CBC mode and the provided key
        cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv), backend=default_backend())

        # Create a decryptor object
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding from the decrypted plaintext
        unpadder = padding.PKCS7(algorithms.CAST5.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Return the plaintext
        return plaintext
