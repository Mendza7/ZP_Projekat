import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class CAST5EncryptorDecryptor:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        # Generate a random IV (Initialization Vector)
        iv = os.urandom(8)

        # Create a CAST5 cipher object with CBC mode and the provided key
        cipher = Cipher(algorithms.CAST5(self.key), modes.CBC(iv), backend=default_backend())

        # Create an encryptor object
        encryptor = cipher.encryptor()

        # Apply PKCS7 padding to the plaintext
        padder = padding.PKCS7(algorithms.CAST5.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Return the IV and ciphertext
        return iv + ciphertext

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
