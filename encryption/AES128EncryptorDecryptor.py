from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

class AES128EncryptorDecryptor:
    def __init__(self, key,iv):
        self.iv = iv
        self.key = key

    def encrypt(self, plaintext):
        # Generate a random IV (Initialization Vector)
        self.iv = os.urandom(16)

        # Create an AES cipher object with CBC mode and the provided key
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())

        # Create an encryptor object
        encryptor = cipher.encryptor()

        # Apply PKCS7 padding to the plaintext
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Return the IV and ciphertext
        return self.iv + ciphertext

    def decrypt(self, ciphertext, iv):
        # Create an AES cipher object with CBC mode and the provided key
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())

        # Create a decryptor object
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding from the decrypted plaintext
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # Return the plaintext
        return plaintext
