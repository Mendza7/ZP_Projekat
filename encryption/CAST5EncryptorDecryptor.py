import os
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class CAST5EncryptorDecryptor:
    @staticmethod
    def encrypt(plaintext, iv, key):

        cipher = Cipher(algorithms.CAST5(key[:16]), modes.CBC(iv[:8]), backend=default_backend())
        plaintext = plaintext.encode('utf-8')
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.CAST5.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return ciphertext

    @staticmethod
    def generate_iv_and_key():
        iv = secrets.token_bytes(64 // 8)
        key = secrets.token_bytes(128 // 8)
        return key, iv

    @staticmethod
    def decrypt(ciphertext, iv, key):
        cipher = Cipher(algorithms.CAST5(key[:16]), modes.CBC(iv[:8]), backend=default_backend())

        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.CAST5.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext

def main():
    # Create an instance of the CAST5EncryptorDecryptor class
    cast5 = CAST5EncryptorDecryptor()

    # Generate a new key and IV
    key, iv = cast5.generate_iv_and_key()

    # The plaintext we want to encrypt
    plaintext = "This is some text we need to encrypt"

    print(f"Original plaintext: {plaintext}")

    # Encrypt the plaintext
    ciphertext = cast5.encrypt(plaintext, iv, key)

    print(f"Ciphertext: {ciphertext}")

    # Decrypt the ciphertext
    decrypted_plaintext = cast5.decrypt(ciphertext, iv, key)

    print(f"Decrypted plaintext: {decrypted_plaintext.decode('utf-8')}")


if __name__ == "__main__":
    main()
