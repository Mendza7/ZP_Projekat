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
    key = b'0123456789abcdef'  # 16-byte key
    iv = b'1234567890abcdef'  # 16-byte IV

    # Create an instance of AES128EncryptorDecryptor
    encryptor_decryptor = AES128EncryptorDecryptor(key, iv)

    # Encrypt a plaintext
    plaintext = b'This is the message to be encrypted.asdasdasdasd'
    ciphertext = encryptor_decryptor.encrypt(plaintext)

    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext)

    # Decrypt the ciphertext
    decrypted_plaintext = AES128EncryptorDecryptor.decrypt(ciphertext[16:], ciphertext[:16], key)

    print("Decrypted plaintext:", decrypted_plaintext)