import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
    cast5 = CAST5EncryptorDecryptor()

    key, iv = cast5.generate_iv_and_key()

    plaintext = "This is some text we need to encrypt"

    print(f"Original plaintext: {plaintext}")

    ciphertext = cast5.encrypt(plaintext, iv, key)

    print(f"Ciphertext: {ciphertext}")

    decrypted_plaintext = cast5.decrypt(ciphertext, iv, key)

    print(f"Decrypted plaintext: {decrypted_plaintext.decode('utf-8')}")


if __name__ == "__main__":
    main()
