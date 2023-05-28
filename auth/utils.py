from cryptography.hazmat.primitives import hashes


def sha1_hash(message):
    # Create an SHA-1 hash object
    sha1_hasher = hashes.Hash(hashes.SHA1())

    # Convert the message to bytes if needed
    if isinstance(message, str):
        message = message.encode()

    # Update the hash object with the message
    sha1_hasher.update(message)

    # Calculate the hash digest
    hash_code = sha1_hasher.finalize()

    # Return the hash code
    return hash_code