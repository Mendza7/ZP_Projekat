import time


class User:
    def __init__(self, user_id, public_key, private_key):
        self.timestamp = time.time()
        self.user_id = user_id
        self.public_key = public_key
        self.private_key = private_key
        self.key_id = self.generate_key_id(public_key)

    def generate_key_id(self, public_key):
        return hash(public_key) & 0xffffffffffffffff
