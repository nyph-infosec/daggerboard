import hashlib


class FileHasher:
    @staticmethod
    def calculate_hash(target_file):
        """Calculates and returns the SHA-1 hash of a file"""
        BUFFER_SIZE = 65536
        sha1_hasher = hashlib.sha1()
        with open(target_file, "rb") as file_to_hash:
            data_chunk = file_to_hash.read(BUFFER_SIZE)
            while len(data_chunk) > 0:
                sha1_hasher.update(data_chunk)
                data_chunk = file_to_hash.read(BUFFER_SIZE)
        return sha1_hasher.hexdigest()
