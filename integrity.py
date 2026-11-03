import hashlib

CHUNK_SIZE = 64 * 1024


def new_hasher():
    return hashlib.sha256()


def sha256_file(path):
    """Hash a file in chunks so large files never sit fully in memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()