import hashlib
import os
import random

OUT_DIR = "test_data"
CHUNK = 64 * 1024  # 64 KB

FILES = {
    "empty.bin": 0,                  # edge case: zero bytes
    "tiny_1KB.bin": 1024,
    "small_100KB.bin": 100 * 1024,
    "medium_5MB.bin": 5 * 1024 * 1024,
    "large_50MB.bin": 50 * 1024 * 1024,
}


def write_file(path, size, seed):
    rng = random.Random(seed)        # same seed -> same bytes every run
    remaining = size
    with open(path, "wb") as f:      # "wb" = write binary
        while remaining > 0:
            n = min(CHUNK, remaining)
            f.write(rng.randbytes(n))
            remaining -= n


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:      # "rb" = read binary
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for i, (name, size) in enumerate(FILES.items()):
        path = os.path.join(OUT_DIR, name)
        write_file(path, size, seed=i)

        actual = os.path.getsize(path)
        assert actual == size, f"{name}: expected {size}, got {actual}"

        # Round-trip check: copy in chunks, then compare hashes
        copy_path = path + ".copy"
        with open(path, "rb") as src, open(copy_path, "wb") as dst:
            while chunk := src.read(CHUNK):
                dst.write(chunk)
        assert sha256_of(path) == sha256_of(copy_path), f"{name}: copy mismatch"
        os.remove(copy_path)

        print(f"{name:18} {actual:>12,} bytes  sha256={sha256_of(path)[:16]}...")


if __name__ == "__main__":
    main()