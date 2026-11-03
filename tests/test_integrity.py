import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import socket
import protocol as p
from integrity import sha256_file

SRC = os.path.join("test_data", "tiny_1KB.bin")
HOST, PORT = "127.0.0.1", 5001


def send_raw(name, payload, claimed_digest):
    """Send a header with claimed_digest, but whatever payload we like."""
    with socket.create_connection((HOST, PORT)) as s:
        p.send_request_header(s, name, len(payload), claimed_digest)
        s.sendall(payload)
        return p.read_response(s)


original = open(SRC, "rb").read()
good_digest = sha256_file(SRC)

# Flip a single bit in the middle of the data
corrupted = bytearray(original)
corrupted[500] ^= 0x01
corrupted = bytes(corrupted)

print("Original  sha256:", good_digest)
import hashlib
print("Corrupted sha256:", hashlib.sha256(corrupted).hexdigest())

status, text = send_raw("corrupted.bin", corrupted, good_digest)
print("Corrupted file ->", "REJECTED" if status == p.STATUS_BAD_HASH else "ACCEPTED (bad!)", f"({text})")

status, text = send_raw("clean.bin", original, good_digest)
print("Clean file     ->", "VERIFIED" if status == p.STATUS_OK else "FAILED", f"({text})")