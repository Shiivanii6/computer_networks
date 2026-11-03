import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import protocol as p


def drip(sock, data):
    """Send data one byte at a time to force partial reads."""
    for i in range(len(data)):
        sock.sendall(data[i:i + 1])
        time.sleep(0.001)
    sock.close()


def run(data):
    a, b = socket.socketpair()
    threading.Thread(target=drip, args=(a, data), daemon=True).start()
    try:
        return p.read_request_header(b)
    finally:
        b.close()


def build(magic=p.MAGIC, version=p.VERSION, header=None):
    import json
    raw = json.dumps(header or {"filename": "a.bin", "file_size": 10,
                                "sha256": "0" * 64}).encode()
    return p.PREAMBLE.pack(magic, version, len(raw)) + raw


def expect_error(label, data):
    try:
        run(data)
    except p.ProtocolError as e:
        print(f"PASS  {label}: rejected ({e})")
    else:
        raise AssertionError(f"{label}: should have been rejected")


print("PASS  valid header:", run(build()))
expect_error("bad magic", build(magic=b"XXXX"))
expect_error("bad version", build(version=9))
expect_error("huge file_size", build(header={"filename": "a", "file_size": 10**12, "sha256": "0" * 64}))
expect_error("negative size", build(header={"filename": "a", "file_size": -1, "sha256": "0" * 64}))
expect_error("path traversal", build(header={"filename": "..\\x.bin", "file_size": 1, "sha256": "0" * 64}))
expect_error("bad digest", build(header={"filename": "a", "file_size": 1, "sha256": "xyz"}))
expect_error("truncated header", build()[:15])
print("All tests passed.")