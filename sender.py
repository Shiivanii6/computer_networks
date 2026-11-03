import argparse
import os
import socket
import sys

import protocol as p
from integrity import sha256_file


def send_file(host, port, path):
    size = os.path.getsize(path)
    digest = sha256_file(path)                   # pass 1: hash
    name = os.path.basename(path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(30)
        s.connect((host, port))
        p.send_request_header(s, name, size, digest)

        with open(path, "rb") as f:              # pass 2: stream
            while chunk := f.read(p.CHUNK_SIZE):
                s.sendall(chunk)

        status, text = p.read_response(s)
    return status, text, digest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5001)
    args = ap.parse_args()

    try:
        status, text, digest = send_file(args.host, args.port, args.file)
    except (OSError, p.ProtocolError) as e:
        print(f"Transfer failed: {e}")
        sys.exit(1)

    print(f"sha256: {digest}")
    print("Receiver says:", "VERIFIED" if status == p.STATUS_OK else f"FAILED ({text})")
    sys.exit(0 if status == p.STATUS_OK else 1)


if __name__ == "__main__":
    main()