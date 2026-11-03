import argparse
import os
import socket

import protocol as p
from integrity import new_hasher


def unique_path(outdir, name):
    """Never overwrite an existing file: a.bin -> a_1.bin -> a_2.bin ..."""
    base, ext = os.path.splitext(name)
    candidate = os.path.join(outdir, name)
    n = 1
    while os.path.exists(candidate) or os.path.exists(candidate + ".part"):
        candidate = os.path.join(outdir, f"{base}_{n}{ext}")
        n += 1
    return candidate


def handle(conn, outdir):
    tmp_path = None
    try:
        header = p.read_request_header(conn)
        name, size, expected = header["filename"], header["file_size"], header["sha256"]
        print(f"  Incoming: {name}, {size:,} bytes")

        final_path = unique_path(outdir, name)
        tmp_path = final_path + ".part"
        hasher = new_hasher()

        remaining = size
        with open(tmp_path, "wb") as f:
            while remaining > 0:
                chunk = conn.recv(min(p.CHUNK_SIZE, remaining))
                if chunk == b"":
                    raise p.ProtocolError(
                        f"connection closed with {remaining} bytes still missing")
                f.write(chunk)
                hasher.update(chunk)
                remaining -= len(chunk)

        actual = hasher.hexdigest()
        if actual == expected:
            os.rename(tmp_path, final_path)   # finalize only after verification
            tmp_path = None
            p.send_response(conn, p.STATUS_OK, "verified")
            print(f"  OK: saved {final_path}")
        else:
            p.send_response(conn, p.STATUS_BAD_HASH, "sha256 mismatch")
            print(f"  FAIL: hash mismatch\n    expected {expected}\n    actual   {actual}")
    except (p.ProtocolError, OSError) as e:
        print(f"  ERROR: {e}")
        try:
            p.send_response(conn, p.STATUS_INCOMPLETE, str(e))
        except OSError:
            pass   # peer already gone
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)               # discard partial file


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")   # use 0.0.0.0 for two computers
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--outdir", default="received_data")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((args.host, args.port))
        server.listen(5)
        print(f"Receiver listening on {args.host}:{args.port} (Ctrl+C to stop)")
        try:
            while True:
                conn, addr = server.accept()
                print(f"Connection from {addr}")
                with conn:
                    conn.settimeout(30)           # don't hang forever on a dead peer
                    handle(conn, args.outdir)
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()