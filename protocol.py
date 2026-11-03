import json
import re
import struct

# ---- Protocol constants (BNP v1) ----
MAGIC = b"BNP1"
VERSION = 1
PREAMBLE = struct.Struct("!4sBI")   # magic(4s), version(B), header_len(I); "!" = network byte order
RESPONSE = struct.Struct("!BH")     # status(B), message_len(H)

MAX_HEADER_LEN = 4096                # JSON header is tiny; reject anything bigger
MAX_FILE_SIZE = 1024 ** 3            # 1 GiB limit
CHUNK_SIZE = 64 * 1024

STATUS_OK = 0
STATUS_BAD_HASH = 1
STATUS_BAD_REQUEST = 2
STATUS_INCOMPLETE = 3

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ProtocolError(Exception):
    """Peer sent something that violates the protocol, or closed early."""


def recv_exact(sock, n):
    """Read exactly n bytes, looping over partial reads."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if chunk == b"":   # peer closed before we got everything
            raise ProtocolError(f"connection closed after {len(buf)} of {n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def validate_header(h):
    """Check decoded metadata. Raises ProtocolError if anything is wrong."""
    if not isinstance(h, dict):
        raise ProtocolError("header is not a JSON object")
    for key in ("filename", "file_size", "sha256"):
        if key not in h:
            raise ProtocolError(f"missing field: {key}")

    name, size, digest = h["filename"], h["file_size"], h["sha256"]

    if not isinstance(name, str) or not (1 <= len(name) <= 255):
        raise ProtocolError("bad filename length")
    if "/" in name or "\\" in name or ":" in name or name in (".", ".."):
        raise ProtocolError("filename must not contain path components")
    if any(ord(c) < 32 for c in name):
        raise ProtocolError("filename contains control characters")

    # bool is a subclass of int in Python, so exclude it explicitly
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ProtocolError("file_size must be a non-negative integer")
    if size > MAX_FILE_SIZE:
        raise ProtocolError(f"file_size {size} exceeds limit {MAX_FILE_SIZE}")

    if not isinstance(digest, str) or not SHA256_RE.match(digest):
        raise ProtocolError("sha256 must be 64 lowercase hex characters")
    return h


def send_request_header(sock, filename, file_size, sha256_hex):
    header = json.dumps(
        {"filename": filename, "file_size": file_size, "sha256": sha256_hex}
    ).encode("utf-8")
    sock.sendall(PREAMBLE.pack(MAGIC, VERSION, len(header)) + header)


def read_request_header(sock):
    magic, version, header_len = PREAMBLE.unpack(recv_exact(sock, PREAMBLE.size))
    if magic != MAGIC:
        raise ProtocolError("bad magic: not a BNP connection")
    if version != VERSION:
        raise ProtocolError(f"unsupported version {version}")
    if header_len == 0 or header_len > MAX_HEADER_LEN:
        raise ProtocolError(f"bad header length {header_len}")
    raw = recv_exact(sock, header_len)
    try:
        header = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtocolError("header is not valid UTF-8 JSON")
    return validate_header(header)


def send_response(sock, status, message=""):
    text = message.encode("utf-8")[:1000]
    sock.sendall(RESPONSE.pack(status, len(text)) + text)


def read_response(sock):
    status, length = RESPONSE.unpack(recv_exact(sock, RESPONSE.size))
    text = recv_exact(sock, length).decode("utf-8", errors="replace")
    return status, text