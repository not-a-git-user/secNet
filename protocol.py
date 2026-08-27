"""Small, length-prefixed wire protocol helpers.

TCP is a byte stream, so the VPN handshake and data channel both need an
explicit message boundary.  The four-byte network-order length prefix is
kept deliberately simple and is shared by both sides.
"""

import json
import socket
import struct
import threading


MAX_FRAME_SIZE = 4 * 1024 * 1024


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("peer closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(sock: socket.socket, data: bytes, send_lock: threading.Lock | None = None):
    if len(data) > MAX_FRAME_SIZE:
        raise ValueError("frame is too large")
    frame = struct.pack("!I", len(data)) + data
    if send_lock is None:
        sock.sendall(frame)
    else:
        with send_lock:
            sock.sendall(frame)


def recv_frame(sock: socket.socket) -> bytes:
    length = struct.unpack("!I", recv_exact(sock, 4))[0]
    if length > MAX_FRAME_SIZE:
        raise ValueError("frame is too large")
    return recv_exact(sock, length)


def encode_message(message: dict) -> bytes:
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_message(data: bytes) -> dict:
    message = json.loads(data.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("protocol message must be a JSON object")
    return message
