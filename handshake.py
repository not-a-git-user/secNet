"""Negotiated, ephemeral key exchange for VPN sessions.

The server still needs a separately configured identity/authentication layer
for protection against an active man-in-the-middle.  This module provides
fresh session secrets and transcript-bound Finished messages, but does not
invent a certificate or peer-key trust model.
"""

import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from encryptDecrypt import (
    SUPPORTED_CIPHERS,
    SessionCipher,
    derive_session_keys,
)
from chat.identity import DeviceIdentity, verify_device_signature
from protocol import decode_message, encode_message, recv_frame, send_frame


PROTOCOL_VERSION = 1
KEY_EXCHANGES = (
    "ecdh",
    "dh-chain",
    "treekem",
    "chained-kdf",
    "rsa-oaep",
    "ml-kem",
)


def ml_kem_available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem  # noqa: F401

        return True
    except ImportError:
        return False


def available_key_exchanges() -> tuple[str, ...]:
    if ml_kem_available():
        return KEY_EXCHANGES
    return tuple(name for name in KEY_EXCHANGES if name != "ml-kem")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    if not isinstance(data, str):
        raise ValueError("key-exchange payload must be base64 text")
    return base64.b64decode(data.encode("ascii"), validate=True)


def _x25519_keypair():
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public


def _x25519_shared(private, public_bytes: bytes) -> bytes:
    return private.exchange(X25519PublicKey.from_public_bytes(public_bytes))


def _chain_digest(parts: list[bytes], label: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(label)
    for part in parts:
        digest.update(len(part).to_bytes(2, "big"))
        digest.update(part)
    return digest.digest()


def _chained_kdf(secret: bytes) -> bytes:
    current = secret
    for label in (b"vpn chained-kdf stage 1", b"vpn chained-kdf stage 2", b"vpn chained-kdf stage 3"):
        current = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=label,
        ).derive(current)
    return current


def _serialize_ec_public(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _client_key_exchange_init(name: str):
    if name == "ecdh":
        private = ec.generate_private_key(ec.SECP256R1())
        return private, {"kind": name, "public": _b64(_serialize_ec_public(private.public_key()))}

    if name in ("dh-chain",):
        private_keys = []
        public_keys = []
        for _ in range(3):
            private, public = _x25519_keypair()
            private_keys.append(private)
            public_keys.append(_b64(public))
        return private_keys, {"kind": name, "public": public_keys}

    if name in ("treekem", "chained-kdf"):
        private, public = _x25519_keypair()
        return private, {"kind": name, "public": _b64(public)}

    if name == "rsa-oaep":
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return private, {
            "kind": name,
            "public": _b64(
                private.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
        }

    if name == "ml-kem":
        if not ml_kem_available():
            raise ValueError("ML-KEM is unavailable in this cryptography build")
        from cryptography.hazmat.primitives.asymmetric import mlkem

        private = mlkem.MLKEM768PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return private, {"kind": name, "public": _b64(public)}

    raise ValueError(f"unsupported key exchange: {name}")


def _server_key_exchange_response(name: str, client_payload: dict):
    if client_payload.get("kind") != name:
        raise ValueError("key-exchange kind does not match negotiation")

    if name == "ecdh":
        client_public = serialization.load_der_public_key(_unb64(client_payload["public"]))
        if not isinstance(client_public, ec.EllipticCurvePublicKey):
            raise ValueError("invalid ECDH public key")
        private = ec.generate_private_key(ec.SECP256R1())
        server_public = _serialize_ec_public(private.public_key())
        return private.exchange(ec.ECDH(), client_public), {"kind": name, "public": _b64(server_public)}

    if name == "dh-chain":
        client_publics = client_payload.get("public")
        if not isinstance(client_publics, list) or len(client_publics) != 3:
            raise ValueError("DH chain requires three public keys")
        private_keys = []
        server_publics = []
        shared = []
        for encoded in client_publics:
            private, public = _x25519_keypair()
            private_keys.append(private)
            server_publics.append(_b64(public))
            shared.append(_x25519_shared(private, _unb64(encoded)))
        return _chain_digest(shared, b"vpn dh-chain v1"), {"kind": name, "public": server_publics}

    if name in ("treekem", "chained-kdf"):
        client_public = _unb64(client_payload["public"])
        private, server_public = _x25519_keypair()
        shared = _x25519_shared(private, client_public)
        if name == "treekem":
            shared = _chain_digest(
                [client_public, server_public, shared], b"vpn treekem two-party root v1"
            )
        else:
            shared = _chained_kdf(shared)
        return shared, {"kind": name, "public": _b64(server_public)}

    if name == "rsa-oaep":
        client_public = serialization.load_der_public_key(_unb64(client_payload["public"]))
        if not isinstance(client_public, rsa.RSAPublicKey):
            raise ValueError("invalid RSA public key")
        shared = os.urandom(32)
        ciphertext = client_public.encrypt(
            shared,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return shared, {"kind": name, "ciphertext": _b64(ciphertext)}

    if name == "ml-kem":
        if not ml_kem_available():
            raise ValueError("ML-KEM is unavailable in this cryptography build")
        from cryptography.hazmat.primitives.asymmetric import mlkem

        client_public = mlkem.MLKEM768PublicKey.from_public_bytes(
            _unb64(client_payload["public"])
        )
        shared, ciphertext = client_public.encapsulate()
        return shared, {"kind": name, "ciphertext": _b64(ciphertext)}

    raise ValueError(f"unsupported key exchange: {name}")


def _client_key_exchange_finish(name: str, private, client_payload: dict, server_payload: dict) -> bytes:
    if server_payload.get("kind") != name:
        raise ValueError("server key-exchange response does not match negotiation")

    if name == "ecdh":
        server_public = serialization.load_der_public_key(_unb64(server_payload["public"]))
        if not isinstance(server_public, ec.EllipticCurvePublicKey):
            raise ValueError("invalid server ECDH public key")
        return private.exchange(ec.ECDH(), server_public)

    if name == "dh-chain":
        server_publics = server_payload.get("public")
        if not isinstance(server_publics, list) or len(server_publics) != 3:
            raise ValueError("DH chain response requires three public keys")
        shared = [
            _x25519_shared(private_key, _unb64(public))
            for private_key, public in zip(private, server_publics)
        ]
        return _chain_digest(shared, b"vpn dh-chain v1")

    if name in ("treekem", "chained-kdf"):
        client_public = _unb64(client_payload["public"])
        server_public = _unb64(server_payload["public"])
        shared = _x25519_shared(private, server_public)
        if name == "treekem":
            return _chain_digest(
                [client_public, server_public, shared], b"vpn treekem two-party root v1"
            )
        return _chained_kdf(shared)

    if name == "rsa-oaep":
        return private.decrypt(
            _unb64(server_payload["ciphertext"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    if name == "ml-kem":
        from cryptography.hazmat.primitives.asymmetric import mlkem

        if not isinstance(private, mlkem.MLKEM768PrivateKey):
            raise ValueError("invalid ML-KEM private key")
        return private.decapsulate(_unb64(server_payload["ciphertext"]))

    raise ValueError(f"unsupported key exchange: {name}")


@dataclass
class Session:
    send_cipher: SessionCipher
    receive_cipher: SessionCipher
    cipher: str
    key_exchange: str
    vpn_ip: str
    device_tag: str | None = None
    device_public_key: bytes | None = None


def _finished(transcript_hash: bytes) -> bytes:
    return b"Finished" + transcript_hash


def _validate_choice(name: str, choices: tuple[str, ...], label: str):
    if name not in choices:
        raise ValueError(f"unsupported {label}: {name}")


def _device_auth_binding(transcript_hash: bytes, client_nonce: bytes, server_nonce: bytes) -> bytes:
    return b"vpn1 device auth binding v1\0" + transcript_hash + client_nonce + server_nonce


def client_handshake(
    sock,
    key_exchange: str,
    cipher: str,
    device_identity: DeviceIdentity | None = None,
) -> Session:
    _validate_choice(key_exchange, KEY_EXCHANGES, "key exchange")
    _validate_choice(cipher, SUPPORTED_CIPHERS, "cipher")
    private, client_key_payload = _client_key_exchange_init(key_exchange)
    client_nonce = os.urandom(16)
    client_hello = {
        "type": "client_hello",
        "version": PROTOCOL_VERSION,
        "key_exchange": key_exchange,
        "cipher": cipher,
        "client_nonce": _b64(client_nonce),
        "key_payload": client_key_payload,
    }
    client_hello_bytes = encode_message(client_hello)
    send_frame(sock, client_hello_bytes)

    server_hello_bytes = recv_frame(sock)
    server_hello = decode_message(server_hello_bytes)
    if server_hello.get("type") != "server_hello":
        raise ValueError("invalid server hello")
    if server_hello.get("version") != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    if server_hello.get("key_exchange") != key_exchange:
        raise ValueError("server selected a different key exchange")
    if server_hello.get("cipher") != cipher:
        raise ValueError("server selected a different cipher")

    server_nonce = _unb64(server_hello["server_nonce"])
    shared = _client_key_exchange_finish(
        key_exchange, private, client_key_payload, server_hello["key_payload"]
    )
    transcript_hash = hashlib.sha256(client_hello_bytes + server_hello_bytes).digest()
    client_to_server, server_to_client = derive_session_keys(
        shared, client_nonce, server_nonce, transcript_hash
    )
    send_cipher = SessionCipher(client_to_server, cipher)
    receive_cipher = SessionCipher(server_to_client, cipher)

    if receive_cipher.decrypt(recv_frame(sock)) != _finished(transcript_hash):
        raise ValueError("server Finished verification failed")
    send_frame(sock, send_cipher.encrypt(_finished(transcript_hash)))

    device_tag = None
    device_public_key = None
    if device_identity is not None:
        device_public_key = device_identity.public_key_bytes
        encryption_public_key = device_identity.direct_public_key_bytes
        binding = _device_auth_binding(transcript_hash, client_nonce, server_nonce)
        signed_binding = binding + device_public_key + encryption_public_key
        auth_message = encode_message(
            {
                "type": "device_auth",
                "public_key": _b64(device_public_key),
                "encryption_public_key": _b64(encryption_public_key),
                "signature": _b64(device_identity.sign(signed_binding)),
            }
        )
        send_frame(sock, send_cipher.encrypt(auth_message))
        auth_ack = decode_message(receive_cipher.decrypt(recv_frame(sock)))
        if auth_ack.get("type") != "device_auth_ok" or not auth_ack.get("device_tag"):
            raise ValueError("device authentication was rejected")
        device_tag = auth_ack["device_tag"]

    return Session(
        send_cipher,
        receive_cipher,
        cipher,
        key_exchange,
        server_hello["vpn_ip"],
        device_tag,
        device_public_key,
    )


def server_handshake(
    sock,
    vpn_ip: str,
    key_exchange: str = "auto",
    cipher: str = "auto",
    device_directory=None,
) -> Session:
    client_hello_bytes = recv_frame(sock)
    client_hello = decode_message(client_hello_bytes)
    if client_hello.get("type") != "client_hello":
        raise ValueError("invalid client hello")
    if client_hello.get("version") != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")

    requested_key_exchange = client_hello.get("key_exchange")
    requested_cipher = client_hello.get("cipher")
    _validate_choice(requested_key_exchange, KEY_EXCHANGES, "key exchange")
    _validate_choice(requested_cipher, SUPPORTED_CIPHERS, "cipher")
    if requested_key_exchange not in available_key_exchanges():
        raise ValueError("requested key exchange is unavailable on the server")
    if key_exchange != "auto" and key_exchange != requested_key_exchange:
        raise ValueError("client and server key-exchange selections differ")
    if cipher != "auto" and cipher != requested_cipher:
        raise ValueError("client and server cipher selections differ")

    selected_key_exchange = requested_key_exchange
    selected_cipher = requested_cipher
    shared, server_key_payload = _server_key_exchange_response(
        selected_key_exchange, client_hello["key_payload"]
    )
    server_nonce = os.urandom(16)
    server_hello = {
        "type": "server_hello",
        "version": PROTOCOL_VERSION,
        "key_exchange": selected_key_exchange,
        "cipher": selected_cipher,
        "server_nonce": _b64(server_nonce),
        "vpn_ip": vpn_ip,
        "key_payload": server_key_payload,
    }
    server_hello_bytes = encode_message(server_hello)
    send_frame(sock, server_hello_bytes)

    client_nonce = _unb64(client_hello["client_nonce"])
    transcript_hash = hashlib.sha256(client_hello_bytes + server_hello_bytes).digest()
    client_to_server, server_to_client = derive_session_keys(
        shared, client_nonce, server_nonce, transcript_hash
    )
    send_cipher = SessionCipher(server_to_client, selected_cipher)
    receive_cipher = SessionCipher(client_to_server, selected_cipher)
    send_frame(sock, send_cipher.encrypt(_finished(transcript_hash)))
    if receive_cipher.decrypt(recv_frame(sock)) != _finished(transcript_hash):
        raise ValueError("client Finished verification failed")

    device_tag = None
    device_public_key = None
    if device_directory is not None:
        auth_message = decode_message(receive_cipher.decrypt(recv_frame(sock)))
        if auth_message.get("type") != "device_auth":
            raise ValueError("missing device authentication message")
        device_public_key = _unb64(auth_message["public_key"])
        encryption_public_key = _unb64(auth_message.get("encryption_public_key", ""))
        if len(encryption_public_key) != 32:
            raise ValueError("device encryption public key must be 32 bytes")
        signature = _unb64(auth_message["signature"])
        binding = _device_auth_binding(transcript_hash, client_nonce, server_nonce)
        verify_device_signature(
            device_public_key,
            binding + device_public_key + encryption_public_key,
            signature,
        )
        device_tag = device_directory.register_or_get(device_public_key, encryption_public_key)
        send_frame(
            sock,
            send_cipher.encrypt(
                encode_message({"type": "device_auth_ok", "device_tag": device_tag})
            ),
        )

    return Session(
        send_cipher,
        receive_cipher,
        selected_cipher,
        selected_key_exchange,
        vpn_ip,
        device_tag,
        device_public_key,
    )
