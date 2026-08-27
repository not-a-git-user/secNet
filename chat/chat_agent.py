"""Local client-side cryptography agent for the VPN1 web chat.

The browser never receives the persistent private keys.  It asks this
loopback-only process to sign authentication challenges and to encrypt or
decrypt chat envelopes.  The agent uses a versioned tree-group state envelope
for the current Python implementation; the state API is intentionally opaque
to the server so it can be replaced by the OpenMLS provider without changing
the HTTP/Kafka chat protocol.

New in this revision:
  - Named group support: each group_id has its own key state stored separately.
  - File encryption/decryption endpoints reuse the group key (files shared with
    the group members by default, or the direct-key for DM file attachments).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from chat.identity import DeviceIdentity


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


class CryptoAgent:
    def __init__(self, identity: DeviceIdentity, state_dir: Path, origin: str):
        self.identity = identity
        self.state_dir = state_dir
        self.origin = origin
        self._lock = threading.RLock()
        # group_id -> {key, epoch, members, ...}
        self._group_states: dict[str, dict] = {}
        self._load_all_group_states()

    @property
    def device_tag(self) -> str:
        # The tag is assigned by the server. The browser learns it from /api/me.
        return self.identity.device_id

    # ------------------------------------------------------------------ #
    #  Persistence                                                         #
    # ------------------------------------------------------------------ #

    def _state_path(self, group_id: str) -> Path:
        safe = group_id.replace("/", "_").replace("..", "_")
        return self.state_dir / f"group-{safe}.json"

    def _load_all_group_states(self):
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        for path in self.state_dir.glob("group-*.json"):
            try:
                state = json.loads(path.read_text())
                gid = state.get("group_id")
                if gid:
                    self._group_states[gid] = state
            except Exception:
                pass

    def _save_group_state(self, group_id: str, state: dict):
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self._state_path(group_id)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, sort_keys=True))
        tmp.chmod(0o600)
        os.replace(tmp, path)

    # ------------------------------------------------------------------ #
    #  Signing                                                             #
    # ------------------------------------------------------------------ #

    def sign(self, challenge: bytes) -> bytes:
        return self.identity.sign(challenge)

    # ------------------------------------------------------------------ #
    #  Low-level crypto helpers                                            #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _derive(shared: bytes, label: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label).derive(shared)

    def _seal_to(self, recipient_public: bytes, plaintext: bytes, label: bytes) -> dict:
        ephemeral = X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))
        key = self._derive(shared, label + ephemeral_public + recipient_public)
        nonce = secrets.token_bytes(12)
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, label)
        return {
            "alg": "x25519-chacha20poly1305-v1",
            "ephemeral_public": b64(ephemeral_public),
            "nonce": b64(nonce),
            "ciphertext": b64(ciphertext),
        }

    def _open_with_direct_key(self, envelope: dict, label: bytes) -> bytes:
        ephemeral_public = unb64(envelope["ephemeral_public"])
        own_public = self.identity.direct_public_key_bytes
        shared = self.identity.direct_private_key.exchange(
            X25519PublicKey.from_public_bytes(ephemeral_public)
        )
        key = self._derive(shared, label + ephemeral_public + own_public)
        return ChaCha20Poly1305(key).decrypt(
            unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), label
        )

    # ------------------------------------------------------------------ #
    #  Direct (1-on-1) messages                                           #
    # ------------------------------------------------------------------ #

    def direct_encrypt(self, recipient_public: bytes, plaintext: bytes, message_id: str) -> dict:
        return {
            "kind": "direct",
            "message_id": message_id,
            "payload": self._seal_to(recipient_public, plaintext, b"vpn1 direct message v1"),
        }

    def direct_decrypt(self, envelope: dict) -> bytes:
        if envelope.get("kind") != "direct":
            raise ValueError("not a direct envelope")
        return self._open_with_direct_key(envelope["payload"], b"vpn1 direct message v1")

    # ------------------------------------------------------------------ #
    #  Group messages (general + named groups)                            #
    # ------------------------------------------------------------------ #

    def _group_key(self, group_id: str = "general") -> tuple[bytes, int]:
        with self._lock:
            state = self._group_states.get(group_id)
            if not state or not state.get("key"):
                raise ValueError(f"group '{group_id}' is not initialized on this device")
            return unb64(state["key"]), int(state["epoch"])

    def group_encrypt(self, plaintext: bytes, message_id: str, group_id: str = "general") -> dict:
        key, epoch = self._group_key(group_id)
        nonce = secrets.token_bytes(12)
        aad = f"vpn1 group v1:{group_id}:{epoch}".encode()
        return {
            "kind": "group",
            "group_id": group_id,
            "message_id": message_id,
            "epoch": epoch,
            "nonce": b64(nonce),
            "ciphertext": b64(ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)),
        }

    def group_decrypt(self, envelope: dict) -> bytes:
        if envelope.get("kind") not in ("group", "general"):
            raise ValueError("not a group envelope")
        group_id = envelope.get("group_id", "general")
        epoch = int(envelope["epoch"])
        with self._lock:
            state = self._group_states.get(group_id)
            if not state or int(state["epoch"]) != epoch:
                raise ValueError(f"group '{group_id}' epoch {epoch} is unavailable")
            key = unb64(state["key"])
        aad = f"vpn1 group v1:{group_id}:{epoch}".encode()
        return ChaCha20Poly1305(key).decrypt(
            unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), aad
        )

    def create_group_state(
        self, members: list[dict], epoch: int, own_tag: str, group_id: str = "general"
    ) -> dict:
        if not members:
            raise ValueError("group requires at least one member")
        group_key = secrets.token_bytes(32)
        label = b"vpn1 group epoch v1"
        state = {
            "kind": "tree-group-state-v1",
            "group_id": group_id,
            "epoch": int(epoch),
            "members": [m["device_tag"] for m in members],
            "envelopes": {},
        }
        for member in members:
            public_key = unb64(member["encryption_public_key"])
            if len(public_key) != 32:
                raise ValueError("member encryption key must be 32 bytes")
            state["envelopes"][member["device_tag"]] = self._seal_to(public_key, group_key, label)
        if own_tag not in state["envelopes"]:
            raise ValueError("own device must be a group member")
        self.install_group_state(state, own_tag)
        return state

    def install_group_state(self, state: dict, own_tag: str):
        group_id = state.get("group_id", "general")
        if state.get("kind") != "tree-group-state-v1" or own_tag not in state.get("envelopes", {}):
            raise ValueError("group state does not contain this device")
        label = b"vpn1 group epoch v1"
        group_key = self._open_with_direct_key(state["envelopes"][own_tag], label)
        if len(group_key) != 32:
            raise ValueError("invalid group key")
        stored = dict(state)
        stored["key"] = b64(group_key)
        stored.pop("envelopes", None)
        with self._lock:
            existing = self._group_states.get(group_id)
            if existing and int(stored["epoch"]) < int(existing["epoch"]):
                raise ValueError("stale group epoch")
            self._group_states[group_id] = stored
            self._save_group_state(group_id, stored)

    # ------------------------------------------------------------------ #
    #  File encryption (reuses group key)                                 #
    # ------------------------------------------------------------------ #

    def file_encrypt(self, plaintext: bytes, group_id: str = "general") -> dict:
        """Encrypt a file blob with the current group key.

        Returns a dict containing the nonce, ciphertext, epoch, and group_id
        so the recipient can decrypt with the matching group key.
        """
        key, epoch = self._group_key(group_id)
        nonce = secrets.token_bytes(12)
        aad = f"vpn1 file v1:{group_id}:{epoch}".encode()
        return {
            "alg": "chacha20poly1305-group-file-v1",
            "group_id": group_id,
            "epoch": epoch,
            "nonce": b64(nonce),
            "ciphertext": b64(ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)),
        }

    def file_decrypt(self, envelope: dict) -> bytes:
        """Decrypt a file blob encrypted by file_encrypt."""
        if envelope.get("alg") != "chacha20poly1305-group-file-v1":
            raise ValueError("unsupported file envelope algorithm")
        group_id = envelope.get("group_id", "general")
        epoch = int(envelope["epoch"])
        with self._lock:
            state = self._group_states.get(group_id)
            if not state or int(state["epoch"]) != epoch:
                raise ValueError(f"group '{group_id}' epoch {epoch} is unavailable for file decrypt")
            key = unb64(state["key"])
        aad = f"vpn1 file v1:{group_id}:{epoch}".encode()
        return ChaCha20Poly1305(key).decrypt(
            unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), aad
        )

    # Backwards-compat aliases for general group (used by existing code)
    def general_encrypt(self, plaintext: bytes, message_id: str) -> dict:
        return self.group_encrypt(plaintext, message_id, group_id="general")

    def general_decrypt(self, envelope: dict) -> bytes:
        # patch kind for legacy envelopes
        if envelope.get("kind") == "general":
            envelope = dict(envelope, kind="group", group_id="general")
        return self.group_decrypt(envelope)


# --------------------------------------------------------------------------- #
#  HTTP handler                                                                #
# --------------------------------------------------------------------------- #

class AgentHandler(BaseHTTPRequestHandler):
    server_version = "VPN1ChatAgent/1.1"

    def _agent(self) -> CryptoAgent:
        return self.server.agent

    def _allowed(self) -> bool:
        return self.headers.get("Origin") in (None, self._agent().origin)

    def _write(self, status: int, value: dict):
        data = b"" if status == 204 else json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        origin = self.headers.get("Origin")
        if origin == self._agent().origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()
        if data:
            self.wfile.write(data)

    def do_OPTIONS(self):
        if not self._allowed():
            self.send_error(403)
            return
        self._write(204, {})

    def do_GET(self):
        if not self._allowed():
            self.send_error(403)
            return
        if self.path == "/v1/status":
            ag = self._agent()
            self._write(200, {
                "device_id": ag.identity.device_id,
                "public_key": ag.identity.export_public_key(),
                "encryption_public_key": b64(ag.identity.direct_public_key_bytes),
            })
            return
        self.send_error(404)

    def do_POST(self):
        if not self._allowed():
            self.send_error(403)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size > 64_000_000:  # 64 MB max (encrypted file upload)
                raise ValueError("request too large")
            body = json.loads(self.rfile.read(size).decode())
            ag = self._agent()
            p = self.path

            if p == "/v1/sign":
                self._write(200, {"signature": b64(ag.sign(unb64(body["challenge"])))})

            elif p == "/v1/direct/encrypt":
                self._write(200, {"envelope": ag.direct_encrypt(
                    unb64(body["recipient_public_key"]),
                    unb64(body["plaintext"]),
                    body.get("message_id", ""),
                )})
            elif p == "/v1/direct/decrypt":
                self._write(200, {"plaintext": b64(ag.direct_decrypt(body["envelope"]))})

            elif p == "/v1/group/encrypt":
                group_id = body.get("group_id", "general")
                self._write(200, {"envelope": ag.group_encrypt(
                    unb64(body["plaintext"]), body.get("message_id", ""), group_id
                )})
            elif p == "/v1/group/decrypt":
                self._write(200, {"plaintext": b64(ag.group_decrypt(body["envelope"]))})

            elif p == "/v1/group/create-state":
                state = ag.create_group_state(
                    body["members"],
                    int(body["epoch"]),
                    body["own_tag"],
                    body.get("group_id", "general"),
                )
                self._write(200, {"state": state})
            elif p == "/v1/group/install-state":
                ag.install_group_state(body["state"], body["own_tag"])
                self._write(200, {"ok": True})

            elif p == "/v1/file/encrypt":
                group_id = body.get("group_id", "general")
                envelope = ag.file_encrypt(unb64(body["plaintext"]), group_id)
                self._write(200, {"envelope": envelope})
            elif p == "/v1/file/decrypt":
                plaintext = ag.file_decrypt(body["envelope"])
                self._write(200, {"plaintext": b64(plaintext)})

            # Backwards-compat aliases
            elif p == "/v1/general/encrypt":
                self._write(200, {"envelope": ag.general_encrypt(
                    unb64(body["plaintext"]), body.get("message_id", "")
                )})
            elif p == "/v1/general/decrypt":
                self._write(200, {"plaintext": b64(ag.general_decrypt(body["envelope"]))})
            elif p == "/v1/general/create-state":
                state = ag.create_group_state(
                    body["members"], int(body["epoch"]), body["own_tag"], "general"
                )
                self._write(200, {"state": state})
            elif p == "/v1/general/install-state":
                ag.install_group_state(body["state"], body["own_tag"])
                self._write(200, {"ok": True})

            else:
                self.send_error(404)
        except Exception as exc:
            self._write(400, {"error": str(exc)})

    def log_message(self, format, *args):
        return


def main():
    parser = argparse.ArgumentParser(description="VPN1 local chat crypto agent")
    parser.add_argument("--device-key", default="~/.vpn1/device-ed25519.key")
    parser.add_argument("--state-dir", default="~/.vpn1/chat")
    parser.add_argument("--port", type=int, default=48271)
    parser.add_argument("--origin", default="http://10.0.0.1:8080")
    args = parser.parse_args()
    identity = DeviceIdentity.load_or_create(Path(args.device_key).expanduser())
    state_dir = Path(args.state_dir).expanduser()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), AgentHandler)
    server.agent = CryptoAgent(identity, state_dir, args.origin)
    print(f"[chat-agent] listening on 127.0.0.1:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
