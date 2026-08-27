"""Kafka-backed, VPN-only chat API.

The service deliberately treats all chat envelopes as opaque.  Encryption and
decryption happen in the local client agent; this process only authenticates
devices, routes ciphertext, and maintains Kafka-derived delivery state.

Changes in this revision:
  - Fixed deprecated hmac.new() -> hmac.HMAC()
  - Added challenge expiry pruning
  - Added named group support (POST /api/groups/create, GET /api/groups,
    POST /api/groups/{id}/message, GET /api/groups/{id}/history)
  - Added file upload/download endpoints via pluggable ObjectStore backend
  - Added message history endpoints (GET /api/history/general)
  - WebSocket now pushes group messages as {kind: "group", group_id, message}
"""


import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from collections import defaultdict
from pathlib import Path

from chat.identity import verify_device_signature


class ChatService:
    def __init__(self, bus, directory, registry, agent_port: int = 48271):
        self.bus = bus
        self.directory = directory
        self.registry = registry
        self.agent_port = agent_port
        self.session_secret = os.environ.get("CHAT_SESSION_SECRET")
        if not self.session_secret:
            raise RuntimeError("CHAT_SESSION_SECRET must be set to a stable random secret")

        # Auth
        self._challenges: dict[str, tuple[str, float]] = {}

        # Private messages: recipient_tag -> message_id -> message
        self._pending: dict[str, dict[str, dict]] = defaultdict(dict)
        self._delivered: set[tuple[str, str]] = set()

        # General channel history (last 1000)
        self._general_history: list[dict] = []

        # Named groups: group_id -> {group_id, name, members, admin_tag, created_at}
        self._groups: dict[str, dict] = {}
        # Named group history: group_id -> list (last 200)
        self._group_history: dict[str, list] = defaultdict(list)

        # MLS state for general group
        self._latest_mls_event: dict | None = None

        # MLS state per named group: group_id -> latest event
        self._latest_group_mls: dict[str, dict] = {}

        # WebSockets: device_tag -> set of (loop, websocket)
        self._websockets: dict[str, set[tuple[asyncio.AbstractEventLoop, object]]] = defaultdict(set)

        self._lock = threading.RLock()
        self._consumer_threads: list[threading.Thread] = []
        self._consumer_instance = uuid.uuid4().hex

        # Lazy-initialized object store
        self._store = None
        self._store_lock = threading.Lock()

    def _get_store(self):
        with self._store_lock:
            if self._store is None:
                try:
                    from chat.storage import get_store
                    self._store = get_store()
                except Exception as exc:
                    raise RuntimeError(
                        f"File store not configured: {exc}. "
                        "Set FILE_STORE_BACKEND and required env vars."
                    ) from exc
            return self._store

    def start_consumers(self):
        suffix = self._consumer_instance
        self._start_consumer("chat-general", f"vpn1-chat-general-{suffix}", self._consume_general)
        self._start_consumer("chat-groups", f"vpn1-chat-groups-{suffix}", self._consume_group_message)
        self._start_consumer("group-directory", f"vpn1-group-dir-{suffix}", self._consume_group_directory)
        rebuild_events = []
        for topic, handler, group in (
            ("delivery-state", self._consume_delivery, f"vpn1-chat-delivery-{suffix}"),
            ("chat-private", self._consume_private, f"vpn1-chat-private-{suffix}"),
            ("mls-group-events", self._consume_mls_event, f"vpn1-chat-mls-{suffix}"),
        ):
            ready = threading.Event()
            rebuild_events.append((topic, ready))
            self._start_consumer(topic, group, handler, ready)
        for topic, ready in rebuild_events:
            if not ready.wait(15):
                print(f"[chat] Kafka replay for {topic} is still in progress")

    def _start_consumer(self, topic: str, group: str, handler, ready_event=None):
        def consume():
            consumer = self.bus.consumer(group, [topic], "earliest")
            assigned = False
            quiet_since = None
            try:
                while True:
                    record = consumer.poll(1.0)
                    if not assigned and consumer.assignment():
                        assigned = True
                    if record is None:
                        if assigned and ready_event is not None:
                            if quiet_since is None:
                                quiet_since = time.monotonic()
                            elif time.monotonic() - quiet_since >= 1.0:
                                ready_event.set()
                        continue
                    if record.error():
                        if ready_event is not None and assigned:
                            if quiet_since is None:
                                quiet_since = time.monotonic()
                            elif time.monotonic() - quiet_since >= 1.0:
                                ready_event.set()
                        continue
                    quiet_since = None
                    try:
                        _, value = self.bus.decode(record)
                        handler(value)
                        consumer.commit(record)
                    except Exception as exc:
                        print(f"[chat] Kafka record handling error on {topic}: {exc}")
            finally:
                if ready_event is not None:
                    ready_event.set()
                consumer.close()

        thread = threading.Thread(target=consume, daemon=True, name=f"kafka-{topic}")
        thread.start()
        self._consumer_threads.append(thread)

    # ------------------------------------------------------------------ #
    #  Kafka consumers                                                     #
    # ------------------------------------------------------------------ #

    def _consume_general(self, value: dict):
        with self._lock:
            self._general_history.append(value)
            self._general_history = self._general_history[-1000:]
        self._broadcast(value.get("sender_tag"), {"kind": "general", "message": value})

    def _consume_private(self, value: dict):
        recipient = value.get("recipient_tag")
        message_id = value.get("message_id")
        if not recipient or not message_id:
            return
        with self._lock:
            if (recipient, message_id) in self._delivered:
                return
            self._pending[recipient][message_id] = value
        self._broadcast(recipient, {"kind": "private", "message": value})

    def _consume_delivery(self, value: dict):
        if value.get("state") != "delivered":
            return
        recipient = value.get("recipient_tag")
        message_id = value.get("message_id")
        if not recipient or not message_id:
            return
        with self._lock:
            self._delivered.add((recipient, message_id))
            self._pending[recipient].pop(message_id, None)

    def _consume_mls_event(self, value: dict):
        with self._lock:
            self._latest_mls_event = value
        self._broadcast(None, {"kind": "mls", "event": value})

    def _consume_group_directory(self, value: dict):
        group_id = value.get("group_id")
        if not group_id:
            return
        with self._lock:
            self._groups[group_id] = value

    def _consume_group_message(self, value: dict):
        group_id = value.get("group_id")
        if not group_id:
            return
        with self._lock:
            hist = self._group_history[group_id]
            hist.append(value)
            self._group_history[group_id] = hist[-200:]
        # Push to all members of the group
        with self._lock:
            group = self._groups.get(group_id, {})
            members = group.get("members", [])
        for member_tag in members:
            self._broadcast(member_tag, {"kind": "group", "group_id": group_id, "message": value})

    def _broadcast(self, recipient_tag: str | None, payload: dict):
        with self._lock:
            targets = []
            if recipient_tag:
                targets.extend(self._websockets.get(recipient_tag, set()))
            else:
                for sockets in self._websockets.values():
                    targets.extend(sockets)
        for loop, websocket in targets:
            future = asyncio.run_coroutine_threadsafe(websocket.send_json(payload), loop)
            future.add_done_callback(
                lambda task: task.exception() if not task.cancelled() else None
            )

    def add_websocket(self, tag: str, websocket, loop):
        with self._lock:
            self._websockets[tag].add((loop, websocket))

    def remove_websocket(self, tag: str, websocket, loop):
        with self._lock:
            self._websockets[tag].discard((loop, websocket))

    # ------------------------------------------------------------------ #
    #  Auth helpers                                                        #
    # ------------------------------------------------------------------ #

    def _peer_tag(self, request) -> str:
        client = request.client
        if not client:
            raise PermissionError("request has no peer address")
        peer = self.registry.get(client.host)
        if not peer or not peer.device_tag:
            raise PermissionError("request must originate from an authenticated VPN peer")
        return peer.device_tag

    def _make_cookie(self, tag: str) -> str:
        payload = f"{tag}.{int(time.time()) + 86400}".encode("utf-8")
        encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        signature = hmac.HMAC(
            self.session_secret.encode(), encoded.encode(), hashlib.sha256
        ).digest()
        return encoded + "." + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")

    def _cookie_tag(self, cookie: str | None) -> str | None:
        if not cookie or "." not in cookie:
            return None
        encoded, supplied = cookie.rsplit(".", 1)
        expected = hmac.HMAC(
            self.session_secret.encode(), encoded.encode(), hashlib.sha256
        ).digest()
        try:
            signature = base64.urlsafe_b64decode(supplied + "=" * (-len(supplied) % 4))
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()
            tag, expiry = raw.rsplit(".", 1)
        except Exception:
            return None
        if not hmac.compare_digest(signature, expected) or int(expiry) < time.time():
            return None
        return tag

    def _authenticated_tag(self, request) -> str:
        tag = self._cookie_tag(request.cookies.get("chat_session"))
        if not tag or not self.directory.get_by_tag(tag):
            raise PermissionError("chat authentication required")
        return tag

    @staticmethod
    def _decode_b64(value: str) -> bytes:
        return base64.b64decode(value.encode("ascii"), validate=True)

    @staticmethod
    def _validate_envelope(envelope: dict):
        if not isinstance(envelope, dict) or not envelope.get("alg") or not envelope.get("ciphertext"):
            raise ValueError("encrypted envelope must contain alg and ciphertext")
        if len(json.dumps(envelope)) > 2_000_000:
            raise ValueError("encrypted envelope is too large")

    @staticmethod
    def _validate_group_message_envelope(envelope: dict):
        """Group message envelopes have nonce+ciphertext but not necessarily alg."""
        if not isinstance(envelope, dict) or not envelope.get("ciphertext"):
            raise ValueError("encrypted envelope must contain ciphertext")
        if len(json.dumps(envelope)) > 2_000_000:
            raise ValueError("encrypted envelope is too large")

    # ------------------------------------------------------------------ #
    #  FastAPI app                                                         #
    # ------------------------------------------------------------------ #

    def create_app(self):
        from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, UploadFile, File, Form
        from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
        from fastapi.staticfiles import StaticFiles

        app = FastAPI(title="secNet Chat")
        web_root = Path(__file__).parent / "web"
        app.mount("/static", StaticFiles(directory=web_root), name="static")

        def error_response(exc):
            status = 401 if isinstance(exc, PermissionError) else 400
            return JSONResponse({"error": str(exc)}, status_code=status)

        @app.get("/")
        async def index():
            return FileResponse(web_root / "index.html")

        # ---- Auth -------------------------------------------------------- #

        @app.get("/api/auth/challenge")
        async def auth_challenge(request: Request):
            try:
                tag = self._peer_tag(request)
                challenge_id = secrets.token_urlsafe(24)
                challenge = secrets.token_bytes(32)
                now = time.time()
                with self._lock:
                    # Prune expired challenges
                    expired = [k for k, v in self._challenges.items() if v[1] < now]
                    for k in expired:
                        del self._challenges[k]
                    self._challenges[challenge_id] = (base64.b64encode(challenge).decode(), now + 60)
                return {
                    "challenge_id": challenge_id,
                    "challenge": base64.b64encode(challenge).decode(),
                    "device_tag": tag,
                    "agent_port": self.agent_port,
                }
            except Exception as exc:
                return error_response(exc)

        @app.post("/api/auth/verify")
        async def auth_verify(request: Request):
            try:
                body = await request.json()
                tag = self._peer_tag(request)
                if body.get("device_tag") != tag:
                    raise PermissionError("device tag does not match VPN session")
                with self._lock:
                    record = self._challenges.pop(body.get("challenge_id"), None)
                if not record or record[1] < time.time():
                    raise PermissionError("challenge expired")
                challenge = base64.b64decode(record[0])
                directory_record = self.directory.get_by_tag(tag)
                signature = self._decode_b64(body["signature"])
                public_key = base64.b64decode(directory_record["public_key"])
                verify_device_signature(public_key, challenge, signature)
                response = JSONResponse({"device_tag": tag, "username": directory_record.get("username")})
                response.set_cookie(
                    "chat_session", self._make_cookie(tag),
                    httponly=True, samesite="strict", max_age=86400,
                )
                return response
            except Exception as exc:
                return error_response(exc)

        # ---- Profile ----------------------------------------------------- #

        @app.get("/api/me")
        async def me(request: Request):
            try:
                tag = self._authenticated_tag(request)
                return self.directory.get_by_tag(tag)
            except Exception as exc:
                return error_response(exc)

        @app.patch("/api/me/username")
        async def set_username(request: Request):
            try:
                tag = self._authenticated_tag(request)
                body = await request.json()
                self.directory.update_username(tag, str(body.get("username", "")))
                return self.directory.get_by_tag(tag)
            except Exception as exc:
                return error_response(exc)

        # ---- Directory --------------------------------------------------- #

        @app.get("/api/directory")
        async def directory(request: Request):
            try:
                self._authenticated_tag(request)
                values = []
                for record in self.directory.all_public():
                    peer = self.registry.get_by_tag(record["device_tag"])
                    values.append({
                        "device_tag": record["device_tag"],
                        "username": record.get("username"),
                        "public_key": record["public_key"],
                        "encryption_public_key": record.get("encryption_public_key", ""),
                        "online": peer is not None,
                    })
                return values
            except Exception as exc:
                return error_response(exc)

        # ---- General channel --------------------------------------------- #

        @app.post("/api/general")
        async def publish_general(request: Request):
            try:
                tag = self._authenticated_tag(request)
                body = await request.json()
                envelope = body["envelope"]
                self._validate_group_message_envelope(envelope)
                message = {
                    "message_id": uuid.uuid4().hex,
                    "sender_tag": tag,
                    "epoch": body.get("epoch"),
                    "envelope": envelope,
                    "created_at": time.time(),
                }
                self.bus.publish("chat-general", "general", message)
                self.bus.publish("network-events", tag, {
                    "event": "chat_general_published",
                    "device_tag": tag,
                    "message_id": message["message_id"],
                    "created_at": time.time(),
                })
                return {"message_id": message["message_id"]}
            except Exception as exc:
                return error_response(exc)

        @app.get("/api/history/general")
        async def general_history(request: Request):
            try:
                self._authenticated_tag(request)
                with self._lock:
                    return list(self._general_history)
            except Exception as exc:
                return error_response(exc)

        # ---- Private (1-on-1) messages ------------------------------------ #

        @app.post("/api/private")
        async def publish_private(request: Request):
            try:
                sender = self._authenticated_tag(request)
                body = await request.json()
                recipient = str(body["recipient_tag"])
                if not self.directory.get_by_tag(recipient):
                    raise ValueError("unknown recipient tag")
                envelope = body["envelope"]
                self._validate_envelope(envelope)
                message = {
                    "message_id": uuid.uuid4().hex,
                    "sender_tag": sender,
                    "recipient_tag": recipient,
                    "envelope": envelope,
                    "created_at": time.time(),
                }
                self.bus.publish("chat-private", recipient, message, flush=True)
                self.bus.publish(
                    "delivery-state",
                    f"{recipient}:{message['message_id']}",
                    {
                        "state": "pending",
                        "recipient_tag": recipient,
                        "message_id": message["message_id"],
                        "created_at": time.time(),
                    },
                    flush=True,
                )
                self.bus.publish("network-events", sender, {
                    "event": "chat_private_published",
                    "device_tag": sender,
                    "recipient_tag": recipient,
                    "message_id": message["message_id"],
                    "created_at": time.time(),
                })
                return {"message_id": message["message_id"]}
            except Exception as exc:
                return error_response(exc)

        @app.get("/api/pending")
        async def pending(request: Request):
            try:
                tag = self._authenticated_tag(request)
                with self._lock:
                    return list(self._pending.get(tag, {}).values())
            except Exception as exc:
                return error_response(exc)

        @app.post("/api/ack")
        async def ack(request: Request):
            try:
                tag = self._authenticated_tag(request)
                message_id = str((await request.json())["message_id"])
                self.bus.publish(
                    "delivery-state",
                    f"{tag}:{message_id}",
                    {
                        "state": "delivered",
                        "recipient_tag": tag,
                        "message_id": message_id,
                        "created_at": time.time(),
                    },
                    flush=True,
                )
                with self._lock:
                    self._delivered.add((tag, message_id))
                    self._pending[tag].pop(message_id, None)
                return {"ok": True}
            except Exception as exc:
                return error_response(exc)

        # ---- Named groups ------------------------------------------------- #

        @app.post("/api/groups/create")
        async def create_group(request: Request):
            try:
                admin_tag = self._authenticated_tag(request)
                body = await request.json()
                name = str(body.get("name", "")).strip()
                if not name or len(name) > 64:
                    raise ValueError("group name must be 1-64 characters")
                member_tags = list(body.get("member_tags", []))
                if admin_tag not in member_tags:
                    member_tags.append(admin_tag)
                # Validate all members exist
                for tag in member_tags:
                    if not self.directory.get_by_tag(tag):
                        raise ValueError(f"unknown member tag: {tag}")
                group_id = uuid.uuid4().hex
                group = {
                    "group_id": group_id,
                    "name": name,
                    "members": member_tags,
                    "admin_tag": admin_tag,
                    "created_at": time.time(),
                }
                self.bus.publish("group-directory", group_id, group, flush=True)
                with self._lock:
                    self._groups[group_id] = group
                self.bus.publish("network-events", admin_tag, {
                    "event": "group_created",
                    "group_id": group_id,
                    "name": name,
                    "created_at": time.time(),
                })
                return group
            except Exception as exc:
                return error_response(exc)

        @app.get("/api/groups")
        async def list_groups(request: Request):
            try:
                tag = self._authenticated_tag(request)
                with self._lock:
                    result = [g for g in self._groups.values() if tag in g.get("members", [])]
                return result
            except Exception as exc:
                return error_response(exc)

        @app.post("/api/groups/{group_id}/message")
        async def publish_group_message(group_id: str, request: Request):
            try:
                sender = self._authenticated_tag(request)
                with self._lock:
                    group = self._groups.get(group_id)
                if not group:
                    raise ValueError("unknown group")
                if sender not in group.get("members", []):
                    raise PermissionError("you are not a member of this group")
                body = await request.json()
                envelope = body["envelope"]
                self._validate_group_message_envelope(envelope)
                message = {
                    "message_id": uuid.uuid4().hex,
                    "group_id": group_id,
                    "sender_tag": sender,
                    "envelope": envelope,
                    "created_at": time.time(),
                }
                self.bus.publish("chat-groups", group_id, message)
                return {"message_id": message["message_id"]}
            except Exception as exc:
                return error_response(exc)

        @app.get("/api/groups/{group_id}/history")
        async def group_history(group_id: str, request: Request):
            try:
                tag = self._authenticated_tag(request)
                with self._lock:
                    group = self._groups.get(group_id)
                if not group:
                    raise ValueError("unknown group")
                if tag not in group.get("members", []):
                    raise PermissionError("you are not a member of this group")
                with self._lock:
                    return list(self._group_history.get(group_id, []))
            except Exception as exc:
                return error_response(exc)

        # ---- MLS (group key exchange) ------------------------------------- #

        @app.post("/api/mls/events")
        async def publish_mls_event(request: Request):
            try:
                tag = self._authenticated_tag(request)
                body = await request.json()
                event = body["event"]
                if not isinstance(event, dict) or len(json.dumps(event)) > 4_000_000:
                    raise ValueError("invalid MLS event")
                parent_epoch = int(body.get("parent_epoch", -1))
                with self._lock:
                    current_epoch = (
                        int(self._latest_mls_event.get("payload", {}).get("epoch", 0))
                        if self._latest_mls_event else 0
                    )
                if parent_epoch != current_epoch:
                    raise ValueError(f"stale MLS parent epoch; expected {current_epoch}")
                if (
                    event.get("kind") == "tree-group-state-v1"
                    and int(event.get("epoch", -1)) != current_epoch + 1
                ):
                    raise ValueError("MLS group event must advance exactly one epoch")
                event_record = {
                    "event": "mls_group_event",
                    "sender_tag": tag,
                    "group_id": body.get("group_id", "general"),
                    "parent_epoch": body.get("parent_epoch"),
                    "payload": event,
                    "created_at": time.time(),
                }
                self.bus.publish("mls-group-events", "general", event_record, flush=True)
                with self._lock:
                    self._latest_mls_event = event_record
                self.bus.publish("network-events", tag, {
                    "event": "mls_key_state_changed",
                    "device_tag": tag,
                    "parent_epoch": body.get("parent_epoch"),
                    "created_at": time.time(),
                })
                return {"ok": True}
            except Exception as exc:
                return error_response(exc)

        @app.post("/api/mls/key-package")
        async def publish_key_package(request: Request):
            try:
                tag = self._authenticated_tag(request)
                body = await request.json()
                package = body.get("package")
                if not isinstance(package, dict) or len(json.dumps(package)) > 1_000_000:
                    raise ValueError("invalid key package")
                record = {
                    "event": "key_package_published",
                    "device_tag": tag,
                    "package": package,
                    "created_at": time.time(),
                }
                self.bus.publish("mls-key-packages", tag, record, flush=True)
                self.bus.publish("network-events", tag, {
                    "event": "mls_key_package_changed",
                    "device_tag": tag,
                    "created_at": time.time(),
                })
                return {"ok": True}
            except Exception as exc:
                return error_response(exc)

        @app.get("/api/mls/state")
        async def mls_state(request: Request):
            try:
                self._authenticated_tag(request)
                with self._lock:
                    return self._latest_mls_event or {}
            except Exception as exc:
                return error_response(exc)

        # ---- File upload/download ---------------------------------------- #

        @app.post("/api/files/upload")
        async def upload_file(
            request: Request,
            file: UploadFile = File(...),
            metadata: str = Form("{}"),
        ):
            try:
                tag = self._authenticated_tag(request)
                meta = json.loads(metadata)
                if not isinstance(meta, dict):
                    raise ValueError("metadata must be a JSON object")
                data = await file.read()
                if len(data) > 64_000_000:
                    raise ValueError("file too large (max 64 MB encrypted)")
                key = f"uploads/{tag}/{uuid.uuid4().hex}"
                store = self._get_store()
                meta.update({"uploader_tag": tag, "original_filename": file.filename})
                download_url = store.upload(key, data, meta)
                return {"file_key": key, "download_url": download_url, "filename": file.filename}
            except Exception as exc:
                return error_response(exc)

        @app.get("/api/files/{file_key:path}")
        async def download_file(file_key: str, request: Request):
            try:
                self._authenticated_tag(request)
                store = self._get_store()
                url = store.presign(file_key)
                return RedirectResponse(url)
            except Exception as exc:
                return error_response(exc)

        # ---- WebSocket --------------------------------------------------- #

        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            tag = self._cookie_tag(websocket.cookies.get("chat_session"))
            if not tag or not self.directory.get_by_tag(tag):
                await websocket.close(code=4401)
                return
            await websocket.accept()
            loop = asyncio.get_running_loop()
            self.add_websocket(tag, websocket, loop)
            try:
                # Flush pending private messages on connect
                with self._lock:
                    pending_messages = list(self._pending.get(tag, {}).values())
                for message in pending_messages:
                    await websocket.send_json({"kind": "private", "message": message})
                while True:
                    incoming = await websocket.receive_json()
                    if incoming.get("kind") == "ack" and incoming.get("message_id"):
                        mid = incoming["message_id"]
                        self.bus.publish(
                            "delivery-state",
                            f"{tag}:{mid}",
                            {
                                "state": "delivered",
                                "recipient_tag": tag,
                                "message_id": mid,
                                "created_at": time.time(),
                            },
                            flush=True,
                        )
                        with self._lock:
                            self._delivered.add((tag, mid))
                            self._pending[tag].pop(mid, None)
            except WebSocketDisconnect:
                pass
            finally:
                self.remove_websocket(tag, websocket, loop)

        return app


def run_chat_service(service: ChatService, host: str, port: int):
    import uvicorn

    service.start_consumers()
    config = uvicorn.Config(service.create_app(), host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True, name="vpn1-chat-http")
    thread.start()
    return server, thread
