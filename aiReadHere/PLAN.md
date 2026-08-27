# secNet — Implementation Plan

## What This Accomplishes

Completes the project into a fully working secure network with:
- A working chat system (named groups, one-on-one DMs, file attachments/downloads)
- Cloud file storage: **S3** (implemented) + **Azure Blob** (implemented) + **GCP stub** + **R2 stub**
- A clean, minimal browser UI — no framework, plain HTML/JS
- Deployment to EC2 under a new `secNet/` folder, via GitHub

---

## Architecture Overview

```
[Client Machine]
  client.py           — VPN client, Ed25519 device auth, spawns chat agent
  chat/chat_agent.py  — loopback HTTP crypto agent (keys never leave device)
  chat/web/           — browser UI (plain HTML/JS)

[EC2 Server]
  server.py           — multi-peer VPN server, TUN routing, NAT
  chat/chat_service.py— FastAPI HTTP+WS chat server (envelopes opaque)
  chat/kafka_backend.py — Kafka producer/consumer abstraction
  Kafka               — 9 topics for persistence, delivery, group state

[Cloud Storage]
  chat/storage/s3_store.py    — AWS S3 (boto3, presigned URLs)     ✅ DONE
  chat/storage/azure_store.py — Azure Blob (SAS URLs)              ✅ DONE
  chat/storage/gcp_store.py   — GCP Cloud Storage                  🔲 STUB
  chat/storage/r2_store.py    — Cloudflare R2 (S3-compatible)      🔲 STUB
```

---

## Cloud Storage Backends

| Backend | Status | Env Vars Needed |
|---|---|---|
| AWS S3 | ✅ Implemented | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `S3_BUCKET_NAME` |
| Azure Blob | ✅ Implemented | `AZURE_STORAGE_CONNECTION_STRING`, `AZURE_CONTAINER_NAME` |
| GCP Cloud Storage | 🔲 Stub (NotImplementedError) | `GOOGLE_APPLICATION_CREDENTIALS`, `GCP_BUCKET_NAME` |
| Cloudflare R2 | 🔲 Stub (NotImplementedError) | `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME` |

Set `FILE_STORE_BACKEND=s3` or `FILE_STORE_BACKEND=azure` in your `.env`.

---

## Kafka Topics

| Topic | Partitions | Policy | Purpose |
|---|---|---|---|
| `chat-general` | 1 | delete | Global channel messages |
| `chat-private` | 12 | delete | 1-on-1 DM messages |
| `chat-groups` | 12 | delete | Named group messages |
| `network-events` | 3 | delete (90d) | Audit log |
| `device-directory` | 3 | compact | Persistent device identity |
| `delivery-state` | 12 | compact | DM delivery tracking |
| `mls-key-packages` | 12 | compact | Key packages |
| `mls-group-events` | 1 | delete | General group key epochs |
| `group-directory` | 3 | compact | Named group metadata |

---

## API Endpoints

### Auth
- `GET /api/auth/challenge` — issue challenge
- `POST /api/auth/verify` — verify Ed25519 signature, set session cookie

### Profile
- `GET /api/me` — own device info
- `PATCH /api/me/username` — set display name

### Directory
- `GET /api/directory` — all devices with online/offline status

### General Channel
- `POST /api/general` — send encrypted message
- `GET /api/history/general` — last 1000 messages

### Private (DM)
- `POST /api/private` — send encrypted DM
- `GET /api/pending` — undelivered DMs
- `POST /api/ack` — acknowledge delivery

### Named Groups
- `POST /api/groups/create` — create group `{name, member_tags[]}`
- `GET /api/groups` — list groups this device is a member of
- `POST /api/groups/{id}/message` — send encrypted group message
- `GET /api/groups/{id}/history` — last 200 messages

### File Storage
- `POST /api/files/upload` — multipart upload (encrypted blob from client)
- `GET /api/files/{key}` — presigned redirect to object store

### MLS / Group Key Exchange
- `POST /api/mls/events` — publish group key epoch update
- `POST /api/mls/key-package` — store key package
- `GET /api/mls/state` — latest general group state

### WebSocket
- `WS /ws` — real-time push for general, private, group, and MLS messages

---

## Crypto Agent Endpoints (local, port 48271)

| Endpoint | Description |
|---|---|
| `GET /v1/status` | Device public keys |
| `POST /v1/sign` | Ed25519 sign challenge |
| `POST /v1/direct/encrypt` | X25519 + ChaCha20 DM encrypt |
| `POST /v1/direct/decrypt` | X25519 + ChaCha20 DM decrypt |
| `POST /v1/group/encrypt` | Group key encrypt (any group_id) |
| `POST /v1/group/decrypt` | Group key decrypt |
| `POST /v1/group/create-state` | Generate group key, wrap to all members |
| `POST /v1/group/install-state` | Unwrap own group key from state envelope |
| `POST /v1/file/encrypt` | Encrypt file with group key |
| `POST /v1/file/decrypt` | Decrypt file with group key |

---

## Deployment

### EC2 Pull
```bash
git clone https://github.com/not-a-git-user/secNet.git ~/secNet
cd ~/secNet
pip install -r requirements.txt
cp chat/kafka/chat.env.example .env
# Edit .env with your Kafka host, session secret, and S3/Azure credentials
```

### Run Server
```bash
source .env
sudo python server.py --host 0.0.0.0 --port 51820 --chat-port 8080 \
  --kafka-bootstrap $KAFKA_BOOTSTRAP_SERVERS
```

### Run Client
```bash
python client.py --host <EC2_PUBLIC_IP> --port 51820 --chat-port 8080
# Then open http://<vpn-gateway-ip>:8080 in browser
```

---

## Open Items / Pending Actions

See `STATUS.md` in this folder for the detailed current status.
