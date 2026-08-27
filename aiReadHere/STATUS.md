# secNet — Current Status

Last updated: 2026-08-27

---

## ✅ Completed

### Core VPN
- [x] Multi-peer encrypted TUN — server routes packets between N clients
- [x] ECDH (SECP256R1), DH-chain (3× X25519), TreeKEM (two-party), Chained-KDF, RSA-OAEP, ML-KEM-768 key exchange modes
- [x] AES-256-GCM and ChaCha20-Poly1305 session ciphers with replay protection (sequence number AAD)
- [x] Ed25519 device authentication (post-handshake, transcript-bound)
- [x] Persistent device identity (`~/.vpn1/device-ed25519.key`)
- [x] Stable `dev-...` tag across reconnects
- [x] iptables NAT + full-tunnel routing (0.0.0.0/1 + 128.0.0.0/1)
- [x] Anti-spoof egress filter on client
- [x] `conntrack -F` flush on connect to prevent spoofed source issues

### Kafka Backend
- [x] 9 topics created: `chat-general`, `chat-private`, `chat-groups`, `network-events`, `device-directory`, `delivery-state`, `mls-key-packages`, `mls-group-events`, `group-directory`
- [x] Idempotent Kafka producer (`acks=all`, `enable.idempotence=True`)
- [x] Compacted topics for durable device directory and delivery state
- [x] `KafkaDeviceDirectory` — stable device tag assignment, username updates
- [x] Network events audit log

### Chat — Server (`chat/chat_service.py`)
- [x] FastAPI HTTP + WebSocket server
- [x] Cookie-based session auth (HMAC-SHA256 signed, 24h expiry) — **bug fixed** (deprecated `hmac.new` → `hmac.HMAC`)
- [x] Challenge-response device authentication with **expiry pruning** (no longer grows unboundedly)
- [x] General channel: send, receive, last 1000 history via `GET /api/history/general`
- [x] Private (DM): send, offline delivery via Kafka, ack tracking
- [x] **Named groups**: create, list membership, send group messages, last 200 message history
- [x] **File upload/download**: multipart upload to object store, presigned redirect for download
- [x] WebSocket real-time push for: general, private, group, and MLS messages
- [x] Pending DM flush on WebSocket connect

### Chat — Crypto Agent (`chat/chat_agent.py`)
- [x] Local loopback HTTP server — browser never touches private keys
- [x] Ed25519 signing for auth challenges
- [x] X25519 + ChaCha20-Poly1305 for DM encryption (ephemeral keys)
- [x] **Named group support**: per-group key states, each persisted to disk separately
- [x] **Group file encryption/decryption**: `POST /v1/file/encrypt`, `POST /v1/file/decrypt`
- [x] Full backwards-compat with old `/v1/general/*` paths

### Cloud Storage (`chat/storage/`)
- [x] Abstract `ObjectStore` interface (`base.py`)
- [x] **AWS S3** — `boto3`, presigned GET URLs (1h expiry) (`s3_store.py`)
- [x] **Azure Blob Storage** — `azure-storage-blob`, SAS URLs (1h expiry) (`azure_store.py`)
- [x] **GCP Cloud Storage** — stub with clear TODO + instructions (`gcp_store.py`)
- [x] **Cloudflare R2** — stub with note that R2 uses S3-compatible boto3 API (`r2_store.py`)
- [x] `get_store()` factory reads `FILE_STORE_BACKEND` env var

### Chat UI (`chat/web/`)
- [x] **3-column layout**: sidebar (channels + DMs) | chat area | directory panel
- [x] Channel switching: general, named groups, DMs — each with separate message history
- [x] **Group creation modal**: name input + member checkboxes
- [x] **File attach**: encrypt client-side → upload encrypted blob → send file reference in chat
- [x] **File download**: fetch from object store → decrypt client-side → browser download
- [x] Click user in directory to open DM
- [x] History loaded on channel open
- [x] Auto-refresh directory every 15s
- [x] Username set via Enter key in sidebar profile bar
- [x] Basic dark monospace UI — no CSS frameworks

### Deployment
- [x] GitHub repo: **https://github.com/not-a-git-user/secNet** (public)
- [x] Local copy: `/home/amrit/Documents/secNet/`
- [x] All 32 files pushed (clean initial commit)

---

## 🔲 Not Done / Remaining

### Must-Do Before Production

| Item | Notes |
|---|---|
| **EC2 pull** | Run `git clone https://github.com/not-a-git-user/secNet.git ~/secNet` on EC2. **Pending user action.** |
| **S3 bucket creation** | Need user approval to touch AWS console. Create bucket + IAM user with `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject`. |
| **Azure container** | Need Azure Storage account + connection string from user. |
| **Fill `.env` on EC2** | Copy `chat/kafka/chat.env.example` → `.env`, fill in Kafka host, `CHAT_SESSION_SECRET`, S3/Azure creds. |
| **Kafka topic creation on EC2** | Run `bash chat/kafka/create-topics.sh` after setting `KAFKA_BOOTSTRAP_SERVERS`. Adds `group-directory` and `chat-groups` if Kafka is already running. |

### Cloud Backends (Stubs)

| Item | Effort | Notes |
|---|---|---|
| **GCP Cloud Storage** | ~50 lines | `pip install google-cloud-storage`, implement `GCPStore` using `google.cloud.storage.Client`. Skeleton is in `gcp_store.py`. |
| **Cloudflare R2** | ~10 lines | R2 is S3-compatible — just copy `s3_store.py`, change `endpoint_url` to `https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com`. Skeleton in `r2_store.py`. |

### Chat Features (Nice-to-Have)

| Item | Notes |
|---|---|
| **Auto-reconnect on client disconnect** | `client.py` exits on VPN disconnect. Add retry loop. |
| **Group key distribution to new members** | When a new member joins an existing group, the admin needs to re-issue the group state. Currently manual (click "Refresh group" / re-init). |
| **Message timestamps** | UI shows messages without timestamps — easy to add. |
| **Notification on incoming message** | Browser Notifications API — one event listener on WebSocket push. |
| **Private message history** | DM history not persisted across browser sessions (only real-time + pending at connect). |
| **MLS key package auto-publish** | Agent doesn't auto-publish a key package on startup. |
| **Pagination** | General history capped at 1000 in memory; no cursor-based API. |

### Security Hardening

| Item | Notes |
|---|---|
| **Server certificate / MitM prevention** | Handshake provides session confidentiality but no server cert. Active MitM against server-to-client still possible. Needs TLS or a TOFU pin store. |
| **Rate limiting** | No rate limiting on auth challenges, message publish, or file upload. |
| **File size enforcement** | Server enforces 64 MB, but no per-user quota. |

### Infrastructure

| Item | Notes |
|---|---|
| **Spot instances / serverless scaling** | EC2 is a static single node. No Lambda, autoscaling, or spot lifecycle handling. |
| **macOS/Windows TUN** | `tun.py` is Linux-only (`ioctl(TUNSETIFF)`). |

---

## File Map

```
secNet/
├── aiReadHere/
│   ├── PLAN.md          ← Implementation plan (API, architecture, deployment)
│   └── STATUS.md        ← This file
├── chat/
│   ├── chat_agent.py    ← Crypto agent (UPDATED: named groups, file encrypt)
│   ├── chat_service.py  ← HTTP/WS server (UPDATED: groups, files, bug fixes)
│   ├── identity.py      ← Ed25519 + X25519 device identity
│   ├── kafka_backend.py ← Kafka producer/consumer abstraction
│   ├── storage/
│   │   ├── __init__.py  ← get_store() factory [NEW]
│   │   ├── base.py      ← ObjectStore abstract interface [NEW]
│   │   ├── s3_store.py  ← AWS S3 backend [NEW]
│   │   ├── azure_store.py ← Azure Blob backend [NEW]
│   │   ├── gcp_store.py ← GCP stub [NEW]
│   │   └── r2_store.py  ← R2 stub [NEW]
│   ├── web/
│   │   ├── index.html   ← UI shell (UPDATED: 3-col layout, modals)
│   │   └── app.js       ← Client JS (UPDATED: full rewrite)
│   └── kafka/
│       ├── create-topics.sh  ← (UPDATED: +group-directory, +chat-groups)
│       └── chat.env.example  ← (UPDATED: +S3, +Azure, +GCP, +R2 vars)
├── client.py            ← VPN client
├── server.py            ← VPN server
├── handshake.py         ← Key exchange + session handshake
├── packet_manager.py    ← TUN routing, NAT, peer registry
├── encryptDecrypt.py    ← AES-256-GCM + ChaCha20-Poly1305
├── tun.py               ← Linux TUN device
├── protocol.py          ← Wire framing (length-prefixed JSON)
└── requirements.txt     ← (UPDATED: +boto3, +azure-storage-blob, +python-multipart)
```
