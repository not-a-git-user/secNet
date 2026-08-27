# VPN1 multi-peer VPN and chat

This project keeps the existing encrypted TUN data plane and adds a separate
Kafka-backed control/chat plane.

The server authenticates a device with its persistent Ed25519 private key,
assigns the device a stable `dev-...` tag, and allocates a new VPN address for
each active session.  A reconnect from a different public IP therefore keeps
the same tag while its VPN IP may change.

Chat messages are encrypted by the local client agent before they are sent to
the server.  Kafka stores and routes opaque ciphertext; it is not used for
raw VPN packets.  `chat-general` carries group ciphertext, `chat-private`
carries recipient-tagged ciphertext, and `network-events` carries VPN/chat
control events.  The compacted topics retain the device directory and delivery
state across restarts.

## Kafka setup

Copy the example configuration and set a strong, stable session secret:

```sh
cp chat/kafka/chat.env.example chat/kafka/chat.env
chmod 600 chat/kafka/chat.env
vi chat/kafka/chat.env
set -a; . chat/kafka/chat.env; set +a
```

For a local Kafka installation, `KAFKA_BOOTSTRAP_SERVERS` is usually
`localhost:9092`.  For a secured broker, also set the SASL/SSL variables shown
in `chat/kafka/chat.env.example`.

Create the topics from the machine that has Kafka's topic CLI:

```sh
KAFKA_TOPICS_BIN=/opt/kafka/bin/kafka-topics.sh bash chat/kafka/create-topics.sh
```

The script creates the required `chat-general`, `chat-private`, and
`network-events` topics, compacted `device-directory`, `delivery-state`, and
`mls-key-packages` state topics, and an append-only `mls-group-events` topic.

The chat service rebuilds its pending-message, delivery, and group-epoch
materialized views by replaying Kafka whenever it starts, so those views do
not depend on a local database.

Install the Python dependencies on the VPN hosts:

```sh
python3 -m pip install -r requirements.txt
```

## Run on EC2

The VPN listener can remain on the public TLS-friendly port 443.  The chat
HTTP service binds to the VPN server address, so it is reached through the
VPN at `http://10.0.0.1:8080`; it does not need a public security-group rule.

On the server:

```sh
set -a; . /path/to/vpn1/chat/kafka/chat.env; set +a
sudo -E python3 server.py --port 443 --chat-port 8080 --debug
```

On each Linux client, preserve the device key path between runs:

```sh
sudo -E python3 client.py \
  --host <ec2-public-ip-or-dns> --port 443 \
  --device-key ~/.vpn1/device-ed25519.key
```

After the TUN interface is up, open `http://10.0.0.1:8080`.  The browser asks
the local `chat.chat_agent` process to sign the login challenge and perform
encryption/decryption; the private keys are not placed in browser storage.

## Key management and chat behavior

Private messages are addressed by the stable device tag, not by username.
Kafka retains private ciphertext until the recipient acknowledges delivery;
the recipient can therefore reconnect with a new public IP and retrieve old
messages.  Usernames are profile metadata and may be changed without changing
device identity.

The current agent implements the project's versioned TreeKEM-style group
envelope (`tree-group-state-v1`): a fresh group key is wrapped to each
authenticated member's X25519 device key and stored locally after unwrap.  The
server validates epochs and relays the opaque group event.  The envelope is
deliberately versioned so an RFC 9420/OpenMLS agent can replace the group-state
provider without changing the VPN or Kafka APIs.

For production deployment, protect the Kafka listener, use TLS/SASL, restrict
the chat HTTP service to the VPN interface, and back up each client's device
key securely.  Losing a device key creates a new device identity by design.
