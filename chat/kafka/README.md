# Kafka setup

The server expects an existing Kafka broker. Copy `chat.env.example` to an
environment file on the EC2 host, fill in the broker address and session
secret, then export it before starting the VPN server.

```bash
set -a
source chat/kafka/chat.env
set +a
export KAFKA_BOOTSTRAP_SERVERS='<EC2_KAFKA_PRIVATE_HOST>:9092'
bash chat/kafka/create-topics.sh
```

For a single-broker development installation, leave
`KAFKA_REPLICATION_FACTOR=1`. Use the broker's normal TLS/SASL settings in
`chat.env` for production; do not expose Kafka's listener to the public
Internet.

The message topics retain ciphertext indefinitely by default so offline
private delivery can be replayed after a server restart. Plan disk capacity or
set an explicit retention policy if the deployment has a finite storage
budget.
