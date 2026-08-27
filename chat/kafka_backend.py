"""Kafka transport and compacted device-directory state."""

from __future__ import annotations

import base64
import os
import threading
import time
import uuid

from chat.identity import _tag_from_random


def _json_bytes(value: dict) -> bytes:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _json_load(value: bytes) -> dict:
    import json

    decoded = json.loads(value.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("Kafka record must contain a JSON object")
    return decoded


class KafkaConfig:
    def __init__(self, values: dict[str, str]):
        self.values = values

    @classmethod
    def from_env(cls) -> "KafkaConfig":
        values = {
            "bootstrap.servers": os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
            "client.id": os.environ.get("KAFKA_CLIENT_ID", "vpn1-chat"),
        }
        mapping = {
            "KAFKA_SECURITY_PROTOCOL": "security.protocol",
            "KAFKA_SASL_MECHANISM": "sasl.mechanism",
            "KAFKA_SASL_USERNAME": "sasl.username",
            "KAFKA_SASL_PASSWORD": "sasl.password",
            "KAFKA_SSL_CA_LOCATION": "ssl.ca.location",
            "KAFKA_SSL_CERTIFICATE_LOCATION": "ssl.certificate.location",
            "KAFKA_SSL_KEY_LOCATION": "ssl.key.location",
        }
        for environment_name, config_name in mapping.items():
            if os.environ.get(environment_name):
                values[config_name] = os.environ[environment_name]
        return cls(values)


class KafkaUnavailable(RuntimeError):
    pass


class KafkaBus:
    def __init__(self, config: KafkaConfig | None = None):
        try:
            from confluent_kafka import Consumer, KafkaError, Producer
        except ImportError as exc:
            raise KafkaUnavailable(
                "confluent-kafka is required; install requirements.txt and configure "
                "KAFKA_BOOTSTRAP_SERVERS"
            ) from exc
        self._Producer = Producer
        self._Consumer = Consumer
        self._KafkaError = KafkaError
        self.config = config or KafkaConfig.from_env()
        producer_config = dict(self.config.values)
        producer_config.update({"acks": "all", "enable.idempotence": True})
        self.producer = Producer(producer_config)

    def publish(
        self,
        topic: str,
        key: str,
        value: dict,
        headers: dict[str, str] | None = None,
        flush: bool = False,
    ):
        kafka_headers = None
        if headers:
            kafka_headers = [(name, val.encode("utf-8")) for name, val in headers.items()]
        self.producer.produce(
            topic,
            key=key.encode("utf-8"),
            value=_json_bytes(value),
            headers=kafka_headers,
        )
        self.producer.poll(0)
        if flush:
            self.producer.flush(10)

    def consumer(self, group_id: str, topics: list[str], auto_offset_reset="earliest"):
        consumer_config = dict(self.config.values)
        consumer_config.update(
            {
                "group.id": group_id,
                "enable.auto.commit": False,
                "enable.partition.eof": True,
                "auto.offset.reset": auto_offset_reset,
            }
        )
        consumer = self._Consumer(consumer_config)
        consumer.subscribe(topics)
        return consumer

    @staticmethod
    def decode(record) -> tuple[str, dict]:
        key = record.key().decode("utf-8") if record.key() else ""
        return key, _json_load(record.value())


class KafkaDeviceDirectory:
    """Kafka-backed device directory with an in-memory materialized view."""

    def __init__(self, bus: KafkaBus, topic="device-directory"):
        self.bus = bus
        self.topic = topic
        self._records_by_id: dict[str, dict] = {}
        self._records_by_tag: dict[str, dict] = {}
        self._lock = threading.RLock()
        self._load_snapshot()

    def _load_snapshot(self):
        consumer = self.bus.consumer(
            f"vpn1-directory-rebuild-{uuid.uuid4().hex}", [self.topic], "earliest"
        )
        assigned = False
        quiet_since = None
        try:
            while True:
                record = consumer.poll(1.0)
                if not assigned and consumer.assignment():
                    assigned = True
                if record is None:
                    if assigned and quiet_since is None:
                        quiet_since = time.monotonic()
                    if assigned and quiet_since is not None and time.monotonic() - quiet_since > 2:
                        break
                    continue
                if record.error():
                    if record.error().code() == self.bus._KafkaError._PARTITION_EOF:
                        assigned = True
                        if quiet_since is None:
                            quiet_since = time.monotonic()
                        continue
                    raise RuntimeError(record.error())
                assigned = True
                quiet_since = None
                _, value = self.bus.decode(record)
                self._apply(value)
        finally:
            consumer.close()

    def _apply(self, record: dict):
        device_id = record["device_id"]
        device_tag = record["device_tag"]
        with self._lock:
            previous = self._records_by_id.get(device_id)
            if previous:
                self._records_by_tag.pop(previous["device_tag"], None)
            previous_tag_record = self._records_by_tag.get(device_tag)
            if previous_tag_record and previous_tag_record["device_id"] != device_id:
                raise ValueError("device tag collision in compacted device directory")
            self._records_by_id[device_id] = record
            self._records_by_tag[device_tag] = record

    def register_or_get(self, public_key_bytes: bytes, encryption_public_key: bytes | None = None) -> str:
        device_id = __import__("hashlib").sha256(public_key_bytes).hexdigest()
        with self._lock:
            existing = self._records_by_id.get(device_id)
            if existing:
                encoded_encryption_key = base64.b64encode(
                    encryption_public_key or b""
                ).decode("ascii")
                if (
                    encryption_public_key
                    and existing.get("encryption_public_key", "")
                    != encoded_encryption_key
                ):
                    record = dict(existing)
                    record["encryption_public_key"] = encoded_encryption_key
                    record["event"] = "device_encryption_key_changed"
                    record["updated_at"] = time.time()
                    self._apply(record)
                    self.bus.publish(self.topic, device_id, record, flush=True)
                    existing = record
                return existing["device_tag"]
            record = {
                "event": "device_registered",
                "device_id": device_id,
                "device_tag": _tag_from_random(),
                "public_key": base64.b64encode(public_key_bytes).decode("ascii"),
                "encryption_public_key": base64.b64encode(encryption_public_key or b"").decode("ascii"),
                "username": None,
                "updated_at": time.time(),
            }
            self._apply(record)
        self.bus.publish(self.topic, device_id, record, flush=True)
        return record["device_tag"]

    def update_username(self, device_tag: str, username: str):
        username = username.strip()
        if not 1 <= len(username) <= 64:
            raise ValueError("username must contain 1 to 64 characters")
        with self._lock:
            current = self._records_by_tag.get(device_tag)
            if not current:
                raise KeyError(device_tag)
            record = dict(current)
            record.update({"event": "username_changed", "username": username, "updated_at": time.time()})
            self._apply(record)
            self.bus.publish(self.topic, record["device_id"], record, flush=True)

    def get_by_tag(self, device_tag: str) -> dict | None:
        with self._lock:
            value = self._records_by_tag.get(device_tag)
            return dict(value) if value else None

    def get_by_id(self, device_id: str) -> dict | None:
        with self._lock:
            value = self._records_by_id.get(device_id)
            return dict(value) if value else None

    def all_public(self) -> list[dict]:
        with self._lock:
            return [dict(record) for record in self._records_by_id.values()]
