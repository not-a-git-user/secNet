#!/usr/bin/env bash
set -euo pipefail

: "${KAFKA_BOOTSTRAP_SERVERS:?Set KAFKA_BOOTSTRAP_SERVERS to the broker host:port}"
KAFKA_TOPICS_BIN="${KAFKA_TOPICS_BIN:-kafka-topics.sh}"
REPLICATION_FACTOR="${KAFKA_REPLICATION_FACTOR:-1}"

create_topic() {
  local name="$1"
  local partitions="$2"
  local policy="$3"
  local retention="$4"
  "$KAFKA_TOPICS_BIN" \
    --bootstrap-server "$KAFKA_BOOTSTRAP_SERVERS" \
    --create --if-not-exists \
    --topic "$name" \
    --partitions "$partitions" \
    --replication-factor "$REPLICATION_FACTOR" \
    --config "cleanup.policy=$policy" \
    --config "retention.ms=$retention"
}

# Required application/control topics.
create_topic chat-general 1 delete -1
create_topic chat-private "${CHAT_PRIVATE_PARTITIONS:-12}" delete -1
create_topic network-events 3 delete "${NETWORK_EVENTS_RETENTION_MS:-7776000000}"

# Kafka-only materialized state and MLS delivery artifacts.
create_topic device-directory 3 compact "${STATE_RETENTION_MS:--1}"
create_topic delivery-state "${DELIVERY_STATE_PARTITIONS:-12}" compact "${STATE_RETENTION_MS:--1}"
create_topic mls-key-packages "${MLS_KEY_PACKAGE_PARTITIONS:-12}" compact "${STATE_RETENTION_MS:--1}"
create_topic mls-group-events 1 delete -1

# Named group support.
create_topic group-directory 3 compact "${STATE_RETENTION_MS:--1}"
create_topic chat-groups "${CHAT_GROUPS_PARTITIONS:-12}" delete -1

echo "secNet chat topics are ready on $KAFKA_BOOTSTRAP_SERVERS"
