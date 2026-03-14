#!/bin/bash
# kafka-topics.sh — Run after docker compose up to create all project topics

KAFKA_CONTAINER="kafka"
BOOTSTRAP="localhost:9092"

echo "⏳ Waiting for Kafka to be ready..."
until docker exec $KAFKA_CONTAINER kafka-broker-api-versions --bootstrap-server $BOOTSTRAP &>/dev/null; do
  sleep 3
  echo "   still waiting..."
done

echo "✅ Kafka is up. Creating topics..."

TOPICS=(
  "raw.network.events"
  "raw.logs"
  "raw.user.events"
  "raw.vuln.events"
  "alerts.network"
  "alerts.logs"
  "alerts.ueba"
  "alerts.vuln"
  "threats.classified"
  "actions.taken"
)

for TOPIC in "${TOPICS[@]}"; do
  docker exec $KAFKA_CONTAINER kafka-topics \
    --bootstrap-server $BOOTSTRAP \
    --create \
    --if-not-exists \
    --topic "$TOPIC" \
    --partitions 3 \
    --replication-factor 1
  echo "   ✔ $TOPIC"
done

echo ""
echo "📋 All topics created. Listing:"
docker exec $KAFKA_CONTAINER kafka-topics --bootstrap-server $BOOTSTRAP --list
