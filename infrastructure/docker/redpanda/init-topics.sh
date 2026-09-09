#!/bin/sh
set -e

echo "============================================================"
echo "Initializing Redpanda Kafka Event Streaming Topics"
echo "============================================================"

REDPANDA_BROKER=${KAFKA_BROKER:-redpanda:9092}

echo "[*] Waiting for Redpanda broker at ${REDPANDA_BROKER} to become ready..."
until rpk cluster info --brokers "${REDPANDA_BROKER}" > /dev/null 2>&1; do
    echo "[*] Waiting for Redpanda broker..."
    sleep 2
done

echo "[+] Redpanda cluster is healthy. Creating topics..."

TOPICS="security-events agent-tasks agent-results correlations incidents alerts dead-letter"

for topic in $TOPICS; do
    echo "[+] Creating topic: ${topic}"
    rpk topic create "${topic}" --brokers "${REDPANDA_BROKER}" --partitions 3 --replicas 1 || true
done

echo "[✓] All event streaming topics successfully initialized!"
rpk topic list --brokers "${REDPANDA_BROKER}"
