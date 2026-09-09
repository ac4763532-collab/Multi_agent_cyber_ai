"""Programmatic Kafka / Redpanda topic creator and verification script."""

import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.config.settings import get_settings
from backend.app.core.broker import KafkaTopic, get_broker_manager


async def main() -> None:
    print("=" * 60)
    print("Multi-Agent Cyber AI - Topic Initialization")
    print("=" * 60)

    settings = get_settings()
    print(f"[*] Target Broker: {settings.kafka_bootstrap_servers}")

    topics = KafkaTopic.list_all()
    print(f"[*] Registered Platform Topics ({len(topics)}):")
    for t in topics:
        print(f"    - {t}")

    broker = get_broker_manager()
    is_healthy, latency, details = await broker.check_broker_health()

    if is_healthy:
        print(f"\n[OK] Broker is ONLINE (Latency: {latency:.2f}ms)")
        print(f"[+] Broker Details: {details}")
    else:
        print(f"\n[!] Broker is OFFLINE: {details.get('error', 'Connection refused')}")
        print("[*] Note: Start Redpanda or Kafka container to activate live topic streaming.")


if __name__ == "__main__":
    asyncio.run(main())
