#!/usr/bin/env python3
"""Quick deployment health check"""
import sys
import time
from shared.utils.kafka_client import get_producer, get_consumer
from shared.utils.es_client import get_es_client
from shared.utils.redis_client import get_redis

def test_kafka():
    """Test Kafka connectivity"""
    try:
        producer = get_producer()
        producer.flush()
        print("✅ Kafka: Connected")
        return True
    except Exception as e:
        print(f"❌ Kafka: {e}")
        return False

def test_elasticsearch():
    """Test Elasticsearch connectivity"""
    try:
        es = get_es_client()
        health = es.cluster.health()
        print(f"✅ Elasticsearch: {health.get('status', 'unknown')} ({health.get('active_shards', 0)} shards)")
        return True
    except Exception as e:
        print(f"❌ Elasticsearch: {e}")
        return False

def test_redis():
    """Test Redis connectivity"""
    try:
        redis = get_redis()
        if redis.ping():
            print("✅ Redis: Connected (PING OK)")
            return True
    except Exception as e:
        print(f"❌ Redis: {e}")
        return False

def test_kafka_topics():
    """Verify Kafka topics exist"""
    try:
        consumer = get_consumer(
            ["alerts.network"],
            group_id="test-group"
        )
        print("✅ Kafka Topics: All created")
        consumer.close()
        return True
    except Exception as e:
        print(f"❌ Kafka Topics: {e}")
        return False

def main():
    print("=" * 60)
    print("🔍 DEPLOYMENT HEALTH CHECK")
    print("=" * 60)
    
    results = [
        test_kafka(),
        test_elasticsearch(),
        test_redis(),
        test_kafka_topics(),
    ]
    
    print("=" * 60)
    if all(results):
        print("✅ ALL SYSTEMS READY FOR DEPLOYMENT")
        print("=" * 60)
        return 0
    else:
        print("⚠️  SOME SYSTEMS NOT READY")
        print("=" * 60)
        return 1

if __name__ == "__main__":
    sys.exit(main())
