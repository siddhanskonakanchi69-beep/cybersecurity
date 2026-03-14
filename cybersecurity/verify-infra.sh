#!/bin/bash
# verify-infra.sh — Checks Kibana, Elasticsearch, Kafka, and Redis are all live

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✅ $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; }
info() { echo -e "${YELLOW}ℹ  $1${NC}"; }

echo "========================================"
echo "  CyberDefense Infra Health Check"
echo "========================================"

# 1. Elasticsearch
info "Checking Elasticsearch (port 9200)..."
ES_STATUS=$(curl -fsSL http://localhost:9200/_cluster/health 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['status'])" 2>/dev/null)
if [[ "$ES_STATUS" == "green" || "$ES_STATUS" == "yellow" ]]; then
  pass "Elasticsearch is healthy (status: $ES_STATUS)"
else
  fail "Elasticsearch not reachable or unhealthy"
fi

# 2. Kibana
info "Checking Kibana (port 5601)..."
KIBANA=$(curl -fsSL http://localhost:5601/api/status 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['status']['overall']['level'])" 2>/dev/null)
if [[ "$KIBANA" == "available" ]]; then
  pass "Kibana is available"
else
  fail "Kibana not ready yet (may still be starting)"
fi

# 3. Kafka
info "Checking Kafka (port 9092)..."
if docker exec kafka kafka-broker-api-versions --bootstrap-server localhost:9092 &>/dev/null; then
  pass "Kafka broker is responding"
  TOPIC_COUNT=$(docker exec kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null | wc -l)
  pass "Kafka topics found: $TOPIC_COUNT"
else
  fail "Kafka not reachable"
fi

# 4. Redis
info "Checking Redis (port 6379)..."
REDIS_PONG=$(docker exec redis redis-cli ping 2>/dev/null)
if [[ "$REDIS_PONG" == "PONG" ]]; then
  pass "Redis ping → PONG"
else
  fail "Redis not responding"
fi

echo ""
echo "========================================"
echo "  Open Kibana: http://localhost:5601"
echo "  Open Kafka UI: http://localhost:8080"
echo "========================================"
