#!/usr/bin/env python3
"""Check if threats were indexed"""
import sys
from shared.utils.es_client import get_es_client

try:
    es = get_es_client()
    result = es.search(index='cyberdefense-threats', size=10, body={"query": {"match_all": {}}})
    total = result['hits']['total'].get('value', 0)
    
    print("=" * 70)
    print(f"📊 THREATS INDEXED: {total}")
    print("=" * 70)
    if total > 0:
        for hit in result['hits']['hits'][:5]:
            src = hit['_source']
            print(f"  • {src.get('threat_type', '?'):20} | Severity: {src.get('severity', '?'):10} | Score: {src.get('compound_score', 0):.1f}")
        print("=" * 70)
        print("✅ Orchestrator is processing alerts!")
    else:
        print("⚠️  No threats indexed yet (might still be processing...)")
        print("=" * 70)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
