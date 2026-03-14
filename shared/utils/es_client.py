"""
Elasticsearch client wrapper — used by agents to index alerts.
"""
import os
from elasticsearch import Elasticsearch
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")


def get_es_client() -> Elasticsearch:
    return Elasticsearch(ES_HOST, api_key=None)


def index_event(es: Elasticsearch, index: str, event: dict) -> None:
    res = es.index(index=index, document=event)
    logger.debug(f"Indexed to {index}: {res['result']}")
