"""Categoria 3 - Testes de Seguranca Web."""

from stg.connectors.web.burp import BurpConnector
from stg.connectors.web.sqlmap import SqlmapConnector
from stg.connectors.web.zap import ZapConnector

CONNECTORS = [ZapConnector, SqlmapConnector, BurpConnector]

__all__ = ["CONNECTORS", "ZapConnector", "SqlmapConnector", "BurpConnector"]
