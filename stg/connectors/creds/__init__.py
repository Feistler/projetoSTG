"""Categoria 4 - Palavras-passe & Autenticacao."""

from stg.connectors.creds.hashcat import HashcatConnector
from stg.connectors.creds.hibp import HibpConnector
from stg.connectors.creds.john import JohnConnector

CONNECTORS = [HashcatConnector, JohnConnector, HibpConnector]

__all__ = ["CONNECTORS", "HashcatConnector", "JohnConnector", "HibpConnector"]
