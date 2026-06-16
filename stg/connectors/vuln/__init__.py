"""Categoria 2 - Avaliacao de Vulnerabilidades."""

from stg.connectors.vuln.nessus import NessusConnector
from stg.connectors.vuln.nikto import NiktoConnector
from stg.connectors.vuln.openvas import OpenVASConnector

CONNECTORS = [NiktoConnector, NessusConnector, OpenVASConnector]

__all__ = ["CONNECTORS", "NiktoConnector", "NessusConnector", "OpenVASConnector"]
