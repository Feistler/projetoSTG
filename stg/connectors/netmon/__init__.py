"""Categoria 5 - Monitorizacao de Rede."""

from stg.connectors.netmon.snort import SnortConnector
from stg.connectors.netmon.suricata import SuricataConnector
from stg.connectors.netmon.wireshark import WiresharkConnector

CONNECTORS = [WiresharkConnector, SuricataConnector, SnortConnector]

__all__ = ["CONNECTORS", "WiresharkConnector", "SuricataConnector", "SnortConnector"]
