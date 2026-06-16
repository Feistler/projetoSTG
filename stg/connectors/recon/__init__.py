"""Categoria 1 - Reconhecimento & Varredura."""

from stg.connectors.recon.amass import AmassConnector
from stg.connectors.recon.nmap import NmapConnector
from stg.connectors.recon.shodan import ShodanConnector

CONNECTORS = [NmapConnector, AmassConnector, ShodanConnector]

__all__ = ["CONNECTORS", "NmapConnector", "AmassConnector", "ShodanConnector"]
