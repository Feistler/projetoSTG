"""Categoria 6 - SIEM & Protecao de Endpoints."""

from stg.connectors.siem.crowdstrike import CrowdStrikeConnector
from stg.connectors.siem.splunk import SplunkConnector
from stg.connectors.siem.wazuh import WazuhConnector

CONNECTORS = [SplunkConnector, WazuhConnector, CrowdStrikeConnector]

__all__ = ["CONNECTORS", "SplunkConnector", "WazuhConnector", "CrowdStrikeConnector"]
