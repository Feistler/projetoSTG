"""Conector Wazuh - consulta a API e sinaliza lacunas de monitoramento.

Foco pratico: agentes que NAO estao 'active' representam pontos cegos do SIEM.
Este conector autentica na Wazuh API e lista esses agentes como achados.
"""

from __future__ import annotations

import json
from typing import Any

import requests

from stg.core.connector import ApiConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType


class WazuhConnector(ApiConnector):
    name = "wazuh"
    tool = "Wazuh"
    category = Category.SIEM
    description = "Consulta a API do Wazuh e reporta agentes inativos (pontos cegos)."
    requires_api_keys = ["WAZUH_API_PASSWORD"]
    target_types: list[TargetType] = []  # consulta a plataforma, nao um alvo de rede
    passive = True

    def _base(self) -> str:
        return (self.settings.secret("WAZUH_API_URL") or "https://localhost:55000").rstrip("/")

    def fetch(self, target: Target, options: dict[str, Any]) -> str:
        base = self._base()
        user = self.settings.secret("WAZUH_API_USER") or "wazuh"
        password = self.settings.secret("WAZUH_API_PASSWORD")
        verify = bool(options.get("verify_tls", False))

        auth = requests.post(
            f"{base}/security/user/authenticate", auth=(user, password), verify=verify, timeout=30
        )
        auth.raise_for_status()
        token = auth.json()["data"]["token"]

        agents = requests.get(
            f"{base}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={"select": "name,ip,status,id", "limit": 1000},
            verify=verify,
            timeout=30,
        )
        agents.raise_for_status()
        return agents.text

    def parse(self, raw: str, target: Target) -> list[Finding]:
        data = json.loads(raw or "{}")
        items = data.get("data", {}).get("affected_items", []) or []
        findings: list[Finding] = []
        for agent in items:
            status = agent.get("status")
            if status == "active" or agent.get("id") == "000":
                continue
            findings.append(
                self.make_finding(
                    title=f"Agente Wazuh inativo: {agent.get('name')}",
                    target=Target(value=agent.get("ip", target.value or "wazuh")),
                    severity=Severity.MEDIUM,
                    description=f"Agente '{agent.get('name')}' esta '{status}' - sem telemetria.",
                    metadata={"agent_id": agent.get("id"), "status": status},
                )
            )
        return findings
