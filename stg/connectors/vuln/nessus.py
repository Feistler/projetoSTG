"""Conector Nessus (Tenable) - consome resultados via REST API.

Estrategia: em vez de disparar um scan (que e assincrono e demorado), este
conector consome os achados do scan mais recente ja concluido. Requer as
API Keys do Nessus (Settings > My Account > API Keys).
"""

from __future__ import annotations

import json
from typing import Any

import requests

from stg.core.connector import ApiConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType

# Mapeia o nivel de severidade do Nessus (0-4) para o modelo do STG.
_SEV = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}


class NessusConnector(ApiConnector):
    name = "nessus"
    tool = "Nessus"
    category = Category.VULN
    description = "Importa vulnerabilidades do scan mais recente do Nessus (REST API)."
    requires_api_keys = ["NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY"]
    target_types = [TargetType.IP, TargetType.DOMAIN, TargetType.HOSTNAME]
    passive = True  # apenas le resultados ja produzidos pelo Nessus

    def _headers(self) -> dict[str, str]:
        access = self.settings.secret("NESSUS_ACCESS_KEY")
        secret = self.settings.secret("NESSUS_SECRET_KEY")
        return {"X-ApiKeys": f"accessKey={access}; secretKey={secret}"}

    def _base_url(self) -> str:
        return (self.settings.secret("NESSUS_URL") or "https://localhost:8834").rstrip("/")

    def fetch(self, target: Target, options: dict[str, Any]) -> str:
        base = self._base_url()
        headers = self._headers()
        # Nessus normalmente usa certificado autoassinado.
        verify = bool(options.get("verify_tls", False))

        scans = requests.get(f"{base}/scans", headers=headers, verify=verify, timeout=30)
        scans.raise_for_status()
        scan_list = scans.json().get("scans") or []
        if not scan_list:
            return json.dumps({"_empty": True})

        scan_id = options.get("scan_id")
        if not scan_id:
            completed = [s for s in scan_list if s.get("status") == "completed"]
            chosen = max(completed or scan_list, key=lambda s: s.get("last_modification_date", 0))
            scan_id = chosen["id"]

        detail = requests.get(
            f"{base}/scans/{scan_id}", headers=headers, verify=verify, timeout=60
        )
        detail.raise_for_status()
        return detail.text

    def parse(self, raw: str, target: Target) -> list[Finding]:
        data = json.loads(raw or "{}")
        if data.get("_empty"):
            return []
        findings: list[Finding] = []
        for vuln in data.get("vulnerabilities", []) or []:
            sev = _SEV.get(int(vuln.get("severity", 0)), Severity.INFO)
            name = vuln.get("plugin_name", "Vulnerabilidade Nessus")
            findings.append(
                self.make_finding(
                    title=name,
                    target=target,
                    severity=sev,
                    description=f"Plugin {vuln.get('plugin_id')}: {name}",
                    metadata={
                        "plugin_id": vuln.get("plugin_id"),
                        "family": vuln.get("plugin_family"),
                        "count": vuln.get("count"),
                    },
                )
            )
        return findings
