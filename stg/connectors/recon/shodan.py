"""Conector Shodan - exposicao de dispositivos (consulta passiva via API)."""

from __future__ import annotations

import json
from typing import Any

import requests

from stg.core.connector import ApiConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType


class ShodanConnector(ApiConnector):
    name = "shodan"
    tool = "Shodan"
    category = Category.RECON
    description = "Consulta passiva da exposicao de um IP na internet (Shodan)."
    requires_api_keys = ["SHODAN_API_KEY"]
    target_types = [TargetType.IP]
    passive = True  # OSINT: nao toca o alvo, consulta a base do Shodan

    def fetch(self, target: Target, options: dict[str, Any]) -> str:
        key = self.settings.secret("SHODAN_API_KEY")
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{target.value}",
            params={"key": key},
            timeout=30,
        )
        if resp.status_code == 404:
            return json.dumps({"_empty": True})
        resp.raise_for_status()
        return resp.text

    def parse(self, raw: str, target: Target) -> list[Finding]:
        data = json.loads(raw or "{}")
        if data.get("_empty"):
            return []

        findings: list[Finding] = []
        org = data.get("org")
        ref = [f"https://www.shodan.io/host/{target.value}"]

        for item in data.get("data", []) or []:
            port = item.get("port")
            transport = item.get("transport", "tcp")
            product = item.get("product")
            findings.append(
                self.make_finding(
                    title=f"Servico exposto na internet {port}/{transport}",
                    target=target,
                    severity=Severity.LOW,
                    description=f"{product or 'Servico'} visivel publicamente (org: {org}).",
                    metadata={"port": port, "transport": transport, "product": product},
                    references=ref,
                )
            )

        vulns = data.get("vulns")
        cve_list = vulns.keys() if isinstance(vulns, dict) else (vulns or [])
        for cve in cve_list:
            findings.append(
                self.make_finding(
                    title=f"CVE potencial: {cve}",
                    target=target,
                    severity=Severity.HIGH,
                    description=f"Shodan associou {cve} a este host.",
                    metadata={"cve": cve},
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
                )
            )
        return findings
