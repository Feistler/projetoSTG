"""Conector Burp Suite.

ATENCAO: o Burp Suite *Community* nao expoe API. Este conector integra com a
REST API do Burp Suite *Enterprise* / *Professional* (extensao REST). Configure
``BURP_API_URL`` e ``BURP_API_KEY`` apontando para essa API.
"""

from __future__ import annotations

import json
from typing import Any

import requests

from stg.core.connector import ApiConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType

_SEV = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}


class BurpConnector(ApiConnector):
    name = "burp"
    tool = "Burp Suite (Enterprise/Pro)"
    category = Category.WEB
    description = "Importa issues do Burp Suite Enterprise/Pro via REST API."
    requires_api_keys = ["BURP_API_KEY"]
    target_types = [TargetType.URL]
    passive = True

    def fetch(self, target: Target, options: dict[str, Any]) -> str:
        base = self.settings.secret("BURP_API_URL")
        if not base:
            raise RuntimeError(
                "BURP_API_URL nao configurada. O Burp Community nao possui API; "
                "use Burp Enterprise/Pro."
            )
        key = self.settings.secret("BURP_API_KEY")
        # Endpoint generico de issues; ajuste conforme sua versao do Burp.
        resp = requests.get(
            f"{base.rstrip('/')}/v0.1/issues",
            headers={"Authorization": key},
            params={"url": target.value},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.text

    def parse(self, raw: str, target: Target) -> list[Finding]:
        data = json.loads(raw or "{}")
        issues = data if isinstance(data, list) else data.get("issues", [])
        findings: list[Finding] = []
        for issue in issues or []:
            sev = str(issue.get("severity", "info")).lower()
            findings.append(
                self.make_finding(
                    title=issue.get("name", issue.get("issue_type", "Issue Burp")),
                    target=target,
                    severity=_SEV.get(sev, Severity.INFO),
                    description=issue.get("description", ""),
                    evidence=issue.get("path", issue.get("origin", "")),
                    metadata={"confidence": issue.get("confidence")},
                )
            )
        return findings
