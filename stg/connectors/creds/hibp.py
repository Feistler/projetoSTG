"""Conector Have I Been Pwned - verifica vazamentos de uma conta."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import requests

from stg.core.connector import ApiConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType


class HibpConnector(ApiConnector):
    name = "hibp"
    tool = "Have I Been Pwned"
    category = Category.CREDS
    description = "Verifica se um e-mail aparece em vazamentos de dados conhecidos."
    requires_api_keys = ["HIBP_API_KEY"]
    target_types = [TargetType.EMAIL]
    passive = True

    def fetch(self, target: Target, options: dict[str, Any]) -> str:
        headers = {
            "hibp-api-key": self.settings.secret("HIBP_API_KEY"),
            "user-agent": "STG-Toolkit",
        }
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(target.value)}",
            params={"truncateResponse": "false"},
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 404:
            return json.dumps({"_empty": True})
        resp.raise_for_status()
        return resp.text

    def parse(self, raw: str, target: Target) -> list[Finding]:
        data = json.loads(raw or "[]")
        if isinstance(data, dict) and data.get("_empty"):
            return []
        findings: list[Finding] = []
        for breach in data:
            name = breach.get("Name", "Vazamento")
            classes = ", ".join(breach.get("DataClasses", []) or [])
            findings.append(
                self.make_finding(
                    title=f"Conta em vazamento: {name}",
                    target=target,
                    severity=Severity.MEDIUM,
                    description=f"E-mail presente no vazamento '{name}' ({breach.get('BreachDate')}).",
                    evidence=f"Dados expostos: {classes}",
                    references=[f"https://haveibeenpwned.com/PwnedWebsites#{name}"],
                    metadata={"breach": name, "pwn_count": breach.get("PwnCount")},
                )
            )
        return findings
