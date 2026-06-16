"""Conector Splunk - executa uma busca via REST e normaliza os eventos."""

from __future__ import annotations

import json
from typing import Any

import requests

from stg.core.connector import ApiConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType

_SEV = {
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class SplunkConnector(ApiConnector):
    name = "splunk"
    tool = "Splunk"
    category = Category.SIEM
    description = "Executa uma busca SPL via REST e converte os eventos em achados."
    requires_api_keys = ["SPLUNK_TOKEN"]
    target_types: list[TargetType] = []
    passive = True

    def _base(self) -> str:
        return (self.settings.secret("SPLUNK_URL") or "https://localhost:8089").rstrip("/")

    def fetch(self, target: Target, options: dict[str, Any]) -> str:
        token = self.settings.secret("SPLUNK_TOKEN")
        verify = bool(options.get("verify_tls", False))
        default_query = (
            f'search index=* "{target.value}" earliest=-24h | head 100'
            if target.value
            else "search index=_internal | head 50"
        )
        query = options.get("query", default_query)

        resp = requests.post(
            f"{self._base()}/services/search/jobs/export",
            headers={"Authorization": f"Bearer {token}"},
            data={"search": query, "output_mode": "json", "exec_mode": "oneshot"},
            verify=verify,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.text

    def parse(self, raw: str, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            result = event.get("result")
            if not isinstance(result, dict):
                continue
            sev = str(result.get("severity", "info")).lower()
            raw_msg = result.get("_raw", "")
            findings.append(
                self.make_finding(
                    title=result.get("source", "Evento Splunk")[:120],
                    target=target,
                    severity=_SEV.get(sev, Severity.INFO),
                    description=raw_msg[:300] if isinstance(raw_msg, str) else "",
                    metadata={"sourcetype": result.get("sourcetype"), "host": result.get("host")},
                )
            )
        return findings
