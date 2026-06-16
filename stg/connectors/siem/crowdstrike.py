"""Conector CrowdStrike Falcon - importa deteccoes de endpoint (OAuth2)."""

from __future__ import annotations

import json
from typing import Any

import requests

from stg.core.connector import ApiConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType

_SEV = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class CrowdStrikeConnector(ApiConnector):
    name = "crowdstrike"
    tool = "CrowdStrike Falcon"
    category = Category.SIEM
    description = "Importa deteccoes de endpoint da plataforma Falcon (Detects API)."
    requires_api_keys = ["CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET"]
    target_types: list[TargetType] = []
    passive = True

    def _base(self) -> str:
        return (self.settings.secret("CROWDSTRIKE_BASE_URL") or "https://api.crowdstrike.com").rstrip("/")

    def _token(self) -> str:
        resp = requests.post(
            f"{self._base()}/oauth2/token",
            data={
                "client_id": self.settings.secret("CROWDSTRIKE_CLIENT_ID"),
                "client_secret": self.settings.secret("CROWDSTRIKE_CLIENT_SECRET"),
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def fetch(self, target: Target, options: dict[str, Any]) -> str:
        base = self._base()
        headers = {"Authorization": f"Bearer {self._token()}"}
        limit = int(options.get("limit", 50))

        ids = requests.get(
            f"{base}/detects/queries/detects/v1",
            headers=headers,
            params={"limit": limit, "sort": "last_behavior|desc"},
            timeout=30,
        )
        ids.raise_for_status()
        detection_ids = ids.json().get("resources", [])
        if not detection_ids:
            return json.dumps({"resources": []})

        summaries = requests.post(
            f"{base}/detects/entities/summaries/GET/v1",
            headers=headers,
            json={"ids": detection_ids},
            timeout=60,
        )
        summaries.raise_for_status()
        return summaries.text

    def parse(self, raw: str, target: Target) -> list[Finding]:
        data = json.loads(raw or "{}")
        findings: list[Finding] = []
        for det in data.get("resources", []) or []:
            sev_name = str(det.get("max_severity_displayname", "low")).lower()
            device = det.get("device", {}) or {}
            findings.append(
                self.make_finding(
                    title=f"Deteccao Falcon: {det.get('detection_id', 'n/d')}",
                    target=Target(value=device.get("hostname", target.value or "endpoint")),
                    severity=_SEV.get(sev_name, Severity.MEDIUM),
                    description=det.get("status", "Deteccao de endpoint reportada pela Falcon."),
                    metadata={
                        "device": device.get("hostname"),
                        "platform": device.get("platform_name"),
                        "tactic": (det.get("behaviors") or [{}])[0].get("tactic"),
                    },
                )
            )
        return findings
