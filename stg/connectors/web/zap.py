"""Conector OWASP ZAP - usa a API do daemon ZAP.

Por padrao apenas LE os alertas existentes para a URL. Com a opcao
``active: true`` dispara spider + active scan (aguardando a conclusao, limitado
por ``max_wait`` segundos) antes de coletar os alertas.
"""

from __future__ import annotations

import json
import time
from typing import Any

import requests

from stg.core.connector import ApiConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType

_RISK = {
    "Informational": Severity.INFO,
    "Low": Severity.LOW,
    "Medium": Severity.MEDIUM,
    "High": Severity.HIGH,
}


class ZapConnector(ApiConnector):
    name = "zap"
    tool = "OWASP ZAP"
    category = Category.WEB
    description = "Analise de vulnerabilidades web via API do OWASP ZAP."
    requires_api_keys = ["ZAP_API_KEY"]
    target_types = [TargetType.URL]
    default_timeout = 1800

    def _base(self) -> str:
        return (self.settings.secret("ZAP_API_URL") or "http://localhost:8080").rstrip("/")

    def _get(self, path: str, **params: Any) -> dict[str, Any]:
        params["apikey"] = self.settings.secret("ZAP_API_KEY")
        resp = requests.get(f"{self._base()}{path}", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _poll(self, path: str, scan_id: str, max_wait: int) -> None:
        deadline = time.time() + max_wait
        while time.time() < deadline:
            status = self._get(path, scanId=scan_id).get("status", "0")
            if int(status) >= 100:
                return
            time.sleep(3)

    def fetch(self, target: Target, options: dict[str, Any]) -> str:
        url = target.value
        if options.get("active"):
            max_wait = int(options.get("max_wait", 600))
            spider = self._get("/JSON/spider/action/scan/", url=url)
            self._poll("/JSON/spider/view/status/", spider.get("scan", "0"), max_wait)
            ascan = self._get("/JSON/ascan/action/scan/", url=url)
            self._poll("/JSON/ascan/view/status/", ascan.get("scan", "0"), max_wait)
        alerts = self._get("/JSON/core/view/alerts/", baseurl=url)
        return json.dumps(alerts)

    def parse(self, raw: str, target: Target) -> list[Finding]:
        data = json.loads(raw or "{}")
        findings: list[Finding] = []
        for alert in data.get("alerts", []) or []:
            findings.append(
                self.make_finding(
                    title=alert.get("alert", "Alerta ZAP"),
                    target=target,
                    severity=_RISK.get(alert.get("risk", "Informational"), Severity.INFO),
                    description=alert.get("description", ""),
                    evidence=alert.get("url", ""),
                    references=[r for r in [alert.get("reference")] if r],
                    metadata={
                        "cweid": alert.get("cweid"),
                        "wascid": alert.get("wascid"),
                        "param": alert.get("param"),
                        "solution": alert.get("solution"),
                    },
                )
            )
        return findings
