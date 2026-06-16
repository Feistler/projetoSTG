"""Conector OpenVAS / Greenbone (GVM) - le resultados via protocolo GMP."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from stg.core.connector import ApiConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType

_THREAT = {
    "Log": Severity.INFO,
    "Low": Severity.LOW,
    "Medium": Severity.MEDIUM,
    "High": Severity.HIGH,
    "Critical": Severity.CRITICAL,
}


class OpenVASConnector(ApiConnector):
    name = "openvas"
    tool = "OpenVAS / Greenbone (GVM)"
    category = Category.VULN
    description = "Importa resultados de vulnerabilidades do GVM via GMP."
    requires_api_keys = ["OPENVAS_PASSWORD"]
    requires_modules = ["gvm"]  # pip install python-gvm
    target_types = [TargetType.IP, TargetType.DOMAIN, TargetType.HOSTNAME]
    passive = True

    def fetch(self, target: Target, options: dict[str, Any]) -> str:
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import Gmp

        host = self.settings.secret("OPENVAS_HOST") or "localhost"
        port = int(self.settings.secret("OPENVAS_PORT") or 9390)
        user = self.settings.secret("OPENVAS_USER") or "admin"
        password = self.settings.secret("OPENVAS_PASSWORD")

        connection = TLSConnection(hostname=host, port=port)
        with Gmp(connection=connection) as gmp:
            gmp.authenticate(user, password)
            rows = int(options.get("rows", 100))
            return gmp.get_results(filter_string=f"host={target.value} rows={rows}")

    def parse(self, raw: str, target: Target) -> list[Finding]:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return []
        findings: list[Finding] = []
        for result in root.iter("result"):
            name = _text(result, "name", "Resultado OpenVAS")
            threat = _text(result, "threat", "Log")
            host = _text(result, "host", target.value)
            findings.append(
                self.make_finding(
                    title=name,
                    target=target,
                    severity=_THREAT.get(threat, Severity.INFO),
                    description=f"Host {host}: {name}",
                    metadata={"threat": threat, "host": host},
                )
            )
        return findings


def _text(el: ET.Element, tag: str, default: str) -> str:
    found = el.find(tag)
    return found.text if found is not None and found.text else default
