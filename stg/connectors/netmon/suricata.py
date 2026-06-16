"""Conector Suricata - IDS/IPS aplicado a um PCAP (le alertas do eve.json)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from stg.core.connector import CommandConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType
from stg.utils import shell

# severidade do Suricata: 1=mais grave ... 4=menos grave
_SEV = {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW, 4: Severity.INFO}


class SuricataConnector(CommandConnector):
    name = "suricata"
    tool = "Suricata"
    category = Category.NETMON
    description = "Aplica regras de IDS sobre um PCAP e normaliza os alertas."
    requires_binaries = ["suricata"]
    target_types = [TargetType.PCAP, TargetType.FILE]
    passive = True
    default_timeout = 1200

    def build_command(self, target: Target, options: dict[str, Any], workdir: Path) -> list[str]:
        cmd = ["suricata", "-r", target.value, "-l", str(workdir)]
        if config := options.get("config"):
            cmd += ["-c", str(config)]
        if rules := options.get("rules"):
            cmd += ["-S", str(rules)]
        return cmd

    def collect_output(self, result: shell.CommandResult, workdir: Path) -> str:
        eve = workdir / "eve.json"
        if not eve.exists():
            return result.stderr or result.stdout
        alerts = [
            line
            for line in eve.read_text(encoding="utf-8", errors="replace").splitlines()
            if '"event_type":"alert"' in line.replace(" ", "")
        ]
        return "\n".join(alerts)

    def parse(self, raw: str, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert = event.get("alert") or {}
            sev = _SEV.get(int(alert.get("severity", 3)), Severity.LOW)
            findings.append(
                self.make_finding(
                    title=alert.get("signature", "Alerta Suricata"),
                    target=target,
                    severity=sev,
                    description=(
                        f"{event.get('src_ip')}:{event.get('src_port')} -> "
                        f"{event.get('dest_ip')}:{event.get('dest_port')} "
                        f"({alert.get('category', 'n/d')})"
                    ),
                    metadata={
                        "signature_id": alert.get("signature_id"),
                        "category": alert.get("category"),
                        "proto": event.get("proto"),
                    },
                )
            )
        return findings
