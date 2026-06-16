"""Conector Snort - IDS aplicado a um PCAP (parser do output 'console')."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from stg.core.connector import CommandConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType

_ALERT_RE = re.compile(r"\[\*\*\]\s*(?:\[\d+:\d+:\d+\]\s*)?(.*?)\s*\[\*\*\]")
_PRIO_RE = re.compile(r"\[Priority:\s*(\d+)\]")
_PRIO_SEV = {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW}


class SnortConnector(CommandConnector):
    name = "snort"
    tool = "Snort"
    category = Category.NETMON
    description = "Deteccao de intrusoes sobre PCAP usando um ruleset Snort."
    requires_binaries = ["snort"]
    target_types = [TargetType.PCAP, TargetType.FILE]
    passive = True
    default_timeout = 1200

    def build_command(self, target: Target, options: dict[str, Any], workdir: Path) -> list[str]:
        config = options.get("config")
        if not config:
            raise RuntimeError(
                "Snort requer 'config' (caminho de um snort.conf/ruleset valido)."
            )
        return [
            "snort",
            "-r", target.value,
            "-c", str(config),
            "-A", "console",
            "-q",
            "-l", str(workdir),
        ]

    def parse(self, raw: str, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if "[**]" not in line:
                continue
            msg_match = _ALERT_RE.search(line)
            if not msg_match:
                continue
            prio_match = _PRIO_RE.search(line)
            priority = int(prio_match.group(1)) if prio_match else 3
            findings.append(
                self.make_finding(
                    title=msg_match.group(1) or "Alerta Snort",
                    target=target,
                    severity=_PRIO_SEV.get(priority, Severity.INFO),
                    description=line.strip()[:300],
                    metadata={"priority": priority},
                )
            )
        return findings
