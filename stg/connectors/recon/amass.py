"""Conector Amass - descoberta de subdominios/ativos."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from stg.core.connector import CommandConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType


class AmassConnector(CommandConnector):
    name = "amass"
    tool = "Amass"
    category = Category.RECON
    description = "Mapeia a superficie de ataque descobrindo subdominios e ativos."
    requires_binaries = ["amass"]
    target_types = [TargetType.DOMAIN, TargetType.HOSTNAME]
    default_timeout = 1800

    def build_command(self, target: Target, options: dict[str, Any], workdir: Path) -> list[str]:
        cmd = ["amass", "enum", "-d", target.host, "-nocolor"]
        if options.get("passive", False):
            cmd.append("-passive")
        if minutes := options.get("timeout_minutes"):
            cmd += ["-timeout", str(minutes)]
        return cmd

    def parse(self, raw: str, target: Target) -> list[Finding]:
        root = target.host.lower()
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            host = line.strip().split()[0].strip().lower() if line.strip() else ""
            if not host or host in seen:
                continue
            if "." in host and (host == root or host.endswith("." + root)):
                seen.add(host)
                findings.append(
                    self.make_finding(
                        title=f"Subdominio descoberto: {host}",
                        target=target,
                        severity=Severity.INFO,
                        description=f"Ativo relacionado a {root}.",
                        metadata={"subdomain": host},
                    )
                )
        return findings
