"""Conector Nikto - varredura de servidores web."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from stg.core.connector import CommandConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType
from stg.utils import shell

_ELEVATE = ("outdated", "vulnerable", "default", "insecure", "disclosure", "injection")


class NiktoConnector(CommandConnector):
    name = "nikto"
    tool = "Nikto"
    category = Category.VULN
    description = "Varredura de servidores web em busca de arquivos e configuracoes perigosas."
    requires_binaries = ["nikto"]
    target_types = [TargetType.URL, TargetType.HOSTNAME, TargetType.IP, TargetType.DOMAIN]
    default_timeout = 1800

    def build_command(self, target: Target, options: dict[str, Any], workdir: Path) -> list[str]:
        out = workdir / "nikto.json"
        cmd = [
            "nikto",
            "-host", target.value,
            "-Format", "json",
            "-output", str(out),
            "-nointeractive",
        ]
        if port := options.get("port"):
            cmd += ["-port", str(port)]
        if options.get("ssl"):
            cmd.append("-ssl")
        if tuning := options.get("tuning"):
            cmd += ["-Tuning", str(tuning)]
        if maxtime := options.get("maxtime"):
            cmd += ["-maxtime", str(maxtime)]
        return cmd

    def collect_output(self, result: shell.CommandResult, workdir: Path) -> str:
        out = workdir / "nikto.json"
        if out.exists():
            return out.read_text(encoding="utf-8", errors="replace")
        return result.stdout

    def parse(self, raw: str, target: Target) -> list[Finding]:
        raw = raw.strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        # Nikto pode devolver objeto unico ou lista de hosts.
        hosts = data if isinstance(data, list) else [data]
        findings: list[Finding] = []
        for host in hosts:
            if not isinstance(host, dict):
                continue
            for vuln in host.get("vulnerabilities", []) or []:
                msg = vuln.get("msg") or vuln.get("id") or "Item reportado pelo Nikto"
                severity = (
                    Severity.MEDIUM
                    if any(k in msg.lower() for k in _ELEVATE)
                    else Severity.LOW
                )
                refs = [vuln["references"]] if vuln.get("references") else []
                findings.append(
                    self.make_finding(
                        title=msg[:120],
                        target=target,
                        severity=severity,
                        description=msg,
                        evidence=f"{vuln.get('method', 'GET')} {vuln.get('url', '')}".strip(),
                        references=refs,
                        metadata={"id": vuln.get("id"), "osvdb": vuln.get("OSVDB")},
                    )
                )
        return findings
