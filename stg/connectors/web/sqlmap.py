"""Conector SQLmap - deteccao/exploracao de SQL Injection."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from stg.core.connector import CommandConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType

_PARAM_RE = re.compile(r"Parameter:\s*(.+)")
_DBMS_RE = re.compile(r"back-end DBMS(?:\s+is|:)\s*([A-Za-z0-9 .()-]+)")


class SqlmapConnector(CommandConnector):
    name = "sqlmap"
    tool = "SQLmap"
    category = Category.WEB
    description = "Testa parametros de aplicacoes web contra SQL Injection."
    requires_binaries = ["sqlmap"]
    target_types = [TargetType.URL]
    default_timeout = 1800

    def build_command(self, target: Target, options: dict[str, Any], workdir: Path) -> list[str]:
        cmd = [
            "sqlmap",
            "-u", target.value,
            "--batch",
            "--disable-coloring",
            "--output-dir", str(workdir),
        ]
        if data := options.get("data"):
            cmd += ["--data", str(data)]
        if cookie := options.get("cookie"):
            cmd += ["--cookie", str(cookie)]
        cmd += ["--level", str(options.get("level", 1))]
        cmd += ["--risk", str(options.get("risk", 1))]
        if dbms := options.get("dbms"):
            cmd += ["--dbms", str(dbms)]
        if options.get("dbs"):
            cmd.append("--dbs")
        return cmd

    def parse(self, raw: str, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        dbms_match = _DBMS_RE.search(raw)
        dbms = dbms_match.group(1).strip() if dbms_match else None

        params = {p.strip() for p in _PARAM_RE.findall(raw)}
        for param in params:
            findings.append(
                self.make_finding(
                    title=f"SQL Injection no parametro {param}",
                    target=target,
                    severity=Severity.HIGH,
                    description=(
                        f"O SQLmap identificou que o parametro '{param}' e injetavel"
                        + (f" (DBMS: {dbms})." if dbms else ".")
                    ),
                    evidence=target.value,
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    metadata={"parameter": param, "dbms": dbms},
                )
            )
        return findings
