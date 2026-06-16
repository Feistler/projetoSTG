"""Conector John the Ripper - auditoria de senhas."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from stg.core.connector import CommandConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType
from stg.utils import shell


class JohnConnector(CommandConnector):
    name = "john"
    tool = "John the Ripper"
    category = Category.CREDS
    description = "Auditoria de senhas: tenta quebrar hashes e lista os fracos."
    requires_binaries = ["john"]
    target_types = [TargetType.FILE]
    default_timeout = 3600
    passive = True

    def build_command(self, target: Target, options: dict[str, Any], workdir: Path) -> list[str]:
        pot = workdir / "john.pot"
        cmd = ["john", f"--pot={pot}"]
        if wordlist := options.get("wordlist"):
            cmd.append(f"--wordlist={wordlist}")
        if fmt := options.get("format"):
            cmd.append(f"--format={fmt}")
        cmd.append(target.value)
        # Comando para listar os hashes quebrados depois do ataque.
        self._show_cmd = ["john", f"--pot={pot}", "--show"]
        if fmt := options.get("format"):
            self._show_cmd.append(f"--format={fmt}")
        self._show_cmd.append(target.value)
        return cmd

    def collect_output(self, result: shell.CommandResult, workdir: Path) -> str:
        show = shell.run(self._show_cmd, timeout=120)
        return show.stdout or result.stdout

    def parse(self, raw: str, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            if "password hash" in line or line.endswith("left"):
                continue  # linha de resumo do --show
            login, password = line.split(":", 1)
            findings.append(
                self.make_finding(
                    title=f"Senha fraca: {login}",
                    target=target,
                    severity=Severity.HIGH,
                    description=f"A conta '{login}' usa uma senha quebravel por dicionario.",
                    evidence=f"{login}:{password.split(':')[0]}",
                    metadata={"login": login},
                )
            )
        return findings
