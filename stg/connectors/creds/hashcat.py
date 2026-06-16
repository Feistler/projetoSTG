"""Conector Hashcat - quebra de senhas (auditoria de hashes proprios)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from stg.core.connector import CommandConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType
from stg.utils import shell

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"


class HashcatConnector(CommandConnector):
    name = "hashcat"
    tool = "Hashcat"
    category = Category.CREDS
    description = "Auditoria de robustez de hashes via ataque de dicionario (GPU/CPU)."
    requires_binaries = ["hashcat"]
    target_types = [TargetType.FILE]
    default_timeout = 3600
    passive = True  # opera sobre arquivo local de hashes, nao toca alvos externos

    def build_command(self, target: Target, options: dict[str, Any], workdir: Path) -> list[str]:
        wordlist = options.get("wordlist", DEFAULT_WORDLIST)
        out = workdir / "cracked.txt"
        return [
            "hashcat",
            "-m", str(options.get("mode", 0)),
            "-a", str(options.get("attack", 0)),
            target.value,
            wordlist,
            "--quiet",
            "--potfile-path", str(workdir / "stg.pot"),
            "-o", str(out),
            "--outfile-format", "3",  # hash:plain
        ]

    def collect_output(self, result: shell.CommandResult, workdir: Path) -> str:
        out = workdir / "cracked.txt"
        if out.exists():
            return out.read_text(encoding="utf-8", errors="replace")
        return result.stdout

    def parse(self, raw: str, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if ":" not in line:
                continue
            hash_value, plain = line.rsplit(":", 1)
            findings.append(
                self.make_finding(
                    title="Hash fraco quebrado",
                    target=target,
                    severity=Severity.HIGH,
                    description="Hash quebrado por ataque de dicionario - senha fraca.",
                    evidence=f"{hash_value[:32]}... -> {plain}",
                    metadata={"plaintext": plain},
                )
            )
        return findings
