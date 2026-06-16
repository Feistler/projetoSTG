"""Conector Wireshark/tshark - analise de pacotes a partir de um PCAP.

Foco pratico: destacar trafego sensivel em texto claro (FTP, Telnet, HTTP com
autenticacao, POP/IMAP/SNMP), que e um achado classico de monitoramento.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from stg.core.connector import CommandConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType

DEFAULT_FILTER = "ftp || telnet || http.authorization || pop || imap || snmp"
MAX_FINDINGS = 200


class WiresharkConnector(CommandConnector):
    name = "wireshark"
    tool = "Wireshark (tshark)"
    category = Category.NETMON
    description = "Analise de PCAP: detecta protocolos sensiveis e credenciais em texto claro."
    requires_binaries = ["tshark"]
    target_types = [TargetType.PCAP, TargetType.FILE]
    passive = True
    default_timeout = 600

    def build_command(self, target: Target, options: dict[str, Any], workdir: Path) -> list[str]:
        display_filter = options.get("filter", DEFAULT_FILTER)
        return [
            "tshark",
            "-r", target.value,
            "-Y", display_filter,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
            "-E", "separator=\t",
        ]

    def parse(self, raw: str, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            frame = parts[0] if len(parts) > 0 else ""
            src = parts[1] if len(parts) > 1 else ""
            dst = parts[2] if len(parts) > 2 else ""
            proto = parts[3] if len(parts) > 3 else "?"
            info = parts[4] if len(parts) > 4 else ""
            findings.append(
                self.make_finding(
                    title=f"Trafego sensivel em texto claro ({proto})",
                    target=target,
                    severity=Severity.MEDIUM,
                    description=f"{src} -> {dst} via {proto} (frame {frame}).",
                    evidence=info[:200],
                    metadata={"frame": frame, "src": src, "dst": dst, "protocol": proto},
                )
            )
            if len(findings) >= MAX_FINDINGS:
                break
        return findings
