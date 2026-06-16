"""Conector Nmap - varredura de portas e servicos (parser XML real)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from stg.core.connector import CommandConnector
from stg.core.models import Category, Finding, Severity, Target, TargetType

# Servicos sensiveis quando expostos -> elevam a severidade (LOW).
RISKY_SERVICES = {
    "telnet", "ftp", "rlogin", "rexec", "rsh", "ms-sql-s", "mysql",
    "postgresql", "snmp",
}
# Servicos de altissimo risco quando expostos (acesso remoto / dados sem auth) -> MEDIUM.
RISKY_MEDIUM = {
    "vnc", "smb", "microsoft-ds", "rdp", "ms-wbt-server", "redis",
    "mongodb", "memcached", "elasticsearch",
}


class NmapConnector(CommandConnector):
    name = "nmap"
    tool = "Nmap"
    category = Category.RECON
    description = "Varredura de redes: descobre hosts, portas abertas e servicos."
    requires_binaries = ["nmap"]
    target_types = [TargetType.IP, TargetType.CIDR, TargetType.DOMAIN, TargetType.HOSTNAME]
    default_timeout = 1800

    def build_command(self, target: Target, options: dict[str, Any], workdir: Path) -> list[str]:
        cmd = ["nmap", "-oX", "-"]
        if options.get("service_detection", True):
            cmd.append("-sV")
        if options.get("os_detection"):
            cmd.append("-O")
        if scripts := options.get("scripts"):
            cmd.append(f"--script={scripts}")
        if ports := options.get("ports"):
            cmd += ["-p", str(ports)]
        else:
            cmd += ["--top-ports", str(options.get("top_ports", 1000))]
        cmd.append(f"-T{options.get('timing', 4)}")
        if extra := options.get("extra_args"):
            cmd += extra if isinstance(extra, list) else str(extra).split()
        cmd.append(target.value)
        return cmd

    def parse(self, raw: str, target: Target) -> list[Finding]:
        raw = raw.strip()
        if "<nmaprun" not in raw:
            return []
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return []

        findings: list[Finding] = []
        for host in root.findall("host"):
            addr = host.find("address")
            host_ip = addr.get("addr") if addr is not None else target.value
            hn = host.find("hostnames/hostname")
            hostname = hn.get("name") if hn is not None else None

            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = port.get("portid")
                proto = port.get("protocol")
                svc = port.find("service")
                service = svc.get("name") if svc is not None else "unknown"
                product = svc.get("product") if svc is not None else None
                version = svc.get("version") if svc is not None else None
                banner = " ".join(p for p in (product, version) if p)

                desc = f"Host {host_ip}: porta {portid}/{proto} aberta, servico '{service}'"
                if banner:
                    desc += f" ({banner})"

                findings.append(
                    self.make_finding(
                        title=f"Porta aberta {portid}/{proto} - {service}",
                        target=target,
                        severity=(
                            Severity.MEDIUM
                            if service in RISKY_MEDIUM
                            else Severity.LOW
                            if service in RISKY_SERVICES
                            else Severity.INFO
                        ),
                        description=desc,
                        metadata={
                            "ip": host_ip,
                            "hostname": hostname,
                            "port": portid,
                            "protocol": proto,
                            "service": service,
                            "product": product,
                            "version": version,
                        },
                    )
                )
        return findings
