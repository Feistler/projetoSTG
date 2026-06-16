"""Modelos de dados normalizados do STG.

Toda ferramenta integrada (Nmap, Nikto, Shodan, Wazuh...) converte sua saida
nativa para estes modelos. Assim o restante do sistema (relatorios, pipelines,
dashboards) trabalha com um unico vocabulario.
"""

from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    """Severidade normalizada de um achado."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return _SEVERITY_ORDER[self]

    # str ja define __lt__/__gt__/etc (comparacao alfabetica). Precisamos
    # sobrescrever TODOS para que a ordenacao siga a gravidade, nao o texto.
    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.score < other.score
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.score <= other.score
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.score > other.score
        return NotImplemented

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.score >= other.score
        return NotImplemented


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Category(str, Enum):
    """As seis familias de ferramentas do projeto."""

    RECON = "reconhecimento"
    VULN = "vulnerabilidades"
    WEB = "web"
    CREDS = "senhas"
    NETMON = "monitoramento-rede"
    SIEM = "siem-endpoint"


class TargetType(str, Enum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    EMAIL = "email"
    FILE = "file"
    PCAP = "pcap"
    UNKNOWN = "unknown"


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Extensoes locais comuns (hashes, wordlists, capturas) que NAO sao dominios.
_FILE_EXTS = (".txt", ".lst", ".hash", ".hashes", ".json", ".csv", ".xml", ".log", ".dump", ".gz")
_PCAP_EXTS = (".pcap", ".pcapng", ".cap")


class Target(BaseModel):
    """Alvo de um scan, com o tipo inferido a partir do valor."""

    value: str
    type: TargetType = TargetType.UNKNOWN

    @classmethod
    def parse(cls, value: str) -> "Target":
        return cls(value=value, type=cls._infer_type(value))

    @staticmethod
    def _infer_type(value: str) -> TargetType:
        v = value.strip()
        if v.startswith(("http://", "https://")):
            return TargetType.URL
        if _EMAIL_RE.match(v):
            return TargetType.EMAIL
        if v.lower().endswith(_PCAP_EXTS):
            return TargetType.PCAP
        # Arquivo local (hashes/wordlist/etc.): por extensao conhecida ou se existe
        # no disco. Vem ANTES do dominio para nao confundir "hashes.txt" com host.
        if v.lower().endswith(_FILE_EXTS) or os.path.exists(v):
            return TargetType.FILE
        try:
            ipaddress.ip_network(v, strict=False)
            return TargetType.CIDR if "/" in v else TargetType.IP
        except ValueError:
            pass
        if _DOMAIN_RE.match(v):
            return TargetType.DOMAIN
        if "/" in v or "\\" in v or "." in v.split("/")[-1]:
            # heuristica fraca para caminho de arquivo local
            return TargetType.FILE
        return TargetType.HOSTNAME

    @property
    def host(self) -> str:
        """Extrai o host de uma URL; caso contrario devolve o valor."""
        if self.type == TargetType.URL:
            stripped = self.value.split("://", 1)[-1]
            return stripped.split("/", 1)[0].split(":", 1)[0]
        return self.value

    def __str__(self) -> str:
        return self.value


class Finding(BaseModel):
    """Um achado individual normalizado."""

    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    title: str
    severity: Severity = Severity.INFO
    connector: str
    category: Category
    target: str
    description: str = ""
    evidence: str = ""
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utcnow)


class ScanStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    UNAUTHORIZED = "unauthorized"
    SKIPPED = "skipped"


class ScanResult(BaseModel):
    """Resultado consolidado da execucao de um conector contra um alvo."""

    connector: str
    category: Category
    target: str
    status: ScanStatus = ScanStatus.SUCCESS
    findings: list[Finding] = Field(default_factory=list)
    command: str | None = None
    error: str | None = None
    raw_output: str | None = None
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)
