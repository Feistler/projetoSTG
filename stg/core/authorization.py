"""Controle de escopo autorizado (Rules of Engagement).

Antes de executar qualquer conector ATIVO, o runner verifica se o alvo esta
dentro do escopo declarado em ``config/authorization.yaml``. Isso materializa,
em codigo, a regra de ouro de qualquer trabalho ofensivo: so se testa o que se
tem autorizacao por escrito para testar.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml

from stg.core.models import Target, TargetType

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class Authorization:
    def __init__(
        self,
        networks: list[IPNetwork] | None = None,
        domains: list[str] | None = None,
        allow_local_files: bool = True,
    ) -> None:
        self.networks = networks or []
        self.domains = [d.lower().lstrip(".") for d in (domains or [])]
        self.allow_local_files = allow_local_files

    @classmethod
    def load(cls, path: str | Path) -> "Authorization":
        p = Path(path)
        if not p.exists():
            return cls(networks=[], domains=[])
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        scope = data.get("scope", {}) or {}
        networks: list[IPNetwork] = []
        for item in scope.get("networks", []) or []:
            try:
                networks.append(ipaddress.ip_network(str(item), strict=False))
            except ValueError:
                continue
        domains = scope.get("domains", []) or []
        allow_files = bool(data.get("allow_local_files", True))
        return cls(networks, domains, allow_files)

    @property
    def configured(self) -> bool:
        return bool(self.networks or self.domains)

    def is_authorized(self, target: Target) -> bool:
        t = target.type
        if t in (TargetType.FILE, TargetType.PCAP):
            return self.allow_local_files
        if t in (TargetType.IP, TargetType.CIDR):
            try:
                net = ipaddress.ip_network(target.value, strict=False)
            except ValueError:
                return False
            return any(self._contains(outer, net) for outer in self.networks)
        if t in (TargetType.DOMAIN, TargetType.HOSTNAME, TargetType.URL, TargetType.EMAIL):
            host = target.value.rsplit("@", 1)[-1] if t == TargetType.EMAIL else target.host
            host = host.lower()
            return any(host == d or host.endswith("." + d) for d in self.domains)
        return False

    @staticmethod
    def _contains(outer: IPNetwork, inner: IPNetwork) -> bool:
        try:
            return inner.subnet_of(outer)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
