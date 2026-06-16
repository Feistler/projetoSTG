"""Runner: orquestra autorizacao -> execucao -> auditoria."""

from __future__ import annotations

from typing import Any

from stg.core.audit import AuditLog
from stg.core.authorization import Authorization
from stg.core.config import Settings
from stg.core.models import Category, ScanResult, ScanStatus, Target
from stg.core.registry import get_registry
from stg.utils.logging import get_logger

log = get_logger()


class Runner:
    """Ponto unico por onde toda execucao de conector passa."""

    def __init__(
        self,
        settings: Settings,
        authorization: Authorization | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.settings = settings
        self.authz = authorization or Authorization.load(settings.authorization_path)
        self.audit = audit or AuditLog(settings.audit_path)
        self.registry = get_registry()

    def run(
        self,
        connector_name: str,
        target_value: str,
        options: dict[str, Any] | None = None,
        *,
        force: bool = False,
    ) -> ScanResult:
        connector = self.registry.build(connector_name, self.settings)
        target = Target.parse(target_value)
        authorized = self.authz.is_authorized(target)
        needs_authz = not connector.passive

        if needs_authz and not authorized and not force:
            self.audit.record_block(connector_name, target.value)
            log.warning(
                f"[bold red]BLOQUEADO[/] '{target.value}' esta fora do escopo autorizado. "
                f"Ajuste [cyan]{self.settings.authorization_path}[/] ou use [yellow]--force[/] "
                f"(sera auditado)."
            )
            return ScanResult(
                connector=connector_name,
                category=connector.category,
                target=target.value,
                status=ScanStatus.UNAUTHORIZED,
                error="Alvo fora do escopo autorizado.",
            )

        forced = needs_authz and not authorized and force
        if forced:
            log.warning(
                f"[bold yellow]--force[/]: executando '{connector_name}' contra "
                f"'{target.value}' FORA do escopo. Acao registrada na auditoria."
            )

        result = connector.run(target, options)
        self.audit.record_scan(
            connector_name,
            target.value,
            authorized=authorized,
            forced=forced,
            status=result.status.value,
            command=result.command,
        )
        return result

    def categories(self) -> dict[Category, list[str]]:
        return {
            cat: [cls.name for cls in classes]
            for cat, classes in self.registry.by_category().items()
        }
