"""Contrato base dos conectores.

Todo conector implementa a mesma interface, o que permite ao runner, aos
pipelines e aos relatorios tratarem qualquer ferramenta de forma identica.

Tres bases sao oferecidas:
  * :class:`BaseConnector`   - contrato minimo (template method ``run``).
  * :class:`CommandConnector`- ferramentas de linha de comando (subprocess).
  * :class:`ApiConnector`    - ferramentas/servicos acessados via HTTP.
"""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from stg.core.config import Settings
from stg.core.exceptions import TargetValidationError
from stg.core.models import (
    Category,
    Finding,
    ScanResult,
    ScanStatus,
    Severity,
    Target,
    TargetType,
    utcnow,
)
from stg.utils import shell


class BaseConnector(ABC):
    # --- metadados (sobrescritos por cada conector) ----------------------
    name: str = ""
    tool: str = ""
    category: Category = Category.RECON
    description: str = ""
    requires_binaries: list[str] = []
    requires_api_keys: list[str] = []
    requires_modules: list[str] = []  # modulos python opcionais (ex.: "gvm")
    target_types: list[TargetType] = []
    passive: bool = False  # True = OSINT/passivo, dispensa escopo ativo
    default_timeout: int = 600

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()

    # --- disponibilidade -------------------------------------------------
    def is_available(self) -> tuple[bool, str]:
        for binary in self.requires_binaries:
            if shell.which(binary) is None:
                return False, f"binario '{binary}' nao encontrado no PATH"
        for module in self.requires_modules:
            if importlib.util.find_spec(module) is None:
                return False, f"modulo python '{module}' ausente (pip install stg-toolkit[integrations])"
        for key in self.requires_api_keys:
            if not self.settings.secret(key):
                return False, f"credencial '{key}' nao configurada"
        return True, "ok"

    # --- validacao -------------------------------------------------------
    def validate_target(self, target: Target) -> None:
        if self.target_types and target.type not in self.target_types:
            supported = ", ".join(t.value for t in self.target_types)
            raise TargetValidationError(
                f"{self.name}: alvo do tipo '{target.type.value}' nao suportado "
                f"(esperados: {supported})"
            )

    # --- contrato a implementar -----------------------------------------
    @abstractmethod
    def _execute(self, target: Target, options: dict[str, Any]) -> tuple[str, str | None]:
        """Executa a ferramenta. Retorna (saida_bruta, comando)."""

    @abstractmethod
    def parse(self, raw: str, target: Target) -> list[Finding]:
        """Converte a saida bruta em findings normalizados."""

    # --- template method -------------------------------------------------
    def run(self, target: Target, options: dict[str, Any] | None = None) -> ScanResult:
        options = options or {}
        result = ScanResult(
            connector=self.name,
            category=self.category,
            target=target.value,
            started_at=utcnow(),
        )
        available, reason = self.is_available()
        if not available:
            result.status = ScanStatus.UNAVAILABLE
            result.error = reason
            result.finished_at = utcnow()
            return result
        try:
            self.validate_target(target)
            raw, command = self._execute(target, options)
            result.command = command
            result.raw_output = (raw or "")[:20000]
            result.findings = self.parse(raw or "", target)
            result.status = ScanStatus.SUCCESS
        except TargetValidationError as exc:
            result.status = ScanStatus.SKIPPED
            result.error = str(exc)
        except Exception as exc:  # noqa: BLE001 - erro encapsulado no resultado
            result.status = ScanStatus.FAILED
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.finished_at = utcnow()
        return result

    # --- helper para criar findings -------------------------------------
    def make_finding(
        self,
        title: str,
        target: Target,
        severity: Severity = Severity.INFO,
        **kwargs: Any,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            connector=self.name,
            category=self.category,
            target=target.value,
            **kwargs,
        )


class CommandConnector(BaseConnector):
    """Conector para ferramentas de linha de comando."""

    @abstractmethod
    def build_command(
        self, target: Target, options: dict[str, Any], workdir: Path
    ) -> list[str]:
        """Monta a lista de argumentos do processo."""

    def collect_output(self, result: shell.CommandResult, workdir: Path) -> str:
        """Por padrao usa stdout. Sobrescreva para ler arquivos do ``workdir``."""
        return result.stdout

    def _execute(self, target: Target, options: dict[str, Any]) -> tuple[str, str | None]:
        workdir = Path(tempfile.mkdtemp(prefix="stg-"))
        timeout = int(options.get("timeout", self.default_timeout))
        try:
            command = self.build_command(target, options, workdir)
            cmd_result = shell.run(command, timeout=timeout)
            raw = self.collect_output(cmd_result, workdir)
            if not (raw or "").strip():
                # Nada coletado: se o processo falhou de fato, propaga o erro
                # (vira FAILED) em vez de fingir sucesso com zero achados.
                if cmd_result.timed_out:
                    raise RuntimeError(f"timeout apos {timeout}s")
                if not cmd_result.ok:
                    detail = (cmd_result.stderr or cmd_result.stdout or "").strip()
                    raise RuntimeError(detail or f"comando falhou (rc={cmd_result.returncode})")
            return raw, cmd_result.command_str
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


class ApiConnector(BaseConnector):
    """Conector para servicos acessados via HTTP/API."""

    @abstractmethod
    def fetch(self, target: Target, options: dict[str, Any]) -> str:
        """Consulta a API e devolve a resposta bruta (em geral JSON em texto)."""

    def _execute(self, target: Target, options: dict[str, Any]) -> tuple[str, str | None]:
        raw = self.fetch(target, options)
        return raw, f"api://{self.name}"
