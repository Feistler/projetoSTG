"""Wrapper seguro para execucao de processos externos.

Regras de seguranca:
  * Nunca usa ``shell=True`` (evita injecao de comando).
  * Sempre aplica timeout.
  * Captura stdout/stderr e normaliza o resultado.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from stg.core.exceptions import BinaryNotFoundError

DEFAULT_TIMEOUT = 600


@dataclass
class CommandResult:
    """Resultado normalizado de um processo externo."""

    command: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def command_str(self) -> str:
        return " ".join(self.command)


def which(binary: str) -> str | None:
    """Retorna o caminho do binario ou None se ausente."""
    return shutil.which(binary)


def run(
    command: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    cwd: str | None = None,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Executa ``command`` (lista de args) e devolve um :class:`CommandResult`.

    Levanta :class:`BinaryNotFoundError` se o executavel nao existir.
    Nunca levanta por codigo de saida != 0 (cabe ao conector interpretar).
    """
    try:
        proc = subprocess.run(  # noqa: S603 - argumentos sao lista controlada
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            input=input_text,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            command=command,
            returncode=124,
            stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
            stderr=exc.stderr or "" if isinstance(exc.stderr, str) else "",
            timed_out=True,
        )
    except FileNotFoundError as exc:
        raise BinaryNotFoundError(command[0]) from exc

    return CommandResult(
        command=command,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )
