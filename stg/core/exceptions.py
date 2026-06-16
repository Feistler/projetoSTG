"""Hierarquia de excecoes do STG."""

from __future__ import annotations


class STGError(Exception):
    """Erro base do toolkit."""


class ConfigError(STGError):
    """Configuracao ausente ou invalida."""


class TargetValidationError(STGError):
    """O alvo informado nao e suportado pelo conector."""


class AuthorizationError(STGError):
    """Alvo fora do escopo autorizado."""


class ConnectorUnavailableError(STGError):
    """Conector indisponivel (binario ausente ou credencial faltando)."""


class BinaryNotFoundError(ConnectorUnavailableError):
    """Binario externo necessario nao encontrado no PATH."""

    def __init__(self, binary: str) -> None:
        self.binary = binary
        super().__init__(f"Binario '{binary}' nao encontrado no PATH.")
