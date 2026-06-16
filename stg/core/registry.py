"""Registro/descoberta de conectores."""

from __future__ import annotations

from stg.core.config import Settings
from stg.core.connector import BaseConnector
from stg.core.models import Category


class ConnectorRegistry:
    def __init__(self) -> None:
        self._classes: dict[str, type[BaseConnector]] = {}

    def register(self, cls: type[BaseConnector]) -> type[BaseConnector]:
        if not cls.name:
            raise ValueError(f"Conector {cls.__name__} sem atributo 'name'.")
        self._classes[cls.name] = cls
        return cls

    def names(self) -> list[str]:
        return sorted(self._classes)

    def classes(self) -> list[type[BaseConnector]]:
        return [self._classes[name] for name in self.names()]

    def get_class(self, name: str) -> type[BaseConnector]:
        if name not in self._classes:
            raise KeyError(f"Conector '{name}' nao registrado.")
        return self._classes[name]

    def build(self, name: str, settings: Settings) -> BaseConnector:
        return self.get_class(name)(settings)

    def by_category(self) -> dict[Category, list[type[BaseConnector]]]:
        grouped: dict[Category, list[type[BaseConnector]]] = {c: [] for c in Category}
        for cls in self.classes():
            grouped[cls.category].append(cls)
        return grouped


_registry: ConnectorRegistry | None = None


def get_registry() -> ConnectorRegistry:
    """Constroi (e memoriza) o registro a partir de ``stg.connectors``."""
    global _registry
    if _registry is None:
        from stg.connectors import ALL_CONNECTORS  # import tardio evita ciclo

        reg = ConnectorRegistry()
        for cls in ALL_CONNECTORS:
            reg.register(cls)
        _registry = reg
    return _registry
