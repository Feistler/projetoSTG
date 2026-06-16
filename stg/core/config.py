"""Carregamento de configuracao (YAML) e segredos (.env / ambiente)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

DEFAULT_DATA_DIR = Path("stg-data")
DEFAULT_CONFIG_PATH = Path("config/config.yaml")


class Settings:
    """Acesso unificado a configuracao e segredos.

    Precedencia de segredos: variavel de ambiente > secao ``secrets`` do YAML.
    """

    def __init__(self, config: dict[str, Any] | None = None, path: Path | None = None) -> None:
        self.config: dict[str, Any] = config or {}
        self.path = path

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Settings":
        load_dotenv()  # popula os.environ a partir de .env, se existir
        cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
        config: dict[str, Any] = {}
        if cfg_path.exists():
            loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
            config = loaded or {}
        return cls(config, cfg_path if cfg_path.exists() else None)

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.config
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    def secret(self, key: str, default: str | None = None) -> str | None:
        value = os.environ.get(key)
        if value:
            return value
        secrets = self.config.get("secrets", {}) if isinstance(self.config, dict) else {}
        return secrets.get(key, default)

    # --- caminhos padrao -------------------------------------------------
    @property
    def data_dir(self) -> Path:
        return Path(self.get("paths.data_dir", str(DEFAULT_DATA_DIR)))

    @property
    def output_dir(self) -> Path:
        return Path(self.get("paths.output_dir", str(self.data_dir / "output")))

    @property
    def audit_path(self) -> Path:
        return Path(self.get("paths.audit_log", str(self.data_dir / "audit.jsonl")))

    @property
    def authorization_path(self) -> Path:
        return Path(self.get("paths.authorization", "config/authorization.yaml"))

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
