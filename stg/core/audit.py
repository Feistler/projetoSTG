"""Trilha de auditoria append-only (JSONL).

Cada execucao - autorizada, bloqueada ou forcada - vira uma linha imutavel.
E o registro que comprova *o que* foi escaneado, *quando*, *por quem* e *sob
qual autorizacao*. Indispensavel em qualquer operacao profissional.
"""

from __future__ import annotations

import getpass
import json
import socket
from pathlib import Path
from typing import Any

from stg.core.models import utcnow


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _write(self, record: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        full = {
            "timestamp": utcnow().isoformat(),
            "user": _current_user(),
            "host": _hostname(),
            **record,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(full, ensure_ascii=False) + "\n")

    def record_scan(
        self,
        connector: str,
        target: str,
        *,
        authorized: bool,
        forced: bool,
        status: str,
        command: str | None = None,
    ) -> None:
        self._write(
            {
                "event": "scan",
                "connector": connector,
                "target": target,
                "authorized": authorized,
                "forced": forced,
                "status": status,
                "command": command,
            }
        )

    def record_block(self, connector: str, target: str) -> None:
        self._write(
            {
                "event": "blocked",
                "connector": connector,
                "target": target,
                "authorized": False,
                "forced": False,
            }
        )


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:  # noqa: BLE001
        return "unknown"
