"""Pipelines declarativos: encadeiam conectores definidos em YAML.

Exemplo (pipelines/recon.yaml):

    name: recon-basico
    description: Descoberta de ativos e portas
    steps:
      - connector: amass
      - connector: nmap
        options: { ports: "1-1000" }
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from stg.core.models import ScanResult
from stg.core.runner import Runner


@dataclass
class PipelineStep:
    connector: str
    target: str | None = None
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class Pipeline:
    name: str
    steps: list[PipelineStep]
    description: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "Pipeline":
        p = Path(path)
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        steps = [
            PipelineStep(
                connector=s["connector"],
                target=s.get("target"),
                options=s.get("options", {}) or {},
            )
            for s in (data.get("steps", []) or [])
        ]
        return cls(
            name=data.get("name", p.stem),
            steps=steps,
            description=data.get("description", ""),
        )

    def run(
        self,
        runner: Runner,
        default_target: str | None = None,
        *,
        force: bool = False,
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        for step in self.steps:
            target = step.target or default_target
            if not target:
                continue
            results.append(runner.run(step.connector, target, step.options, force=force))
        return results
