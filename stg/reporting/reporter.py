"""Consolida uma lista de ScanResult em relatorios JSON/Markdown/HTML."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from jinja2 import Environment, FileSystemLoader, select_autoescape

from stg import __version__
from stg.core.models import ScanResult, Severity

TEMPLATES_DIR = Path(__file__).parent / "templates"
SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def build_context(results: Sequence[ScanResult]) -> dict:
    overall = {s.value: 0 for s in Severity}
    total = 0
    blocks = []
    for result in results:
        counts = result.severity_counts()
        for key, value in counts.items():
            overall[key] += value
        total += len(result.findings)
        blocks.append(
            {
                "connector": result.connector,
                "category": result.category.value,
                "target": result.target,
                "status": result.status.value,
                "error": result.error,
                "duration": result.duration_seconds,
                "counts": counts,
                "findings": sorted(
                    result.findings, key=lambda f: f.severity.score, reverse=True
                ),
            }
        )
    return {
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "overall": overall,
        "total": total,
        "blocks": blocks,
        "severity_order": [s.value for s in SEVERITY_ORDER],
    }


def _render(results: Sequence[ScanResult], fmt: str) -> str:
    template = _env().get_template(f"report.{fmt}.j2")
    return template.render(**build_context(results))


def _to_json(results: Sequence[ScanResult], path: Path) -> None:
    payload = [r.model_dump(mode="json") for r in results]
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def generate_report(
    results: Sequence[ScanResult],
    output_dir: str | Path,
    formats: Sequence[str] = ("md", "html", "json"),
    name: str | None = None,
) -> dict[str, Path]:
    """Gera os relatorios pedidos e devolve {formato: caminho}."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    name = name or datetime.now().strftime("stg-report-%Y%m%d-%H%M%S")
    paths: dict[str, Path] = {}
    for fmt in formats:
        path = out / f"{name}.{fmt}"
        if fmt == "json":
            _to_json(results, path)
        else:
            path.write_text(_render(results, fmt), encoding="utf-8")
        paths[fmt] = path
    return paths
