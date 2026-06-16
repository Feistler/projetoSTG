"""API FastAPI do painel STG.

Endpoints (todos reaproveitam o nucleo):
  GET  /                 -> dashboard (HTML)
  GET  /api/connectors   -> lista conectores + disponibilidade
  GET  /api/scope        -> escopo autorizado atual
  POST /api/scan         -> executa um conector e devolve o ScanResult
  GET  /api/report/{id}  -> relatorio do scan (html | md | json)
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from stg import __version__
from stg.core.authorization import Authorization
from stg.core.config import Settings
from stg.core.models import ScanResult
from stg.core.registry import get_registry
from stg.core.runner import Runner
from stg.reporting import render_report
from stg.web.content import CATEGORY_GUIDE, TOOL_TIPS

STATIC_DIR = Path(__file__).parent / "static"
_MEDIA = {"html": "text/html", "md": "text/markdown", "json": "application/json"}

app = FastAPI(title="STG - Security Toolkit Gateway", version=__version__)
settings = Settings.load()
_results: dict[str, ScanResult] = {}


class ScanRequest(BaseModel):
    connector: str
    target: str
    options: dict[str, Any] = {}
    force: bool = False


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/api/connectors")
def list_connectors() -> list[dict[str, Any]]:
    registry = get_registry()
    out: list[dict[str, Any]] = []
    for category, classes in registry.by_category().items():
        for cls in classes:
            available, reason = cls(settings).is_available()
            out.append(
                {
                    "name": cls.name,
                    "tool": cls.tool,
                    "category": category.value,
                    "description": cls.description,
                    "available": available,
                    "reason": "" if available else reason,
                    "passive": cls.passive,
                    "target_types": [t.value for t in cls.target_types],
                    "requires_binaries": cls.requires_binaries,
                    "requires_api_keys": cls.requires_api_keys,
                    "tip": TOOL_TIPS.get(cls.name, ""),
                }
            )
    return out


@app.get("/api/guide")
def guide() -> list[dict[str, Any]]:
    """Metodologia didatica: as 6 fases em ordem, com as ferramentas de cada uma."""
    grouped = get_registry().by_category()
    out: list[dict[str, Any]] = []
    for category, classes in grouped.items():
        info = CATEGORY_GUIDE.get(category.value, {})
        out.append(
            {
                **info,
                "categoria": category.value,
                "ferramentas": [cls.tool for cls in classes],
            }
        )
    out.sort(key=lambda c: c.get("ordem", 99))
    return out


@app.get("/api/scope")
def scope() -> dict[str, Any]:
    authz = Authorization.load(settings.authorization_path)
    return {
        "configured": authz.configured,
        "networks": [str(n) for n in authz.networks],
        "domains": authz.domains,
    }


@app.post("/api/scan")
def scan(req: ScanRequest) -> dict[str, Any]:
    runner = Runner(settings)
    try:
        result = runner.run(req.connector, req.target, req.options, force=req.force)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    rid = uuid.uuid4().hex[:12]
    _results[rid] = result
    payload = result.model_dump(mode="json")
    payload["id"] = rid
    return payload


@app.get("/api/report/{rid}")
def report(rid: str, format: str = "html") -> Response:
    result = _results.get(rid)
    if result is None:
        raise HTTPException(status_code=404, detail="resultado nao encontrado")
    if format not in _MEDIA:
        raise HTTPException(status_code=400, detail="formato invalido (html|md|json)")
    return Response(render_report([result], format), media_type=_MEDIA[format])


@app.get("/api/history")
def history() -> list[dict[str, Any]]:
    """Scans desta sessao (em memoria), com contagem por severidade e link de relatorio."""
    out: list[dict[str, Any]] = []
    for rid, res in reversed(list(_results.items())):
        out.append(
            {
                "id": rid,
                "connector": res.connector,
                "category": res.category.value,
                "target": res.target,
                "status": res.status.value,
                "total": len(res.findings),
                "counts": res.severity_counts(),
                "finished_at": res.finished_at.isoformat() if res.finished_at else None,
            }
        )
    return out


@app.get("/api/audit")
def audit(limit: int = 150) -> list[dict[str, Any]]:
    """Trilha de auditoria persistida (audit.jsonl), mais recentes primeiro."""
    path = settings.audit_path
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    entries.reverse()
    return entries


def run() -> None:
    """Sobe o servidor (entry point `stg-web`)."""
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    run()
