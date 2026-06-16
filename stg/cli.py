"""Interface de linha de comando do STG (Typer + Rich)."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from stg import __version__
from stg.core.authorization import Authorization
from stg.core.config import Settings
from stg.core.models import ScanResult, ScanStatus, Severity, Target
from stg.core.pipeline import Pipeline
from stg.core.registry import get_registry
from stg.core.runner import Runner
from stg.reporting import generate_report

app = typer.Typer(add_completion=False, help="STG - Security Toolkit Gateway")
authz_app = typer.Typer(help="Gestao do escopo autorizado (Rules of Engagement).")
app.add_typer(authz_app, name="authz")
console = Console()

SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
STATUS_STYLE = {
    ScanStatus.SUCCESS: "green",
    ScanStatus.PARTIAL: "yellow",
    ScanStatus.FAILED: "red",
    ScanStatus.UNAVAILABLE: "dim",
    ScanStatus.UNAUTHORIZED: "bold red",
    ScanStatus.SKIPPED: "dim",
}

CONFIG_OPT = typer.Option(None, "--config", "-c", help="Caminho do config.yaml.")
OPTION_OPT = typer.Option(None, "--opt", "-o", help="Opcao do conector no formato chave=valor.")
FORCE_OPT = typer.Option(False, "--force", help="Executa mesmo fora do escopo (auditado).")
REPORT_OPT = typer.Option(None, "--report", "-r", help="Formatos do relatorio: md, html, json.")


def _settings(config: Optional[Path]) -> Settings:
    return Settings.load(config)


def _coerce(value: str):
    low = value.lower()
    if low in ("true", "false"):
        return low == "true"
    for caster in (int, float):
        try:
            return caster(value)
        except ValueError:
            continue
    return value


def _parse_options(pairs: Optional[List[str]]) -> dict:
    options: dict = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise typer.BadParameter(f"Opcao '{pair}' deve ser chave=valor.")
        key, raw = pair.split("=", 1)
        options[key.strip()] = _coerce(raw.strip())
    return options


def _print_result(result: ScanResult) -> None:
    status = result.status
    header = (
        f"[bold]{result.connector}[/] -> [cyan]{result.target}[/]  "
        f"[{STATUS_STYLE.get(status, 'white')}]{status.value.upper()}[/]"
    )
    if result.error:
        header += f"  [dim]({result.error})[/]"
    console.print(Panel(header, expand=False))

    if not result.findings:
        return
    table = Table(show_lines=False, header_style="bold")
    table.add_column("Sev.")
    table.add_column("Achado")
    table.add_column("Detalhe", overflow="fold")
    for finding in sorted(result.findings, key=lambda f: f.severity.score, reverse=True):
        style = SEV_STYLE.get(finding.severity, "white")
        table.add_row(
            f"[{style}]{finding.severity.value.upper()}[/]",
            finding.title,
            finding.description or finding.evidence,
        )
    console.print(table)


def _maybe_report(
    results: List[ScanResult], report: Optional[List[str]], settings: Settings
) -> None:
    if not report:
        return
    formats = [f.strip() for f in report if f.strip()]
    paths = generate_report(results, settings.output_dir, formats)
    for fmt, path in paths.items():
        console.print(f"[green]Relatorio {fmt}:[/] {path}")


@app.command()
def version() -> None:
    """Mostra a versao do STG."""
    console.print(f"[bold]STG - Security Toolkit Gateway[/] v{__version__}")


@app.command("list")
def list_connectors(config: Optional[Path] = CONFIG_OPT) -> None:
    """Lista os conectores e sua disponibilidade no ambiente atual."""
    settings = _settings(config)
    registry = get_registry()
    table = Table(title="Conectores STG", header_style="bold")
    table.add_column("Nome")
    table.add_column("Ferramenta")
    table.add_column("Categoria")
    table.add_column("Disponivel")
    table.add_column("Observacao", overflow="fold")
    for category, classes in registry.by_category().items():
        for cls in classes:
            available, reason = cls(settings).is_available()
            mark = "[green]sim[/]" if available else "[red]nao[/]"
            table.add_row(cls.name, cls.tool, category.value, mark, "" if available else reason)
    console.print(table)


@app.command()
def info(connector: str, config: Optional[Path] = CONFIG_OPT) -> None:
    """Detalha um conector especifico."""
    settings = _settings(config)
    try:
        cls = get_registry().get_class(connector)
    except KeyError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from exc
    instance = cls(settings)
    available, reason = instance.is_available()
    body = [
        f"[bold]Ferramenta:[/] {cls.tool}",
        f"[bold]Categoria:[/] {cls.category.value}",
        f"[bold]Descricao:[/] {cls.description}",
        f"[bold]Tipos de alvo:[/] {', '.join(t.value for t in cls.target_types) or 'qualquer'}",
        f"[bold]Binarios:[/] {', '.join(cls.requires_binaries) or '-'}",
        f"[bold]Credenciais:[/] {', '.join(cls.requires_api_keys) or '-'}",
        f"[bold]Passivo:[/] {'sim' if cls.passive else 'nao'}",
        f"[bold]Disponivel:[/] {'sim' if available else f'nao ({reason})'}",
    ]
    console.print(Panel("\n".join(body), title=cls.name, expand=False))


@app.command()
def scan(
    connector: str,
    target: str,
    option: Optional[List[str]] = OPTION_OPT,
    force: bool = FORCE_OPT,
    report: Optional[List[str]] = REPORT_OPT,
    config: Optional[Path] = CONFIG_OPT,
) -> None:
    """Executa um conector contra um alvo."""
    settings = _settings(config)
    runner = Runner(settings)
    options = _parse_options(option)
    result = runner.run(connector, target, options, force=force)
    _print_result(result)
    _maybe_report([result], report, settings)


@app.command()
def pipeline(
    file: Path,
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Alvo padrao do pipeline."),
    force: bool = FORCE_OPT,
    report: Optional[List[str]] = REPORT_OPT,
    config: Optional[Path] = CONFIG_OPT,
) -> None:
    """Executa um pipeline declarativo (YAML) de varios conectores."""
    settings = _settings(config)
    runner = Runner(settings)
    pipe = Pipeline.load(file)
    console.print(f"[bold]Pipeline:[/] {pipe.name} - {pipe.description}")
    results = pipe.run(runner, target, force=force)
    for result in results:
        _print_result(result)
    _maybe_report(results, report, settings)


@authz_app.command("check")
def authz_check(target: str, config: Optional[Path] = CONFIG_OPT) -> None:
    """Verifica se um alvo esta dentro do escopo autorizado."""
    settings = _settings(config)
    authz = Authorization.load(settings.authorization_path)
    parsed = Target.parse(target)
    if not authz.configured:
        console.print(
            f"[yellow]Nenhum escopo definido em {settings.authorization_path}.[/] "
            "Rode [bold]stg authz init[/]."
        )
    allowed = authz.is_authorized(parsed)
    mark = "[green]AUTORIZADO[/]" if allowed else "[red]FORA DO ESCOPO[/]"
    console.print(f"{parsed.value} ({parsed.type.value}): {mark}")


@authz_app.command("init")
def authz_init(config: Optional[Path] = CONFIG_OPT) -> None:
    """Cria um arquivo authorization.yaml inicial."""
    settings = _settings(config)
    path = settings.authorization_path
    if path.exists():
        console.print(f"[yellow]{path} ja existe; nada alterado.[/]")
        raise typer.Exit()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_AUTHZ_TEMPLATE, encoding="utf-8")
    console.print(f"[green]Criado {path}.[/] Edite com o seu escopo autorizado.")


_AUTHZ_TEMPLATE = """\
# Escopo autorizado (Rules of Engagement).
# Liste APENAS redes/dominios para os quais voce tem autorizacao por escrito.
allow_local_files: true
scope:
  networks:
    - 192.168.56.0/24
    - 10.0.0.0/24
  domains:
    - exemplo.local
"""


def main() -> None:
    app()


if __name__ == "__main__":
    main()
